//! virtio-blk over PCI.
//!
//! virtio-drivers owns the device and the transport; this module supplies what
//! they need from the platform - configuration-space access and a DMA HAL - and
//! presents the disk as a `BlockDevice`.
//!
//! DMA buffers are UEFI pages from Patina. Patina identity-maps memory, so a
//! physical address is the pointer the driver uses, and QEMU's virtio devices
//! are cache-coherent, so write-back RAM needs no maintenance around a request.

use core::ptr::NonNull;

use patina::standard::efi;
use spin::Mutex;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{ConfigurationAccess, DeviceFunction, PciRoot};
use virtio_drivers::transport::{DeviceType, Transport};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

use super::block::{BlockDevice, BlockError};
use super::pci::{self, PciDevice};
use crate::tables;

/// The sector size virtio-blk addresses in.
const SECTOR: u32 = 512;

/// The platform's virtio HAL.
pub struct PlatformHal;

// SAFETY: the HAL is stateless; the memory it returns is boot-services pages
// owned by the driver until `dma_dealloc`.
unsafe impl Hal for PlatformHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let services = tables::boot_services();
        assert!(
            !services.is_null(),
            "virtio: DMA allocation without boot services"
        );
        let mut address: efi::PhysicalAddress = 0;
        // SAFETY: boot services are live, and the out-parameter is a local.
        let status = unsafe {
            ((*services).allocate_pages)(
                efi::ALLOCATE_ANY_PAGES,
                efi::BOOT_SERVICES_DATA,
                pages,
                &mut address,
            )
        };
        assert!(
            status == efi::Status::SUCCESS,
            "virtio: out of DMA memory: {status:?}"
        );
        // SAFETY: the pages were just allocated, and virtio-drivers expects them
        // zeroed.
        unsafe { core::ptr::write_bytes(address as *mut u8, 0, pages * 4096) };
        // SAFETY: a successful allocation is never at address zero, which the
        // firmware leaves unmapped.
        (address as PhysAddr, unsafe {
            NonNull::new_unchecked(address as *mut u8)
        })
    }

    unsafe fn dma_dealloc(paddr: PhysAddr, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        let services = tables::boot_services();
        if services.is_null() {
            return 1;
        }
        // SAFETY: the pages are the ones `dma_alloc` returned.
        let status = unsafe { ((*services).free_pages)(paddr as efi::PhysicalAddress, pages) };
        i32::from(status != efi::Status::SUCCESS)
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        // SAFETY: BARs are assigned in the 32-bit aperture, which is identity
        // mapped as device memory; a BAR is never at zero.
        unsafe { NonNull::new_unchecked(paddr as *mut u8) }
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        // No IOMMU and an identity map: the address is the pointer.
        buffer.as_ptr() as *mut u8 as PhysAddr
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}

/// The machine's configuration space, as virtio-drivers sees it.
pub struct EcamAccess;

impl ConfigurationAccess for EcamAccess {
    fn read_word(&self, function: DeviceFunction, offset: u8) -> u32 {
        pci::read32(
            function.bus,
            function.device,
            function.function,
            offset as u16,
        )
    }

    fn write_word(&mut self, function: DeviceFunction, offset: u8, data: u32) {
        pci::write32(
            function.bus,
            function.device,
            function.function,
            offset as u16,
            data,
        )
    }

    unsafe fn unsafe_clone(&self) -> Self {
        EcamAccess
    }
}

type Disk = VirtIOBlk<PlatformHal, PciTransport>;

/// A virtio block device.
pub struct VirtioBlk {
    disk: Mutex<Disk>,
    block_count: u64,
    readonly: bool,
}

// SAFETY: boot services run on one core, every request goes through the mutex,
// and the driver's raw pointers are MMIO and DMA memory it owns.
unsafe impl Send for VirtioBlk {}
// SAFETY: as `Send`.
unsafe impl Sync for VirtioBlk {}

impl VirtioBlk {
    /// Opens `device` when it is a virtio block device.
    pub fn open(device: &PciDevice) -> Option<VirtioBlk> {
        // The transport reads its capabilities through the BARs, so decoding and
        // bus mastering come first.
        device.enable();
        let mut root = PciRoot::new(EcamAccess);
        let transport =
            match PciTransport::new::<PlatformHal, EcamAccess>(&mut root, device.function()) {
                Ok(transport) => transport,
                Err(error) => {
                    log::warn!(
                        "virtio: {:02x}:{:02x}.{}: {error}",
                        device.bus,
                        device.slot,
                        device.func
                    );
                    return None;
                }
            };
        if transport.device_type() != DeviceType::Block {
            return None;
        }
        let disk = match Disk::new(transport) {
            Ok(disk) => disk,
            Err(error) => {
                log::warn!(
                    "virtio-blk: {:02x}:{:02x}.{}: {error:?}",
                    device.bus,
                    device.slot,
                    device.func
                );
                return None;
            }
        };
        Some(VirtioBlk {
            block_count: disk.capacity(),
            readonly: disk.readonly(),
            disk: Mutex::new(disk),
        })
    }

    fn check(&self, lba: u64, bytes: usize) -> Result<(), BlockError> {
        if bytes % SECTOR as usize != 0 {
            return Err(BlockError::Io);
        }
        match lba.checked_add((bytes / SECTOR as usize) as u64) {
            Some(end) if end <= self.block_count => Ok(()),
            _ => Err(BlockError::OutOfRange),
        }
    }
}

impl BlockDevice for VirtioBlk {
    fn block_size(&self) -> u32 {
        SECTOR
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.check(lba, buffer.len())?;
        self.disk
            .lock()
            .read_blocks(lba as usize, buffer)
            .map_err(|_| BlockError::Io)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        if self.readonly {
            return Err(BlockError::WriteProtected);
        }
        self.check(lba, buffer.len())?;
        self.disk
            .lock()
            .write_blocks(lba as usize, buffer)
            .map_err(|_| BlockError::Io)
    }

    fn is_writable(&self) -> bool {
        !self.readonly
    }
}
