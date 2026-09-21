//! virtio-blk: the boot disk.
//!
//! virtio-drivers owns the device; this module owns the *interface*: it presents
//! the disk as a `BlockDevice` so GPT, FAT, and the EFI Block I/O protocol above
//! it never see virtio at all.
//!
//! The driver needs `&mut self` for a request and `BlockDevice` hands out
//! `&self`, so the device sits behind a spin mutex. On a machine with one core
//! running boot services that mutex is never contended; it is there because the
//! trait promises the methods can be called through a shared reference.

use spin::Mutex;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::{DeviceType, Transport};

use super::hal::PlatformHal;
use super::pci;
use crate::block::{BlockDevice, BlockError};
use crate::drivers::pci::PciDevice;

/// The sector size virtio-blk uses, and the size GPT and FAT expect.
const SECTOR: u32 = 512;

/// Names for the first few disks, so a log line says which one it means.
const NAMES: [&str; 8] = [
    "virtio-blk0",
    "virtio-blk1",
    "virtio-blk2",
    "virtio-blk3",
    "virtio-blk4",
    "virtio-blk5",
    "virtio-blk6",
    "virtio-blk7",
];

type Disk = VirtIOBlk<PlatformHal, PciTransport>;

pub struct VirtioBlk {
    disk: Mutex<Disk>,
    block_count: u64,
    name: &'static str,
}

// SAFETY: the firmware runs boot services on one core, and every access to the
// device goes through `disk`'s mutex. The raw pointers inside the driver refer to
// MMIO and DMA memory the firmware itself owns and maps.
unsafe impl Send for VirtioBlk {}
// SAFETY: as `Send`: `&self` methods serialise on the mutex, and nothing else
// touches the transport.
unsafe impl Sync for VirtioBlk {}

impl VirtioBlk {
    /// Opens `device` when it is a virtio block device.
    ///
    /// The device type comes from the transport, not from a table of PCI device
    /// IDs written down here: the crate knows that mapping, and it is the one
    /// place it stays correct.
    pub fn open(device: &PciDevice, index: usize) -> Option<VirtioBlk> {
        let transport = pci::open(device)?;
        if transport.device_type() != DeviceType::Block {
            return None;
        }
        let disk = match Disk::new(transport) {
            Ok(disk) => disk,
            Err(error) => {
                let (bus, slot, func) = device.address();
                crate::println!("[virtio-blk] {bus:02x}:{slot:02x}.{func}: {error:?}");
                return None;
            }
        };
        let block_count = disk.capacity();
        Some(VirtioBlk {
            disk: Mutex::new(disk),
            block_count,
            name: NAMES[index.min(NAMES.len() - 1)],
        })
    }

    /// Whether the device advertised itself read-only.
    pub fn readonly(&self) -> bool {
        self.disk.lock().readonly()
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
        if buffer.len() % SECTOR as usize != 0 {
            return Err(BlockError::Io);
        }
        let blocks = buffer.len() / SECTOR as usize;
        if lba + blocks as u64 > self.block_count {
            return Err(BlockError::OutOfRange);
        }
        self.disk
            .lock()
            .read_blocks(lba as usize, buffer)
            .map_err(|_| BlockError::Io)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        if buffer.len() % SECTOR as usize != 0 {
            return Err(BlockError::Io);
        }
        if self.readonly() {
            return Err(BlockError::WriteProtected);
        }
        let blocks = buffer.len() / SECTOR as usize;
        if lba + blocks as u64 > self.block_count {
            return Err(BlockError::OutOfRange);
        }
        self.disk
            .lock()
            .write_blocks(lba as usize, buffer)
            .map_err(|_| BlockError::Io)
    }

    fn is_writable(&self) -> bool {
        !self.readonly()
    }

    fn name(&self) -> &'static str {
        self.name
    }
}
