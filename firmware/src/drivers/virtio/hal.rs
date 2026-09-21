//! The virtio HAL: DMA memory and the address translation virtio-drivers asks
//! its platform for.
//!
//! The firmware's identity map makes this the simplest possible HAL: a physical
//! address *is* the pointer the driver uses, and a DMA buffer is just pages the
//! EFI pool hands out. RAM is mapped non-cacheable for exactly this reason, so
//! a device's writes to a used ring are visible to the core polling it without
//! any cache maintenance in between.

use core::ptr::NonNull;

use virtio_drivers::{BufferDirection, Hal, PhysAddr};

use crate::uefi::mem;

/// The platform's virtio HAL.
pub struct PlatformHal;

// SAFETY: every method below is stateless - the addresses it returns are the
// firmware's own RAM, which is identity mapped and owned by the allocator - so
// there is no per-instance state for a data race to corrupt.
unsafe impl Hal for PlatformHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        // EFI pages rather than the firmware heap: they are 4 KiB aligned, zeroed
        // and typed, and they outlive the driver setup that asks for them.
        let memory = mem::pages_for(r_efi::system::LOADER_DATA, pages * 4096);
        assert!(!memory.is_null(), "virtio: out of DMA memory");
        // SAFETY: `pages_for` returned `pages` zeroed 4 KiB pages.
        let pointer = unsafe { NonNull::new_unchecked(memory) };
        (memory as PhysAddr, pointer)
    }

    unsafe fn dma_dealloc(paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // The identity map means the physical address is the pointer; freeing
        // through the EFI service is what keeps the memory map honest.
        let status = unsafe { mem::free_pages_physical(paddr, _pages) };
        i32::from(status != r_efi::base::Status::SUCCESS)
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        // SAFETY: the caller promises `paddr` is a valid MMIO region, and the
        // firmware maps every PCI BAR window as device memory.
        unsafe { NonNull::new_unchecked(paddr as *mut u8) }
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        // No IOMMU and no bounce buffer: the address is the pointer.
        buffer.as_ptr() as *mut u8 as PhysAddr
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
        // Nothing was mapped or copied, so nothing has to be undone.
    }
}
