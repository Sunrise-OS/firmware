//! The Rust global allocator.
//!
//! The region is a reserved RAM window the memory map keeps to the firmware, so
//! the allocator never competes with the pages it hands out through
//! `EFI_BOOT_SERVICES.AllocatePages`. `alloc::alloc` backs the firmware's own
//! use of `alloc` - the page tables, the FAT code, and image loading - and
//! `AllocatePool`, which carves blocks out of the same heap.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use linked_list_allocator::Heap;
use spin::Mutex;

pub struct FirmwareHeap {
    heap: Mutex<Heap>,
}

// SAFETY: the inner heap is behind a spin mutex, so allocation is serialised,
// and it only ever hands out memory from the regions it was given.
unsafe impl GlobalAlloc for FirmwareHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match self.heap.lock().allocate_first_fit(layout) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_) => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is that `ptr` came from `alloc` with
        // this layout, which is what `deallocate` requires.
        unsafe {
            self.heap
                .lock()
                .deallocate(NonNull::new_unchecked(ptr), layout)
        }
    }
}

#[global_allocator]
pub static ALLOCATOR: FirmwareHeap = FirmwareHeap {
    heap: Mutex::new(Heap::empty()),
};

/// Gives the allocator its region. Called before anything allocates, which on
/// this target means before the page tables are built.
///
/// # Safety
///
/// Call once, from single-threaded bring-up, with a region no other allocator
/// or subsystem will touch, before any allocation.
pub unsafe fn init(start: *mut u8, size: usize) {
    // SAFETY: the caller guarantees the region and that this runs once.
    unsafe { ALLOCATOR.heap.lock().init(start, size) }
}

/// How much of the heap is still unallocated, for the boot log.
pub fn free_bytes() -> usize {
    ALLOCATOR.heap.lock().free()
}
