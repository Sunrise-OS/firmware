//! The memory services: the page pool, the pool allocator, `GetMemoryMap`, and
//! `ExitBootServices`.
//!
//! Two allocators, because UEFI has two. `AllocatePages` hands out 4 KiB pages
//! carved from RAM the memory map describes, with a type attached to each
//! run; `AllocatePool` hands out smaller blocks from the firmware's own heap.
//!
//! The memory map is generated rather than stored: RAM is one span, the firmware
//! keeps two windows of it for itself, and every live allocation is a run with a
//! type. Building the map means walking those in address order and emitting the
//! complement as conventional memory, which is exactly what the map says and
//! never drifts from what was actually handed out.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use r_efi::base::{PhysicalAddress, Status};
use r_efi::system as efi;
use r_efi::system::{ALLOCATE_ADDRESS, AllocateType, MemoryDescriptor, MemoryType};

use crate::platform;

/// `EFI_MEMORY_DESCRIPTOR` size: 40 bytes with the specification's padding, and
/// the number `GetMemoryMap` reports as `DescriptorSize`.
pub const DESCRIPTOR_SIZE: usize = core::mem::size_of::<MemoryDescriptor>();
/// `EFI_MEMORY_DESCRIPTOR_VERSION`.
pub const DESCRIPTOR_VERSION: u32 = 1;
/// `EFI_MEMORY_WB`: the attribute every RAM range carries, because the firmware's
/// identity map makes it write-back cacheable.
const WB: u64 = 0x8;
/// `EFI_MEMORY_RUNTIME`: set for the firmware's own window, which the operating
/// system keeps mapped.
const RUNTIME: u64 = 1 << 63;

/// How many allocations the map may describe. Each `AllocatePages` call takes
/// one slot; running out makes further allocation fail rather than produce a map
/// that does not match reality.
const MAX_ALLOCATIONS: usize = 64;
/// How many descriptors `GetMemoryMap` can produce: RAM span, the firmware's
/// reserved windows, and every live allocation, plus slack.
const MAX_DESCRIPTORS: usize = 96;

/// A run of pages handed out by `AllocatePages`.
#[derive(Clone, Copy)]
struct Allocation {
    start: PhysicalAddress,
    pages: usize,
    memory_type: u32,
}

static mut ALLOCATIONS: [Allocation; MAX_ALLOCATIONS] = [Allocation {
    start: 0,
    pages: 0,
    memory_type: 0,
}; MAX_ALLOCS];
static ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The map key: bumped whenever the map changes, so `ExitBootServices` can tell
/// an application that has a stale copy to ask again.
static MAP_KEY: AtomicUsize = AtomicUsize::new(1);
/// Set once `ExitBootServices` succeeds; after that the services that allocate
/// are no longer available.
static BOOT_SERVICES_ENDED: AtomicBool = AtomicBool::new(false);

const MAX_ALLOCS: usize = MAX_ALLOCATIONS;

/// The windows the firmware keeps for itself, in address order:
/// `(start, end, memory_type)`.
///
/// * the image, its stack, and everything linked into RAM - runtime code, so the
///   operating system keeps it mapped;
/// * the firmware's heap, where the page tables and protocol structures live -
///   boot-services data, so the operating system reclaims it after
///   `ExitBootServices`. That is the same contract every firmware makes: the
///   pages are only in use while the translation built over them is in use, and
///   the operating system replaces that translation before it reclaims anything.
fn reserved_windows() -> [(usize, usize, u32); 2] {
    [
        (
            platform::RAM_BASE,
            crate::layout::STACK_TOP,
            efi::RUNTIME_SERVICES_CODE,
        ),
        (
            crate::layout::HEAP_BASE,
            crate::layout::HEAP_BASE + crate::layout::HEAP_SIZE,
            efi::BOOT_SERVICES_DATA,
        ),
    ]
}

/// The first address the page allocator may hand out.
fn page_pool_start() -> usize {
    crate::layout::STACK_TOP
}

/// The end of the first conventional window: the heap starts above it.
fn page_pool_end() -> usize {
    crate::layout::HEAP_BASE
}

/// Sets a fresh map key. Called whenever the map changes.
fn touch_map() {
    MAP_KEY.fetch_add(1, Ordering::AcqRel);
}

/// Whether boot services have ended.
pub fn boot_services_ended() -> bool {
    BOOT_SERVICES_ENDED.load(Ordering::Acquire)
}

/// Marks boot services over. Called by `ExitBootServices`.
pub fn set_boot_services_ended() {
    BOOT_SERVICES_ENDED.store(true, Ordering::Release);
}

/// Validates the key an application presents to `ExitBootServices`.
pub fn check_map_key(key: usize) -> bool {
    key == MAP_KEY.load(Ordering::Acquire)
}

/// How many RAM bytes the machine has, from the device tree when one was passed
/// and from the built-in platform description otherwise.
pub fn ram_end() -> usize {
    platform::ram_end()
}

/// Adds an allocation to the map's list of live runs.
fn record_allocation(start: PhysicalAddress, pages: usize, memory_type: u32) -> Option<usize> {
    let count = ALLOCATION_COUNT.load(Ordering::Acquire);
    if count >= MAX_ALLOCS {
        return None;
    }
    // SAFETY: single-threaded boot services; `count` is inside the array.
    unsafe {
        core::ptr::write(
            (core::ptr::addr_of_mut!(ALLOCATIONS))
                .cast::<Allocation>()
                .add(count),
            Allocation {
                start,
                pages,
                memory_type,
            },
        );
    }
    ALLOCATION_COUNT.store(count + 1, Ordering::Release);
    touch_map();
    Some(count)
}

/// Removes an allocation, so its pages read as conventional memory again.
fn drop_allocation(start: PhysicalAddress) -> bool {
    let count = ALLOCATION_COUNT.load(Ordering::Acquire);
    // SAFETY: as `record_allocation`.
    unsafe {
        let allocations = (core::ptr::addr_of_mut!(ALLOCATIONS)).cast::<Allocation>();
        for index in 0..count {
            if (*allocations.add(index)).start == start {
                let last = count - 1;
                core::ptr::copy(
                    allocations.add(index + 1),
                    allocations.add(index),
                    last - index,
                );
                ALLOCATION_COUNT.store(last, Ordering::Release);
                touch_map();
                return true;
            }
        }
    }
    false
}

/// The windows the page allocator may hand out, in address order.
///
/// The page pool is RAM between the firmware's own windows: its image and
/// stack below, its heap above, and everything above the heap to the end of
/// RAM.
fn page_windows() -> [(usize, usize); 2] {
    let end = ram_end();
    let above_heap = (crate::layout::HEAP_BASE + crate::layout::HEAP_SIZE).min(end);
    [(page_pool_start(), page_pool_end()), (above_heap, end)]
}

/// Finds a run of `pages` pages that is free, below `ceiling` when one is
/// given, and returns its start address.
///
/// "Free" means inside a page window and not overlapping a recorded
/// allocation, so the answer is the same as what `GetMemoryMap` will report.
fn find_run(pages: usize, ceiling: Option<usize>) -> Option<usize> {
    let wanted = pages * 4096;
    let live = ALLOCATION_COUNT.load(Ordering::Acquire);
    for (window_start, window_end) in page_windows() {
        if window_end <= window_start {
            continue;
        }
        // The allocations that touch this window, in address order.
        let mut ranges: alloc::vec::Vec<(usize, usize)> = alloc::vec::Vec::new();
        // SAFETY: single-threaded boot services.
        unsafe {
            let allocations = (core::ptr::addr_of!(ALLOCATIONS)).cast::<Allocation>();
            for index in 0..live {
                let allocation = core::ptr::read(allocations.add(index));
                let start = allocation.start as usize;
                let end = start + allocation.pages * 4096;
                if end > window_start && start < window_end {
                    ranges.push((start.max(window_start), end.min(window_end)));
                }
            }
        }
        ranges.sort_unstable();

        let mut cursor = window_start;
        for (start, end) in ranges
            .into_iter()
            .chain(core::iter::once((window_end, window_end)))
        {
            if start > cursor {
                let gap_start = cursor;
                let gap_end = start;
                if gap_end - gap_start >= wanted {
                    let candidate = gap_start;
                    let fits = ceiling.is_none_or(|ceiling| candidate + wanted <= ceiling);
                    if fits {
                        return Some(candidate);
                    }
                }
            }
            cursor = cursor.max(end);
            if cursor >= window_end {
                break;
            }
        }
    }
    None
}

/// `AllocatePages`.
pub unsafe extern "efiapi" fn allocate_pages(
    allocate_type: AllocateType,
    memory_type: MemoryType,
    pages: usize,
    address: *mut PhysicalAddress,
) -> Status {
    if address.is_null() || pages == 0 {
        return Status::INVALID_PARAMETER;
    }
    if boot_services_ended() {
        return Status::UNSUPPORTED;
    }

    // SAFETY: the out-parameter is writable for all three allocate types.
    let requested = unsafe { *address } as usize;
    let wanted = pages * 4096;

    let start = match allocate_type {
        // A specific address: it has to be inside RAM, inside the pool, and
        // unallocated.
        ALLOCATE_ADDRESS => {
            if requested % 4096 != 0 || !is_ram(requested, wanted) {
                return Status::INVALID_PARAMETER;
            }
            if overlaps_reserved(requested, wanted) {
                return Status::OUT_OF_RESOURCES;
            }
            let in_window = page_windows()
                .iter()
                .any(|(start, end)| requested >= *start && requested + wanted <= *end);
            if !in_window || overlaps_allocation(requested, wanted) {
                return Status::OUT_OF_RESOURCES;
            }
            requested
        }
        efi::ALLOCATE_MAX_ADDRESS => match find_run(pages, Some(requested)) {
            Some(found) => found,
            None => return Status::OUT_OF_RESOURCES,
        },
        _ => match find_run(pages, None) {
            Some(found) => found,
            None => return Status::OUT_OF_RESOURCES,
        },
    };

    if record_allocation(start as u64, pages, memory_type).is_none() {
        return Status::OUT_OF_RESOURCES;
    }
    // SAFETY: the out-parameter is writable.
    unsafe { *address = start as PhysicalAddress };
    Status::SUCCESS
}

/// Whether `[start, start + size)` already belongs to an allocation.
fn overlaps_allocation(start: usize, size: usize) -> bool {
    let end = start + size;
    let live = ALLOCATION_COUNT.load(Ordering::Acquire);
    // SAFETY: single-threaded boot services.
    unsafe {
        let allocations = (core::ptr::addr_of!(ALLOCATIONS)).cast::<Allocation>();
        for index in 0..live {
            let allocation = core::ptr::read(allocations.add(index));
            let other_start = allocation.start as usize;
            let other_end = other_start + allocation.pages * 4096;
            if start < other_end && end > other_start {
                return true;
            }
        }
    }
    false
}

/// Whether `[start, start + size)` runs into a window the firmware keeps.
fn overlaps_reserved(start: usize, size: usize) -> bool {
    let end = start + size;
    reserved_windows()
        .iter()
        .any(|(window_start, window_end, _)| start < *window_end && end > *window_start)
}

/// `FreePages`.
pub unsafe extern "efiapi" fn free_pages(address: PhysicalAddress, _pages: usize) -> Status {
    if drop_allocation(address) {
        Status::SUCCESS
    } else {
        Status::INVALID_PARAMETER
    }
}

/// `GetMemoryMap`.
///
/// Writes the descriptors the caller's buffer fits, then reports the sizes it
/// would need: `*map_size` becomes the full size, `*descriptor_size` and
/// `*descriptor_version` describe one descriptor, and `*map_key` is the key to
/// hand `ExitBootServices`.
pub unsafe extern "efiapi" fn get_memory_map(
    map_size: *mut usize,
    map: *mut MemoryDescriptor,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> Status {
    if map_size.is_null() || descriptor_size.is_null() || descriptor_version.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let mut descriptors = [MemoryDescriptor {
        r#type: efi::RESERVED_MEMORY_TYPE,
        physical_start: 0,
        virtual_start: 0,
        number_of_pages: 0,
        attribute: 0,
    }; MAX_DESCRIPTORS];
    let count = build_memory_map(&mut descriptors);

    let needed = count * DESCRIPTOR_SIZE;
    // SAFETY: the out-parameters are writable, as checked above.
    unsafe {
        *descriptor_size = DESCRIPTOR_SIZE;
        *descriptor_version = DESCRIPTOR_VERSION;
        if !map_key.is_null() {
            *map_key = MAP_KEY.load(Ordering::Acquire);
        }
        let capacity = *map_size;
        *map_size = needed;
        if capacity < needed || map.is_null() {
            return Status::BUFFER_TOO_SMALL;
        }
        for (index, descriptor) in descriptors[..count].iter().enumerate() {
            *map.add(index) = *descriptor;
        }
    }
    Status::SUCCESS
}

/// Fills `out` with the map and returns how many descriptors there are.
fn build_memory_map(out: &mut [MemoryDescriptor]) -> usize {
    let ram_end = ram_end() as u64;
    let mut count = 0;

    let mut push = |out: &mut [MemoryDescriptor],
                    count: &mut usize,
                    start: u64,
                    pages: u64,
                    ty: u32,
                    attribute: u64| {
        if *count < out.len() && pages > 0 {
            out[*count] = MemoryDescriptor {
                r#type: ty,
                physical_start: start,
                virtual_start: start,
                number_of_pages: pages,
                attribute,
            };
            *count += 1;
        }
    };

    // The whole RAM span, minus the firmware's own windows, minus live
    // allocations: everything left is conventional memory.
    let mut cursor = platform::RAM_BASE as u64;
    let mut windows: alloc::vec::Vec<(u64, u64, u32, u64)> = alloc::vec::Vec::new();
    for (start, end, ty) in reserved_windows() {
        windows.push((start as u64, end as u64, ty, WB | RUNTIME));
    }
    let live = ALLOCATION_COUNT.load(Ordering::Acquire);
    // SAFETY: single-threaded boot services.
    unsafe {
        let allocations = (core::ptr::addr_of!(ALLOCATIONS)).cast::<Allocation>();
        for index in 0..live {
            let allocation = core::ptr::read(allocations.add(index));
            let start = allocation.start;
            let end = start + (allocation.pages as u64) * 4096;
            windows.push((start, end, allocation.memory_type, WB));
        }
    }
    windows.sort_unstable_by_key(|(start, ..)| *start);

    for (start, end, ty, attribute) in windows {
        if start > cursor {
            push(
                out,
                &mut count,
                cursor,
                (start - cursor) / 4096,
                efi::CONVENTIONAL_MEMORY,
                WB,
            );
        }
        push(out, &mut count, start, (end - start) / 4096, ty, attribute);
        cursor = cursor.max(end);
    }
    if cursor < ram_end {
        push(
            out,
            &mut count,
            cursor,
            (ram_end - cursor) / 4096,
            efi::CONVENTIONAL_MEMORY,
            WB,
        );
    }
    count
}

/// `AllocatePool`: a block from the firmware's heap, with the size in a header
/// so `FreePool` can hand the same layout back.
pub unsafe extern "efiapi" fn allocate_pool(
    _memory_type: MemoryType,
    size: usize,
    buffer: *mut *mut c_void,
) -> Status {
    if buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if boot_services_ended() {
        return Status::UNSUPPORTED;
    }
    let layout = match core::alloc::Layout::from_size_align(size + 8, 8) {
        Ok(layout) => layout,
        Err(_) => return Status::INVALID_PARAMETER,
    };
    let pointer = unsafe { alloc::alloc::alloc(layout) };
    if pointer.is_null() {
        return Status::OUT_OF_RESOURCES;
    }
    // SAFETY: the block is ours for `size` bytes plus the 8-byte header.
    unsafe {
        core::ptr::write_unaligned(pointer as *mut usize, size);
        *buffer = pointer.add(8) as *mut c_void;
    }
    touch_map();
    Status::SUCCESS
}

/// `FreePool`.
pub unsafe extern "efiapi" fn free_pool(buffer: *mut c_void) -> Status {
    if buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let pointer = (buffer as *mut u8).sub(8);
    // SAFETY: the header was written by `allocate_pool` at this address.
    let size = unsafe { core::ptr::read_unaligned(pointer as *const usize) };
    let layout = match core::alloc::Layout::from_size_align(size + 8, 8) {
        Ok(layout) => layout,
        Err(_) => return Status::INVALID_PARAMETER,
    };
    unsafe { alloc::alloc::dealloc(pointer, layout) };
    touch_map();
    Status::SUCCESS
}

/// `AllocatePages` for callers inside the firmware: pages of the given type,
/// zeroed, or null when the pool is exhausted.
pub fn pages_for(memory_type: u32, bytes: usize) -> *mut u8 {
    let pages = bytes.div_ceil(4096);
    let mut address: PhysicalAddress = 0;
    let status =
        unsafe { allocate_pages(efi::ALLOCATE_ANY_PAGES, memory_type, pages, &mut address) };
    if status != Status::SUCCESS {
        return core::ptr::null_mut();
    }
    let pointer = address as *mut u8;
    // SAFETY: freshly allocated pages belong to us.
    unsafe { core::ptr::write_bytes(pointer, 0, pages * 4096) };
    pointer
}

/// Allocates from the EFI pool, for firmware code that hands a buffer to an
/// application: the application releases it with `FreePool`, so it has to come
/// from the same allocator that call belongs to.
pub fn pool_allocate(size: usize) -> *mut u8 {
    let mut buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: the out-parameter is a local, and the size is the caller's.
    let status = unsafe { allocate_pool(efi::BOOT_SERVICES_DATA, size, &mut buffer) };
    if status == Status::SUCCESS {
        buffer as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

/// Frees pages by physical address, for a driver that allocated DMA memory with
/// `pages_for` and then has to give it back.
pub fn free_pages_physical(address: u64, pages: usize) -> Status {
    // SAFETY: the caller passes a run this firmware allocated, and freeing it
    // only drops it from the allocation list.
    unsafe { free_pages(address, pages) }
}

/// Whether an address range is in RAM the firmware may hand out. Used by
/// drivers that need to check a device-provided address.
pub fn is_ram(start: usize, size: usize) -> bool {
    start >= platform::RAM_BASE && start + size <= ram_end()
}
