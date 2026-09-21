//! The HOB list the DXE core is handed.
//!
//! A DXE core is entered with a hand-off block list: the phase before it brings
//! the machine up and describes what it found. When TianoCore's PEI does that,
//! the list is built from the PI specification's structures; this firmware
//! builds the same structures itself, so that Patina's core sees the handoff it
//! expects without an EDK2 firmware around it.
//!
//! The hand-off table describes RAM, resource descriptors describe what the
//! core may use, the DXE module HOB locates its loaded PE image, and an FV HOB
//! lets Patina install and dispatch from the firmware volume that supplied it.
//! Firmware-owned windows (image, stack, heap, device tree and FV) are reserved.
//!
//! The list lives in this module's buffer, which is part of the firmware's
//! image, so it is mapped and reachable from the core's first instruction.

use core::ffi::c_void;

/// `EFI_HOB_GENERIC_HEADER`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    hob_type: u16,
    length: u16,
    reserved: u32,
}

/// `EFI_HOB_HANDOFF_INFO_TABLE`, which every HOB list starts with.
#[repr(C)]
#[derive(Clone, Copy)]
struct Handoff {
    header: Header,
    version: u32,
    boot_mode: u32,
    memory_top: u64,
    memory_bottom: u64,
    free_memory_top: u64,
    free_memory_bottom: u64,
    end_of_hob_list: u64,
}

/// `EFI_HOB_MEMORY_ALLOCATION_MODULE`: where the DXE core's own image is. The
/// core finds it by the module GUID it carries, and reads the image to map it,
/// so the image has to be a real PE at the address this names.
///
/// A memory allocation HOB is not a type of its own: it is the memory
/// allocation type, and this variant is the one whose length says it carries a
/// module name and an entry point.
#[repr(C)]
#[derive(Clone, Copy)]
struct MemoryAllocationModule {
    header: Header,
    name: [u8; 16],
    memory_base_address: u64,
    memory_length: u64,
    memory_type: u32,
    reserved: [u8; 4],
    module_name: [u8; 16],
    entry_point: u64,
}

/// `EFI_HOB_FIRMWARE_VOLUME`: the FV that supplied the DXE core, kept in RAM
/// so Patina can publish its files through the firmware volume protocols.
#[repr(C)]
#[derive(Clone, Copy)]
struct FirmwareVolume {
    header: Header,
    base_address: u64,
    length: u64,
}

/// `EFI_HOB_CPU`: how wide the machine's physical addresses and I/O ports are.
#[repr(C)]
#[derive(Clone, Copy)]
struct Cpu {
    header: Header,
    size_of_memory_space: u8,
    size_of_io_space: u8,
    reserved: [u8; 6],
}

/// `EFI_HOB_RESOURCE_DESCRIPTOR`, the specification's second revision of it: the
/// original structure with the resource's cacheability appended. The core reads
/// this revision only, and takes the attributes it initialises the GCD with from
/// the descriptor covering the hand-off table's free memory.
#[repr(C)]
#[derive(Clone, Copy)]
struct ResourceDescriptor {
    header: Header,
    owner: [u8; 16],
    resource_type: u32,
    resource_attribute: u32,
    physical_start: u64,
    resource_length: u64,
    /// Cacheability, as `EFI_MEMORY_WB` and its neighbours describe it.
    attributes: u64,
}

/// `EFI_HOB_TYPE_HANDOFF`.
const TYPE_HANDOFF: u16 = 0x0001;
/// `EFI_HOB_MEMORY_ALLOCATION`: memory the firmware allocated, named for what it
/// holds. The core looks for the stack by this name, and makes it
/// non-executable; without it the core stops with "No stack hob found".
#[repr(C)]
#[derive(Clone, Copy)]
struct MemoryAllocation {
    header: Header,
    name: [u8; 16],
    memory_base_address: u64,
    memory_length: u64,
    memory_type: u32,
    reserved: [u8; 4],
}

/// `EFI_HOB_TYPE_MEMORY_ALLOCATION`.
const TYPE_MEMORY_ALLOCATION: u16 = 0x0002;
/// `EFI_MEMORY_TYPE` of the DXE core's image, which is boot services code: the
/// operating system may reclaim it once boot services end.
const MEMORY_BOOT_SERVICES_CODE: u32 = 0x0000_0003;
/// `EFI_HOB_MEMORY_ALLOC_STACK_GUID`: how the core finds the stack it was called
/// on, which it marks non-executable.
const MEMORY_ALLOC_STACK_GUID: [u8; 16] = [
    0x27, 0xbf, 0xd4, 0x4e, 0x92, 0x40, 0xe9, 0x42, 0x80, 0x7d, 0x52, 0x7b, 0x1d, 0x00, 0xc9, 0xbd,
];

/// `EFI_MEMORY_TYPE` of a stack: boot services data, reclaimed once boot services
/// end.
const MEMORY_BOOT_SERVICES_DATA: u32 = 0x0000_0004;

/// The DXE core is filed under its own identity, `patina::guid::DXE_CORE_ID`.
const DXE_CORE_ID: [u8; 16] = [
    0x2f, 0x32, 0xc9, 0x23, 0xf2, 0x2a, 0x6a, 0x47, 0xbc, 0x4c, 0x26, 0xbc, 0x88, 0x26, 0x6c, 0x71,
];
/// `EFI_HOB_TYPE_FV`.
const TYPE_FV: u16 = 0x0005;

/// `EFI_HOB_TYPE_CPU`. The core initializes the GCD when it sees this HOB, so
/// without it the core has no memory space at all.
const TYPE_CPU: u16 = 0x0006;
/// `EFI_HOB_TYPE_RESOURCE_DESCRIPTOR` as the specification's second revision
/// numbers it, which is the revision the core parses.
const TYPE_RESOURCE_DESCRIPTOR: u16 = 0x000d;
/// `EFI_HOB_TYPE_END_OF_HOB_LIST`.
const TYPE_END_OF_HOB_LIST: u16 = 0xffff;

/// `EFI_RESOURCE_SYSTEM_MEMORY`: memory the core may hand out.
const RESOURCE_SYSTEM_MEMORY: u32 = 0x0000_0000;
/// `EFI_RESOURCE_MEMORY_MAPPED_IO`: the machine's devices. The core maps these
/// into its page tables, so a device that is not described is a device that
/// faults on the first access - the console included.
const RESOURCE_MEMORY_MAPPED_IO: u32 = 0x0000_0001;
/// `EFI_RESOURCE_MEMORY_RESERVED`: memory it must leave alone.
const RESOURCE_MEMORY_RESERVED: u32 = 0x0000_0005;

/// `EFI_RESOURCE_ATTRIBUTE_PRESENT | INITIALIZED | TESTED`, plus the statement
/// that the range's execution permission can be changed. The core makes RAM and
/// device windows non-executable while it runs, and that is only permitted for a
/// range whose attributes say it can be: without this, mapping the console fails
/// and the firmware goes quiet.
const RESOURCE_ATTRIBUTES: u32 = 0x0000_0007 | 0x0040_0000;
/// `EFI_RESOURCE_ATTRIBUTE_PRESENT` and the same permission, which is all a
/// reserved range has.
///
/// `EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE` is declared too: the core maps a
/// reserved range write-back, as RAM, and it may only set the caching a range's
/// capabilities allow - the firmware's own image and the FV failed to map
/// without it.
const RESOURCE_ATTRIBUTES_RESERVED: u32 = 0x0000_0001 | 0x0000_2000 | 0x0040_0000;
/// A device window's attributes: the same, plus `EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE`.
/// The core derives a range's GCD capabilities from these bits, and a device
/// window whose capabilities lack `EFI_MEMORY_UC` is one the core cannot map as
/// the uncached memory it is: every MMIO window then failed to map with an
/// invalid state transition.
const RESOURCE_ATTRIBUTES_DEVICE: u32 = RESOURCE_ATTRIBUTES | 0x0000_0400;
/// `EFI_MEMORY_WB`: write-back caching, which is what RAM is.
const CACHE_WRITE_BACK: u64 = 0x0000_0000_0000_0008;
/// `EFI_MEMORY_UC`: uncached, which is what a device window is. A device mapped
/// as cacheable is a device whose writes arrive late, in whatever order they
/// feel like.
const CACHE_UNCACHED: u64 = 0x0000_0000_0000_0001;

/// The PI specification revision the list claims, and a boot that configured
/// everything it found.
const VERSION: u32 = 0x0000_0009;
const BOOT_WITH_FULL_CONFIGURATION: u32 = 0x0000_0000;

/// The list is small - a hand-off table, a descriptor per window, and an end
/// marker - so the buffer holds far more than it needs.
const AREA_SIZE: usize = 4096;

#[repr(align(8))]
struct Area([u8; AREA_SIZE]);

static mut AREA: Area = Area([0; AREA_SIZE]);

/// Writes structures into the buffer, one after another, each aligned to eight
/// bytes as the specification requires.
struct Builder<'a> {
    area: &'a mut [u8],
    cursor: usize,
}

impl Builder<'_> {
    fn push<T: Copy>(&mut self, value: &T) {
        let size = core::mem::size_of::<T>();
        let end = self.cursor + size;
        assert!(end <= self.area.len(), "the HOB list outgrew its buffer");
        // SAFETY: the structure is `repr(C)`, it is copied immediately, and the
        // buffer was checked to be long enough.
        let bytes =
            unsafe { core::slice::from_raw_parts(core::ptr::from_ref(value).cast::<u8>(), size) };
        self.area[self.cursor..end].copy_from_slice(bytes);
        self.cursor = (end + 7) & !7;
    }

    /// Describes a range, minus the hand-off window, which the core describes to
    /// itself and refuses to see described twice.
    fn describe_skipping(
        &mut self,
        start: usize,
        end: usize,
        reserved: bool,
        skip: (usize, usize),
    ) {
        if skip.1 <= start || skip.0 >= end {
            self.describe(start, end, reserved);
            return;
        }
        if skip.0 > start {
            self.describe(start, skip.0, reserved);
        }
        if skip.1 < end {
            self.describe(skip.1, end, reserved);
        }
    }

    /// A device window: memory-mapped I/O, which the core maps and does not hand
    /// out.
    fn describe_device(&mut self, start: usize, end: usize) {
        self.push(&ResourceDescriptor {
            header: Header {
                hob_type: TYPE_RESOURCE_DESCRIPTOR,
                length: core::mem::size_of::<ResourceDescriptor>() as u16,
                reserved: 0,
            },
            owner: [0; 16],
            resource_type: RESOURCE_MEMORY_MAPPED_IO,
            resource_attribute: RESOURCE_ATTRIBUTES_DEVICE,
            physical_start: start as u64,
            resource_length: (end - start) as u64,
            attributes: CACHE_UNCACHED,
        });
    }

    fn describe(&mut self, start: usize, end: usize, reserved: bool) {
        // Every range carries a cache attribute: memory the core maps without
        // one is memory its page tables refuse to describe, and the cores's own
        // stack is one of these ranges.
        let (resource_type, resource_attribute, cache) = if reserved {
            (
                RESOURCE_MEMORY_RESERVED,
                RESOURCE_ATTRIBUTES_RESERVED,
                CACHE_WRITE_BACK,
            )
        } else {
            (
                RESOURCE_SYSTEM_MEMORY,
                RESOURCE_ATTRIBUTES,
                CACHE_WRITE_BACK,
            )
        };
        self.push(&ResourceDescriptor {
            header: Header {
                hob_type: TYPE_RESOURCE_DESCRIPTOR,
                length: core::mem::size_of::<ResourceDescriptor>() as u16,
                reserved: 0,
            },
            owner: [0; 16],
            resource_type,
            resource_attribute,
            physical_start: start as u64,
            resource_length: (end - start) as u64,
            attributes: cache,
        });
    }
}

/// Builds the HOB list and returns the pointer to hand to the DXE core.
///
/// `ram` is the machine's memory, low and high. `reserved` are the windows the
/// core must not use, in any order and possibly overlapping; everything in `ram`
/// they do not cover is offered as system memory.
///
/// `devices` are the machine's memory-mapped I/O windows.
///
/// `stack` is where the firmware's stack is, and how much of it there is. The
/// core marks it non-executable, so it is also the range the core must find in
/// its own memory space: a stack outside what the HOB list describes is a panic
/// rather than a quietly unprotected stack.
///
/// `dxe_core` is where the core's image has been loaded, how big it is, and its
/// entry point. The core maps that image during paging setup, and fails if the
/// HOB list does not describe it.
///
/// `firmware_volume` is the RAM copy of the FV, kept reserved and readable
/// throughout DXE so the PI dispatcher can install its FFS files.
///
/// `address_bits` is how wide the machine's physical addresses are, which the
/// core needs before it can size anything: it is the same width this firmware
/// programmed its own translation for.
///
/// `hob_heap` is memory the core may allocate HOBs from before its own allocator
/// runs, which the hand-off table advertises. No resource descriptor describes
/// it: the core adds that memory to its own memory space, and a descriptor for a
/// range the core has already claimed is refused, which would lose whatever else
/// that descriptor covered.
///
/// # Safety
///
/// Called once, before the core runs. The returned pointer stays valid for the
/// rest of the boot.
pub unsafe fn build(
    ram: (usize, usize),
    reserved: &[(usize, usize)],
    hob_heap: (usize, usize),
    address_bits: u8,
    dxe_core: (usize, usize, usize),
    firmware_volume: (usize, usize),
    stack: (usize, usize),
    devices: &[(usize, usize)],
) -> *const c_void {
    let mut windows: alloc::vec::Vec<(usize, usize)> = alloc::vec::Vec::new();
    for &(start, end) in reserved {
        let start = start.max(ram.0);
        let end = end.min(ram.1);
        if end > start {
            windows.push((start, end));
        }
    }
    windows.sort_unstable();
    // The hand-off window is left out of the descriptors: the core adds it.
    let hob_heap = (hob_heap.0.max(ram.0), hob_heap.1.min(ram.1));

    // SAFETY: the buffer is this module's, and the caller guarantees this runs
    // once, before anything else reads the list.
    let area = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(AREA.0).cast::<u8>(), AREA_SIZE)
    };
    let base = area.as_mut_ptr() as usize;
    let mut builder = Builder { area, cursor: 0 };

    // The hand-off table first. Its free-memory fields are the HOB heap, which
    // the core allocates from before its own allocator exists.
    builder.push(&Handoff {
        header: Header {
            hob_type: TYPE_HANDOFF,
            length: core::mem::size_of::<Handoff>() as u16,
            reserved: 0,
        },
        version: VERSION,
        boot_mode: BOOT_WITH_FULL_CONFIGURATION,
        memory_top: ram.1 as u64,
        memory_bottom: ram.0 as u64,
        free_memory_top: hob_heap.1 as u64,
        free_memory_bottom: hob_heap.0 as u64,
        end_of_hob_list: 0,
    });

    // The CPU HOB next: the core reads it to size its address spaces, and the
    // GCD is only initialised when it has been seen. I/O ports are not a thing
    // on this machine.
    builder.push(&Cpu {
        header: Header {
            hob_type: TYPE_CPU,
            length: core::mem::size_of::<Cpu>() as u16,
            reserved: 0,
        },
        size_of_memory_space: address_bits,
        size_of_io_space: 0,
        reserved: [0; 6],
    });

    // The stack this firmware called the core on.
    builder.push(&MemoryAllocation {
        header: Header {
            hob_type: TYPE_MEMORY_ALLOCATION,
            length: core::mem::size_of::<MemoryAllocation>() as u16,
            reserved: 0,
        },
        name: MEMORY_ALLOC_STACK_GUID,
        memory_base_address: stack.0 as u64,
        memory_length: stack.1 as u64,
        memory_type: MEMORY_BOOT_SERVICES_DATA,
        reserved: [0; 4],
    });

    // The core's own image, so it can find and map itself.
    builder.push(&MemoryAllocationModule {
        header: Header {
            hob_type: TYPE_MEMORY_ALLOCATION,
            length: core::mem::size_of::<MemoryAllocationModule>() as u16,
            reserved: 0,
        },
        name: DXE_CORE_ID,
        memory_base_address: dxe_core.0 as u64,
        memory_length: dxe_core.1 as u64,
        memory_type: MEMORY_BOOT_SERVICES_CODE,
        reserved: [0; 4],
        module_name: DXE_CORE_ID,
        entry_point: dxe_core.2 as u64,
    });

    builder.push(&FirmwareVolume {
        header: Header {
            hob_type: TYPE_FV,
            length: core::mem::size_of::<FirmwareVolume>() as u16,
            reserved: 0,
        },
        base_address: firmware_volume.0 as u64,
        length: firmware_volume.1 as u64,
    });

    // Then walk the memory, describing what the core may use and what it may not.
    let mut at = ram.0;
    for &(start, end) in &windows {
        if start > at {
            builder.describe_skipping(at, start, false, hob_heap);
        }
        builder.describe_skipping(start, end, true, hob_heap);
        at = at.max(end);
    }
    if at < ram.1 {
        builder.describe_skipping(at, ram.1, false, hob_heap);
    }

    // The machine's devices, after the memory: the core maps these into its page
    // tables, so that reaching the console or a disk does not fault once it has
    // installed its own translation.
    for &(start, end) in devices {
        builder.describe_device(start, end);
    }

    builder.push(&Header {
        hob_type: TYPE_END_OF_HOB_LIST,
        length: core::mem::size_of::<Header>() as u16,
        reserved: 0,
    });
    let end = base + builder.cursor;
    let length = builder.cursor;

    // SAFETY: the hand-off table is the first structure in the buffer, which
    // this function owns for the rest of the boot.
    unsafe { (*(base as *mut Handoff)).end_of_hob_list = end as u64 };
    debug_assert!(length <= AREA_SIZE);

    base as *const c_void
}
