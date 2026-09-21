//! Identity-mapped page tables: the firmware's memory attributes.
//!
//! Until translation is on every address is Device-nGnRnE, so an unaligned
//! access faults and nothing is cacheable. The firmware's copies of
//! automatic-layout structs, and anything that reads a table it did not align,
//! need Normal memory; boot media and the interrupt controller need the
//! peripherals as Device. One identity map gives both: virtual addresses stay
//! physical, which is what the UEFI specification wants until an OS calls
//! `SetVirtualAddressMap`.

use aarch64_paging::{
    descriptor::El1Attributes,
    idmap::IdMap,
    paging::{El1And0, MemoryRegion},
};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::platform;

/// Root table at level 1: 4 KiB granule, 1 GiB per entry, 512 GiB of address
/// space. Everything this machine has is inside that.
const ROOT_LEVEL: usize = 1;
/// Non-zero so the firmware's mappings can be invalidated by ASID instead of a
/// full TLB flush. The value itself is arbitrary: nothing else runs here.
const ASID: usize = 1;

/// MAIR: index 0 Device-nGnRnE, index 1 Normal non-cacheable (see `NORMAL`),
/// index 2 Normal write-back, which is kept for regions that are provably never
/// touched by a device.
pub const MAIR: u64 = 0x00 | (0x44 << 8) | (0xff << 16);

/// TCR: 4 KiB granule, 39-bit virtual addresses (which is why the root table is
/// a level 1 one), inner shareable write-back walks, TTBR1 disabled (everything
/// is below 512 GiB), 40-bit physical addresses.
pub const TCR: u64 = 25          // T0SZ
    | (1 << 8)                   // IRGN0: write-back, read-write allocate
    | (1 << 10)                  // ORGN0
    | (3 << 12)                  // SH0: inner shareable
    | (1 << 23)                  // EPD1: no TTBR1 walks
    | (2 << 32); // IPS: 40-bit physical addresses

/// The attribute index of a device window, and of RAM: the numbers `MAIR`
/// above puts Device-nGnRnE and Normal non-cacheable at.
const DEVICE_INDEX: u64 = 0;
/// MAIR index 2 is Normal write-back (`0xff`). Non-cacheable is not an option
/// here: an exclusive access to non-cacheable memory is what HVF reports as a
/// fault, and the allocator's first lock is one.
const RAM_INDEX: u64 = 2;

/// A level 1 block descriptor - 1 GiB - for the reset path's table. `pa` is the
/// block's base, so it has to be 1 GiB aligned. A block that is not executable
/// has both PXN and UXN set; nothing at all executes below EL1.
const fn boot_block(pa: u64, attribute_index: u64, executable: bool) -> u64 {
    let mut entry =
        pa | (1 << 10) /* AF */ | (3 << 8) /* inner shareable */ | (attribute_index << 2) | 0b01;
    entry |= 1 << 54; // UXN: no EL0 in this firmware
    if !executable {
        entry |= 1 << 53; // PXN
    }
    entry
}

/// The level 1 table the reset path installs before the first compiled
/// instruction that touches memory.
///
/// With translation off, every access is Device-nGnRnE, and Device memory has
/// rules that compiled code breaks without meaning to: an atomic read-modify-
/// write - which is what the global allocator's very first lock is - is
/// unpredictable there, as are unaligned or multi-register accesses and `dc
/// zva`. A core that reports those as faults stops bring-up at the first
/// allocation, and one that does not hides the mistake until the firmware runs
/// on a machine that reports them.
///
/// So this table is in the image, read-only, with no allocation and no writes
/// to set it up: two 1 GiB blocks, the low one Device (the flash is in it, and
/// so is the console an early panic writes to) and the one above it RAM, which
/// is the whole of the memory the firmware's image, stack and heap occupy.
/// `init` replaces it with the full map, devices included.
#[repr(C, align(4096))]
pub struct BootTable(pub [u64; 512]);

pub static BOOT_TABLE: BootTable = {
    let mut entries = [0u64; 512];
    entries[0] = boot_block(0x0000_0000, DEVICE_INDEX, false);
    entries[1] = boot_block(platform::RAM_BASE as u64, RAM_INDEX, true);
    BootTable(entries)
};

/// MAIR index 0: Device-nGnRnE. Everything a driver programs lives here.
pub const DEVICE: El1Attributes = El1Attributes::ATTRIBUTE_INDEX_0;
/// MAIR index 2: Normal write-back, inner shareable.
///
/// Write-back, not the non-cacheable index. An exclusive access - the global
/// allocator's lock - to non-cacheable memory faults under HVF, which executes
/// the guest on the real core. A buffer a device DMA's into has to be mapped
/// non-cacheable on its own, when there is one; the firmware's image, stack and
/// heap are not that buffer.
const NORMAL: El1Attributes =
    El1Attributes::ATTRIBUTE_INDEX_2.union(El1Attributes::INNER_SHAREABLE);

const VALID: El1Attributes = El1Attributes::VALID.union(El1Attributes::ACCESSED);

/// A device register window: no speculation, no execution, never cachable.
pub const DEVICE_WINDOW: El1Attributes = DEVICE
    .union(El1Attributes::UXN)
    .union(El1Attributes::PXN)
    .union(VALID);

/// RAM: writable and executable, because the firmware runs PE images from it.
/// UXN stays set; nothing runs at EL0 in this firmware.
const RAM_WINDOW: El1Attributes = NORMAL.union(El1Attributes::UXN).union(VALID);

/// The page table, as a leaked pointer and never as an owned value: dropping an
/// `IdMap` frees it and puts the previous (empty) translation back, which would
/// leave the core without a valid mapping. It lives for the life of the
/// firmware, so the leak is the point.
static PAGETABLE: AtomicUsize = AtomicUsize::new(0);

/// Builds the identity map, turns translation on, and keeps the map alive.
///
/// `ram_end` is the end of RAM: the map must cover everything the firmware, its
/// heap, and the images it loads can touch.
pub fn init(ram_end: usize) {
    let mut map = IdMap::with_asid(ASID, ROOT_LEVEL, El1And0);

    // Flash: the image executes in place from read-only, cacheable memory.
    map.map_range(
        &MemoryRegion::new(
            platform::FLASH_BASE,
            platform::FLASH_BASE + platform::FLASH_SIZE,
        ),
        NORMAL
            .union(El1Attributes::READ_ONLY)
            .union(El1Attributes::UXN)
            .union(VALID),
    )
    .expect("mmu: flash");

    // Peripherals below 4 GiB: the GIC, the UART, the RTC, fw_cfg, the virtio
    // MMIO transports and the platform bus, then the 32-bit PCI MMIO window.
    map.map_range(&MemoryRegion::new(0x0800_0000, 0x0c00_0000), DEVICE_WINDOW)
        .expect("mmu: peripherals");
    map.map_range(
        &MemoryRegion::new(
            platform::PCIE_MMIO32_BASE,
            platform::PCIE_MMIO32_BASE + platform::PCIE_MMIO32_SIZE,
        ),
        DEVICE_WINDOW,
    )
    .expect("mmu: pci mmio32");

    map.map_range(&MemoryRegion::new(platform::RAM_BASE, ram_end), RAM_WINDOW)
        .expect("mmu: ram");

    // PCIe: the ECAM and the 64-bit MMIO window, both above 4 GiB, which is why
    // the root table has to cover more than the low 4 GiB.
    map.map_range(
        &MemoryRegion::new(
            platform::PCIE_ECAM_BASE,
            platform::PCIE_ECAM_BASE + platform::PCIE_ECAM_SIZE,
        ),
        DEVICE_WINDOW,
    )
    .expect("mmu: pcie ecam");
    map.map_range(
        &MemoryRegion::new(
            platform::PCIE_MMIO64_BASE,
            platform::PCIE_MMIO64_BASE + platform::PCIE_MMIO64_SIZE,
        ),
        DEVICE_WINDOW,
    )
    .expect("mmu: pci mmio64");

    // The attribute indices in those descriptors must agree with MAIR, which is
    // also what the reset path programs, so this only rewrites the same values.
    let mair: u64 = MAIR;
    let tcr: u64 = TCR;

    // SAFETY: MAIR_EL1 and TCR_EL1 are writable at EL1, and the tables these
    // describe are the ones `activate` is about to point the core at.
    unsafe {
        core::arch::asm!(
            "msr mair_el1, {mair}",
            "msr tcr_el1, {tcr}",
            "dsb ish",
            "isb",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            options(nostack)
        );
    }

    // SAFETY: every address the firmware touches - its image in flash, its
    // stack, heap and tables in RAM, and the peripherals it programs - is
    // mapped above, and the map is stored in PAGETABLE rather than dropped.
    unsafe {
        map.activate();

        let mut sctlr: u64;
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
        // M: translation on. C and I: data and instruction caches on. The RES1
        // bits are set as the architecture requires. WXN stays clear so RAM
        // stays executable, and A stays clear so unaligned accesses are legal.
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12);
        sctlr |= (1 << 11)
            | (1 << 20)
            | (1 << 22)
            | (1 << 23)
            | (1 << 28)
            | (1 << 29)
            | (1 << 30)
            | (1 << 31);
        sctlr &= !(1 << 1) & !(1 << 19);
        core::arch::asm!(
            "dsb ish",
            "msr sctlr_el1, {sctlr}",
            "isb",
            sctlr = in(reg) sctlr,
            options(nostack)
        );
    }

    let leaked: *mut IdMap<El1And0> = alloc::boxed::Box::leak(alloc::boxed::Box::new(map));
    PAGETABLE.store(leaked as usize, Ordering::Release);
}

/// Maps a device window into the live page table, for a driver whose registers
/// sit outside the windows mapped at bring-up.
pub fn map_device_window(start: usize, end: usize) {
    let map = PAGETABLE.load(Ordering::Acquire) as *mut IdMap<El1And0>;
    assert!(!map.is_null(), "mmu: not initialised");
    // SAFETY: the pointer is the leaked page table, which is never freed, and
    // mapping a device window only writes new descriptors into it.
    unsafe {
        (*map)
            .map_range(&MemoryRegion::new(start, end), DEVICE_WINDOW)
            .expect("mmu: device window");
    }
}
