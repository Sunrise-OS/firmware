//! Address map of the machine this firmware runs on.
//!
//! The target is QEMU's AArch64 `virt` machine, the machine
//! `scripts/run-qemu.sh` boots. These are the addresses QEMU's own device tree
//! gives for that machine; `platform::init` overrides what the tree handed over
//! in `x0` says differently (the RAM size, principally), and everything the
//! firmware maps or programs comes from here.

/// Executed in place: QEMU maps `-bios` into pflash0 at address 0 and resets
/// the core there. Read-only, so nothing writable is linked into it.
pub const FLASH_BASE: usize = 0x0000_0000;
pub const FLASH_SIZE: usize = 64 * 1024 * 1024;

/// The low DRAM window. RAM continues above 4 GiB on machines sized past 1 GiB;
/// the firmware reads the real size out of the device tree.
pub const RAM_BASE: usize = 0x4000_0000;
pub const RAM_SIZE_MAX: usize = 4 * 1024 * 1024 * 1024;

/// ARM PrimeCell PL011 UART: the console, and `EFI_SIMPLE_TEXT_OUTPUT`'s.
pub const UART0_BASE: usize = 0x0900_0000;
/// PL031 real-time clock, behind `GetTime`/`SetTime`.
pub const RTC_BASE: usize = 0x0901_0000;
/// QEMU's fw_cfg: the machine's own ACPI tables and the ramfb configuration.
pub const FW_CFG_BASE: usize = 0x0902_0000;

/// The GICv3 the machine is run with (`-machine virt,gic-version=3`): a
/// distributor, and a redistributor region with a pair of frames per core. The
/// GICv2 windows below them are not part of this machine, but the old GICv2
/// driver in `arch::gic` still names them.
pub const GIC_DIST_BASE: usize = 0x0800_0000;
pub const GIC_REDIST_BASE: usize = 0x080a_0000;
/// Four cores, two frames each: what `-smp 4` gives the machine.
pub const GIC_REDIST_SIZE: usize = 0x8_0000;
pub const GIC_CPU_BASE: usize = 0x0801_0000;
pub const GIC_V2M_BASE: usize = 0x0802_0000;

/// 32 virtio-mmio transports at 0x200 bytes each. Boot media is normally a
/// PCI device here, but the MMIO transports are what the tree advertises.
pub const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;
pub const VIRTIO_MMIO_SIZE: usize = 0x200;
pub const VIRTIO_MMIO_COUNT: usize = 32;

/// PCIe: ECAM in high memory, a 32-bit MMIO window below 4 GiB and a 64-bit one
/// above. The GPEX host bridge is at 00:00.0.
pub const PCIE_ECAM_BASE: usize = 0x40_1000_0000;
pub const PCIE_ECAM_SIZE: usize = 0x1000_0000;
pub const PCIE_MMIO32_BASE: usize = 0x1000_0000;
pub const PCIE_MMIO32_SIZE: usize = 0x2f00_0000;
pub const PCIE_MMIO64_BASE: usize = 0x40_0000_0000;
pub const PCIE_MMIO64_SIZE: usize = 0x1_0000_0000;

/// The PSCI conduit from the device tree: `hvc` on this machine.
pub const PSCI_CONDUIT_HVC: bool = true;

// Notes on the numbers above, so a later reader does not have to re-derive them:
//
// * `flash@0` is `cfi-flash` with two 64 MiB banks; `-bios` loads the image into
//   the first, which is what address 0 is.
// * `pcie@10000000` ranges: ECAM at 0x40_1000_0000 (256 MiB), MMIO32
//   0x1000_0000..0x3eff_0000, MMIO64 0x40_0000_0000..0x41_0000_0000.
// * The GIC is v2 (`arm,cortex-a15-gic`): distributor, CPU interface, and a
//   v2m MSI frame. `intc` claims are GICv2 (acknowledge/EOI), not GICv3 (IAR1).

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The CPUs the machine has, as MPIDRs, in the order the device tree lists
/// them. The tree is the machine's own description of its cores, so it is what
/// the MADT and SMBIOS report; a machine that hands over no tree keeps the
/// single-core default below.
///
/// The MADT has to agree with the tree: Linux takes its CPU numbering for an
/// ACPI boot from the MADT's MPIDR fields, and a MADT that disagrees with the
/// tree is how a machine ends up running on one core.
const MAX_CPUS: usize = 8;

static MPIDRS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

pub fn set_cpus(mpidrs: &[u64]) {
    let count = mpidrs.len().clamp(1, MAX_CPUS);
    for (index, mpidr) in mpidrs[..count].iter().enumerate() {
        MPIDRS[index].store(*mpidr, Ordering::Release);
    }
    CPU_COUNT.store(count, Ordering::Release);
}

pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

pub fn mpidr(index: usize) -> u64 {
    MPIDRS[index.min(MAX_CPUS - 1)].load(Ordering::Acquire)
}

/// The end of RAM the firmware believes in. The device tree narrows the
/// pessimistic default: the firmware maps the whole window it could have, and
/// reports only what the machine actually has to the operating system.
static RAM_END: AtomicUsize = AtomicUsize::new(RAM_BASE + RAM_SIZE_MAX);

pub fn set_ram_end(end: usize) {
    RAM_END.store(end, Ordering::Release);
}

pub fn ram_end() -> usize {
    RAM_END.load(Ordering::Acquire)
}
