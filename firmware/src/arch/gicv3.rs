//! The GICv3 state a firmware has to leave behind for the DXE core.
//!
//! The core brings the interrupt controller up itself, but it expects to be
//! handed a machine whose timer ticks: its paging sleeps for an interrupt when
//! it waits for one, and an interrupt that nothing ever raises is a core that
//! stops - which is exactly what happened before this module existed.
//!
//! So this does the minimum to make the timer's interrupt reachable, and no
//! more:
//!
//! * the redistributor's SGI/PPI frame for *this* core, found by matching its
//!   affinity against `MPIDR_EL1`, with the EL1 physical timer's private
//!   interrupt (30) given a priority and enabled;
//! * the CPU interface, which on GICv3 is a set of system registers rather than
//!   a window of memory, enabled through `ICC_SRE_EL1`;
//! * group 1 interrupts enabled, which is where those private interrupts live.
//!
//! Interrupts stay masked: the core unmasks them when it is ready, and this
//! firmware wants none of them before it hands over.

use core::arch::asm;
use core::ptr;

use crate::platform;

/// The EL1 physical timer's interrupt, as a private interrupt on this core.
const TIMER_PPI: u32 = 30;
/// A priority that is not the lowest and not the highest: what firmware
/// conventionally gives a timer.
const TIMER_PRIORITY: u8 = 0xa0;
/// Accept every priority: the mask is "interrupts with a lower priority number
/// than this are taken", and 0xf0 leaves room above for the core to raise its
/// own.
const PRIORITY_MASK: u64 = 0xf0;

/// The redistributor frame of the core this code runs on.
///
/// Redistributors are laid out one per core, each with a pair of 64 KiB frames,
/// and the last one says so in its type register. The first with matching
/// affinity is this core's.
fn redistributor() -> usize {
    let mpidr = read_mpidr();
    let mut frame = platform::GIC_REDIST_BASE;
    for _ in 0..64 {
        // SAFETY: the redistributor region is the machine's, mapped as device
        // memory by this firmware's own translation, and the machine declares
        // how many frames it has through the last one's type register.
        let typer = unsafe { ptr::read_volatile((frame + 0x0008) as *const u64) };
        let affine = typer >> 32;
        if affine & 0xff_00ff_ffff == mpidr & 0xff_00ff_ffff {
            return frame;
        }
        if typer & (1 << 4) != 0 {
            break;
        }
        // Two frames per core, or four where the core supports virtual
        // interrupts: bit 1 of the type register says which.
        frame += if typer & (1 << 1) != 0 {
            0x4_0000
        } else {
            0x2_0000
        };
    }
    // Nothing matched, which cannot happen on a machine whose device tree the
    // firmware has read: use the first frame rather than park the core.
    platform::GIC_REDIST_BASE
}

/// Reads `MPIDR_EL1`, which identifies the core this code is running on.
fn read_mpidr() -> u64 {
    let mpidr: u64;
    // SAFETY: `MPIDR_EL1` is readable at EL1 and reading it has no side effects.
    unsafe { asm!("mrs {}, MPIDR_EL1", out(reg) mpidr, options(nomem, nostack)) };
    mpidr
}

/// Brings up as much of the interrupt controller as the firmware's handover
/// needs, and leaves the timer's interrupt armed.
pub fn init() {
    let redistributor = redistributor();
    // The SGI/PPI frame is the second of the pair: private interrupts live
    // there, one priority byte each and one enable bit each.
    let sgi = redistributor + 0x1_0000;

    // SAFETY: the frame is this core's, mapped as device memory, and the
    // offsets are the ones the architecture defines for the priority byte and
    // the enable bit of a private interrupt.
    unsafe {
        ptr::write_volatile(
            (sgi + 0x400 + TIMER_PPI as usize) as *mut u8,
            TIMER_PRIORITY,
        );
        ptr::write_volatile((sgi + 0x100) as *mut u32, 1 << TIMER_PPI);
    }

    // SAFETY: the system register interface and the priority mask exist at EL1,
    // and this runs once, before anything can be interrupted.
    unsafe {
        asm!(
            "msr     ICC_SRE_EL1, {sre}",
            "msr     ICC_PMR_EL1, {mask}",
            "msr     ICC_IGRPEN1_EL1, {enable}",
            "isb",
            sre = in(reg) 0x7u64,
            mask = in(reg) PRIORITY_MASK,
            enable = in(reg) 1u64,
            options(nostack, preserves_flags),
        );
    }
}
