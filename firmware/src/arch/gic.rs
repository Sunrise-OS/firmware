//! GICv2: the distributor, the CPU interface, and interrupt dispatch.
//!
//! QEMU's AArch64 `virt` machine describes `arm,cortex-a15-gic` with
//! `-cpu cortex-a57`, which is GICv2: one distributor for shared interrupts, one
//! CPU interface per core for the private ones, and single-register acknowledge
//! and end-of-interrupt at the CPU interface.

use crate::platform;

const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_ISPENDR: usize = 0x200;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_IGROUPR: usize = 0x080;

const GICC_CTLR: usize = 0x0000;
const GICC_PMR: usize = 0x0004;
const GICC_IAR: usize = 0x000c;
const GICC_EOIR: usize = 0x0010;

/// Interrupt IDs at or above this are not real interrupts: 1020 is "spurious",
/// 1022 and 1023 are the group signals.
const INTERRUPT_ID_LIMIT: u32 = 1020;

#[inline]
fn dist_read(offset: usize) -> u32 {
    // SAFETY: the distributor is mapped Device memory at a known base.
    unsafe { core::ptr::read_volatile((platform::GIC_DIST_BASE + offset) as *mut u32) }
}

#[inline]
fn dist_write(offset: usize, value: u32) {
    // SAFETY: as `dist_read`.
    unsafe { core::ptr::write_volatile((platform::GIC_DIST_BASE + offset) as *mut u32, value) }
}

#[inline]
fn cpu_read(offset: usize) -> u32 {
    // SAFETY: the CPU interface is mapped Device memory at a known base.
    unsafe { core::ptr::read_volatile((platform::GIC_CPU_BASE + offset) as *mut u32) }
}

#[inline]
fn cpu_write(offset: usize, value: u32) {
    // SAFETY: as `cpu_read`.
    unsafe { core::ptr::write_volatile((platform::GIC_CPU_BASE + offset) as *mut u32, value) }
}

/// Brings the distributor and this core's CPU interface up and enables the
/// given interrupt IDs. Every interrupt is group 1 and targets this core, which
/// is the only configuration a single-core UEFI environment needs.
pub fn init(interrupts: &[u32]) {
    dist_write(GICD_CTLR, 0);
    cpu_write(GICC_CTLR, 0);

    for &id in interrupts {
        // Interrupts below 32 are private to the core: the target register does
        // not cover them, and a write there would hit the next interrupt's bits.
        if id >= 32 {
            let target = GICD_ITARGETSR + (id as usize & !3);
            dist_write(target, 0xff << ((id & 3) * 8));
            dist_write(GICD_IGROUPR + (id as usize & !31), 1 << (id & 31));
            dist_write(GICD_IPRIORITYR + (id as usize & !3), 0);
        }
        dist_write(GICD_ISENABLER + (id as usize & !31), 1 << (id & 31));
        // Clear a stale pending state, so enabling does not deliver an interrupt
        // the firmware never asked for.
        dist_write(GICD_ISPENDR + (id as usize & !31), 1 << (id & 31));
    }

    // Priorities below 0xf0 are accepted; 0xff would mask everything.
    cpu_write(GICC_PMR, 0xf0);
    cpu_write(GICC_CTLR, 1);
    dist_write(GICD_CTLR, 1);
}

/// Acknowledges the interrupt, dispatches it, and signals end of interrupt.
/// Called from the IRQ vector.
pub fn handle_irq() {
    let acknowledge = cpu_read(GICC_IAR);
    let id = acknowledge & 0x3ff;
    if id >= INTERRUPT_ID_LIMIT {
        return;
    }

    match id {
        crate::arch::timer::TIMER_IRQ => {
            crate::arch::timer::on_irq(crate::arch::timer::period_ticks())
        }
        _ => {}
    }

    cpu_write(GICC_EOIR, acknowledge);
}

/// Whether the interrupt is pending in the distributor. Used by drivers that
/// prefer to poll.
pub fn is_pending(id: u32) -> bool {
    dist_read(GICD_ISPENDR + (id as usize & !31)) & (1 << (id & 31)) != 0
}
