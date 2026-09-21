//! The architectured timer: `CNTFRQ`/`CNTPCT` and the EL1 physical timer.
//!
//! The counter is what the firmware measures time with (`Stall`, event
//! deadlines, `GetTime`'s tick), and the EL1 physical timer's interrupt is what
//! drives periodic work. QEMU's `virt` machine signals that timer as PPI 14,
//! which is interrupt ID 30 on both GIC generations.

use core::sync::atomic::{AtomicU64, Ordering};

/// The EL1 physical timer's interrupt: PPI 14.
pub const TIMER_IRQ: u32 = 14 + 16;

/// Interrupts taken since reset. Read by the boot banner to show the timer is
/// live, and by `Stall` for its deadline.
static TICKS: AtomicU64 = AtomicU64::new(0);

/// The counter frequency in Hz, from `CNTFRQ_EL0`.
pub fn frequency() -> u64 {
    let value: u64;
    // SAFETY: reading the counter frequency register has no side effects.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) value, options(nomem, nostack)) };
    value
}

/// The system counter's current value.
pub fn counter() -> u64 {
    let value: u64;
    // SAFETY: reading the counter has no side effects.
    unsafe {
        core::arch::asm!("isb", "mrs {}, cntpct_el0", out(reg) value, options(nomem, nostack))
    };
    value
}

/// The timer's period: ten milliseconds, the tick event timers are checked
/// against.
pub fn period_ticks() -> u64 {
    frequency() / 100
}

/// The number of timer interrupts taken so far.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Converts a duration in nanoseconds to counter ticks.
pub fn ticks_from_ns(ns: u64) -> u64 {
    (ns * frequency()) / 1_000_000_000
}

/// Arms the EL1 physical timer to fire after `ticks` counter ticks.
pub fn arm(ticks: u64) {
    // SAFETY: the timer registers are writable at EL1 once EL2 has handed the
    // physical timer over (`CNTHCTL_EL2`), which the EL2 drop does.
    unsafe {
        core::arch::asm!(
            "msr cntp_tval_el0, {ticks}",
            "mov x1, #1",           // ENABLE
            "msr cntp_ctl_el0, x1",
            "isb",
            ticks = in(reg) ticks,
            out("x1") _,
            options(nostack)
        );
    }
}

/// Stops the EL1 physical timer.
pub fn disable() {
    // SAFETY: as `arm`.
    unsafe {
        core::arch::asm!("msr cntp_ctl_el0, xzr", "isb", options(nostack));
    }
}

/// Re-arms the timer and counts the tick. Called from the IRQ path.
///
/// Re-arming from a fixed period, rather than from the moment the handler runs,
/// keeps the period independent of how late the handler was.
pub fn on_irq(period_ticks: u64) {
    TICKS.fetch_add(1, Ordering::Relaxed);
    arm(period_ticks);
}

/// The system counter expressed in the specification's 100 ns units. This is
/// the unit every EFI timer deadline is in.
pub fn now_100ns() -> u64 {
    counter().wrapping_mul(10_000_000) / frequency()
}

/// Busy-waits for the given number of microseconds, for `Stall`.
pub fn stall_microseconds(microseconds: u64) {
    if microseconds == 0 {
        return;
    }
    let start = counter();
    let ticks = microseconds * frequency() / 1_000_000;
    while counter().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}
