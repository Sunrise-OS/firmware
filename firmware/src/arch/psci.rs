//! PSCI: the power-control calls this machine exposes.
//!
//! QEMU's `virt` device tree declares `arm,psci-1.0` with `method = "hvc"`, so
//! every call goes out as an HVC with the function identifier in `x0` and its
//! arguments in `x1`-`x3`. The identifiers are the standard ones: 32-bit calls
/// for the operations that fit, 64-bit for those that need an address.
use core::arch::asm;

/// `PSCI_CPU_OFF`: not used yet, but the shutdown path is symmetric with it.
const CPU_OFF: u64 = 0x8400_0002;
/// `PSCI_SYSTEM_OFF`: power the machine down.
const SYSTEM_OFF: u64 = 0x8400_0008;
/// `PSCI_SYSTEM_RESET`: reset the machine.
const SYSTEM_RESET: u64 = 0x8400_0009;
/// `PSCI_CPU_ON`: start a secondary core at an entry address.
const CPU_ON: u64 = 0xc400_0003;

/// Issues a PSCI call with one argument and no return we care about.
///
/// # Safety
///
/// The identifiers must name operations the machine implements; `SYSTEM_OFF`
/// and `SYSTEM_RESET` do not return.
fn call(function: u64, argument: u64) -> i64 {
    let result: i64;
    // SAFETY: the HVC interface exists at EL1 (`method = "hvc"`), and the
    // register conventions are PSCI's own.
    unsafe {
        asm!(
            "hvc #0",
            inlateout("x0") function as i64 => result,
            in("x1") argument,
            options(nostack)
        );
    }
    result
}

/// Powers the machine off. Never returns on success.
pub fn system_off() -> ! {
    let _ = call(SYSTEM_OFF, 0);
    // A machine that refused to power off has nothing sensible left to do.
    crate::arch::halt()
}

/// Resets the machine. Never returns on success.
pub fn system_reset() -> ! {
    let _ = call(SYSTEM_RESET, 0);
    crate::arch::halt()
}

/// Starts a secondary core. Returns PSCI's status: 0 on success, a negative
/// error otherwise (`-5` is `ALREADY_ON`).
///
/// # Safety
///
/// `entry` must be a valid instruction address, and `context` whatever its ABI
/// passes on in `x0`.
pub unsafe fn cpu_on(mpidr: u64, entry: usize, context: usize) -> i64 {
    // SAFETY: the caller guarantees the entry point.
    unsafe { call_cpu_on(CPU_ON, mpidr, entry as u64, context as u64) }
}

unsafe fn call_cpu_on(function: u64, target: u64, entry: u64, context: u64) -> i64 {
    let result: i64;
    // SAFETY: as `call`, plus the extra arguments PSCI's ABI takes.
    unsafe {
        asm!(
            "hvc #0",
            inlateout("x0") function as i64 => result,
            in("x1") target,
            in("x2") entry,
            in("x3") context,
            options(nostack)
        );
    }
    result
}

/// The calling convention's status codes, for callers that want to report them.
pub const SUCCESS: i64 = 0;
pub const ALREADY_ON: i64 = -5;
