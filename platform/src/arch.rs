//! The architectural protocols Patina expects a platform to produce.
//!
//! Patina provides the CPU and hardware-interrupt protocols itself but, like
//! EDK2's DXE core, it leaves time to the platform. Without these, timer events
//! never fire (so `WaitForEvent` on a timer blocks forever), `Stall` returns
//! `NOT_READY`, and `SetWatchdogTimer` fails.
//!
//! * Timer: the EL1 physical timer, PPI 14 (interrupt ID 30) on QEMU `virt`,
//!   through the hardware-interrupt protocol Patina installs.
//! * Metronome: a busy-wait on the system counter, in 100 ns ticks.
//! * Watchdog: accepted and remembered, never fired.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering},
};

use patina::BinaryGuid;
use patina::component::component;
use patina::error::{EfiError, Result};
use patina::pi::protocol::{metronome, timer, watchdog};
use patina::standard::efi::{self, Guid};
use patina::uefi::boot_services::{BootServices, StandardBootServices};

/// The EL1 physical timer's interrupt ID on QEMU `virt`: PPI 14.
const TIMER_INTERRUPT: u64 = 30;
/// The period the timer starts with: 10 ms, in 100 ns units, which is what
/// EDK2's `PcdTimerPeriod` defaults to.
const DEFAULT_PERIOD: u64 = 100_000;

const HARDWARE_INTERRUPT_GUID: BinaryGuid =
    BinaryGuid::from_string("2890B3EA-053D-1643-AD0C-D64808DA3FF1");
static HARDWARE_INTERRUPT: Guid = HARDWARE_INTERRUPT_GUID.into_inner();
static TIMER_GUID: Guid = timer::PROTOCOL_GUID.into_inner();
static METRONOME_GUID: Guid = metronome::PROTOCOL_GUID.into_inner();
static WATCHDOG_GUID: Guid = watchdog::PROTOCOL_GUID.into_inner();

/// The first five members of `EFI_HARDWARE_INTERRUPT_PROTOCOL`, in EDK2's
/// layout. Patina's own definition is private to its core; the ABI is what
/// matters, and it is the one EDK2's ARM timer driver calls.
#[repr(C)]
struct HardwareInterrupt {
    register_interrupt_source: unsafe extern "efiapi" fn(
        *mut HardwareInterrupt,
        u64,
        Option<InterruptHandler>,
    ) -> efi::Status,
    enable_interrupt_source: unsafe extern "efiapi" fn(*mut HardwareInterrupt, u64) -> efi::Status,
    disable_interrupt_source: unsafe extern "efiapi" fn(*mut HardwareInterrupt, u64) -> efi::Status,
    get_interrupt_source_state:
        unsafe extern "efiapi" fn(*mut HardwareInterrupt, u64, *mut bool) -> efi::Status,
    end_of_interrupt: unsafe extern "efiapi" fn(*mut HardwareInterrupt, u64) -> efi::Status,
}

/// The handler signature: the interrupt source and the exception context.
type InterruptHandler = extern "efiapi" fn(u64, *mut c_void);

static INTERRUPTS: AtomicPtr<HardwareInterrupt> = AtomicPtr::new(core::ptr::null_mut());
/// The core's tick handler, as a function address; zero when none is set.
static NOTIFY: AtomicUsize = AtomicUsize::new(0);
/// The current period in 100 ns units; zero means the timer is off.
static PERIOD: AtomicU64 = AtomicU64::new(0);
static WATCHDOG_PERIOD: AtomicU64 = AtomicU64::new(0);

fn frequency() -> u64 {
    let value: u64;
    // SAFETY: reading CNTFRQ_EL0 has no side effects.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) value, options(nomem, nostack)) };
    value
}

fn counter() -> u64 {
    let value: u64;
    // SAFETY: reading CNTPCT_EL0 has no side effects; the ISB orders it after
    // the instructions before it.
    unsafe {
        core::arch::asm!("isb", "mrs {}, cntpct_el0", out(reg) value, options(nomem, nostack))
    };
    value
}

/// Counter ticks in `units` of 100 ns.
fn counter_ticks(units: u64) -> u64 {
    ((units as u128 * frequency() as u128) / 10_000_000) as u64
}

/// Arms the EL1 physical timer to fire `units` × 100 ns from now.
fn arm(units: u64) {
    let ticks = counter_ticks(units).clamp(1, u32::MAX as u64);
    // SAFETY: the reset stage granted EL1 the physical timer (CNTHCTL_EL2), and
    // this driver owns it for the DXE phase.
    unsafe {
        core::arch::asm!(
            "msr cntp_tval_el0, {ticks}",
            "msr cntp_ctl_el0, {enable}",
            "isb",
            ticks = in(reg) ticks,
            enable = in(reg) 1u64,
            options(nostack)
        );
    }
}

fn disarm() {
    // SAFETY: as `arm`.
    unsafe { core::arch::asm!("msr cntp_ctl_el0, xzr", "isb", options(nostack)) };
}

fn notify() -> Option<timer::EfiTimerNotify> {
    match NOTIFY.load(Ordering::Acquire) {
        0 => None,
        // SAFETY: only `register_handler` stores into NOTIFY, and it stores a
        // function of this type.
        address => Some(unsafe { core::mem::transmute::<usize, timer::EfiTimerNotify>(address) }),
    }
}

/// The timer interrupt. The next period is armed and the interrupt ended before
/// the core's handler runs: the handler restores the TPL, which re-enables
/// interrupts, and a level interrupt still asserted then would re-enter here.
extern "efiapi" fn timer_interrupt(source: u64, _context: *mut c_void) {
    let period = PERIOD.load(Ordering::Acquire);
    if period == 0 {
        disarm();
    } else {
        arm(period);
    }
    let interrupts = INTERRUPTS.load(Ordering::Acquire);
    if !interrupts.is_null() {
        // SAFETY: the protocol was located at install time and outlives boot
        // services.
        unsafe { ((*interrupts).end_of_interrupt)(interrupts, source) };
    }
    if let Some(notify) = notify() {
        notify(period);
    }
}

extern "efiapi" fn register_handler(
    _this: *mut timer::TimerProtocol,
    function: timer::EfiTimerNotify,
) -> efi::Status {
    let address = function as usize;
    // A null handler unregisters; r-efi's function-pointer type cannot be null,
    // so a caller that passes one arrives here as address zero.
    if address == 0 {
        if NOTIFY.swap(0, Ordering::AcqRel) == 0 {
            return efi::Status::INVALID_PARAMETER;
        }
        return efi::Status::SUCCESS;
    }
    if NOTIFY
        .compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return efi::Status::ALREADY_STARTED;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn set_timer_period(_this: *mut timer::TimerProtocol, period: u64) -> efi::Status {
    PERIOD.store(period, Ordering::Release);
    if period == 0 {
        disarm();
    } else {
        arm(period);
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn get_timer_period(
    _this: *mut timer::TimerProtocol,
    period: *mut u64,
) -> efi::Status {
    if period.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller passed a writable out-parameter.
    unsafe { period.write_unaligned(PERIOD.load(Ordering::Acquire)) };
    efi::Status::SUCCESS
}

extern "efiapi" fn generate_soft_interrupt(_this: *mut timer::TimerProtocol) -> efi::Status {
    // The core's handler raises the TPL itself, so calling it here is what a
    // software-generated tick is.
    if let Some(notify) = notify() {
        notify(0);
    }
    efi::Status::SUCCESS
}

static mut TIMER: timer::TimerProtocol = timer::TimerProtocol {
    register_handler,
    set_timer_period,
    get_timer_period,
    generate_soft_interrupt,
};

extern "efiapi" fn wait_for_tick(
    this: *const metronome::MetronomeProtocol,
    ticks: u32,
) -> efi::Status {
    // SAFETY: `this` is the protocol instance below.
    let period = if this.is_null() {
        1
    } else {
        unsafe { (*this).tick_period }
    };
    let wait = counter_ticks(ticks as u64 * period as u64);
    let start = counter();
    while counter().wrapping_sub(start) < wait {
        core::hint::spin_loop();
    }
    efi::Status::SUCCESS
}

static mut METRONOME: metronome::MetronomeProtocol = metronome::MetronomeProtocol {
    wait_for_tick,
    tick_period: 1,
};

extern "efiapi" fn watchdog_register(
    _this: *const watchdog::WatchdogProtocol,
    _notify: watchdog::WatchdogTimerNotify,
) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn watchdog_set(
    _this: *const watchdog::WatchdogProtocol,
    period: u64,
) -> efi::Status {
    WATCHDOG_PERIOD.store(period, Ordering::Release);
    efi::Status::SUCCESS
}

extern "efiapi" fn watchdog_get(
    _this: *const watchdog::WatchdogProtocol,
    period: *mut u64,
) -> efi::Status {
    if period.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller passed a writable out-parameter.
    unsafe { period.write_unaligned(WATCHDOG_PERIOD.load(Ordering::Acquire)) };
    efi::Status::SUCCESS
}

static mut WATCHDOG: watchdog::WatchdogProtocol = watchdog::WatchdogProtocol {
    register_handler: watchdog_register,
    set_timer_period: watchdog_set,
    get_timer_period: watchdog_get,
};

/// Installs the timer, metronome and watchdog architectural protocols.
pub struct ArchProtocols;

#[component]
impl ArchProtocols {
    fn entry_point(self, boot_services: StandardBootServices) -> Result<()> {
        // SAFETY: the GUID names the hardware-interrupt protocol, and the layout
        // above is its ABI.
        let interrupts = unsafe {
            boot_services.locate_protocol_unchecked(&HARDWARE_INTERRUPT, core::ptr::null_mut())
        }
        .map_err(|_| EfiError::NotReady)? as *mut HardwareInterrupt;
        INTERRUPTS.store(interrupts, Ordering::Release);

        // Arm before the source is enabled: registering enables it, and the
        // first interrupt then finds a period to re-arm with.
        PERIOD.store(DEFAULT_PERIOD, Ordering::Release);
        arm(DEFAULT_PERIOD);
        // SAFETY: the protocol pointer was just located.
        let status = unsafe {
            ((*interrupts).register_interrupt_source)(
                interrupts,
                TIMER_INTERRUPT,
                Some(timer_interrupt),
            )
        };
        if status != efi::Status::SUCCESS {
            log::error!("timer: registering interrupt {TIMER_INTERRUPT} failed: {status:?}");
            return Err(EfiError::DeviceError);
        }

        // SAFETY: each interface is a static of the structure its GUID names,
        // and it outlives boot services.
        unsafe {
            boot_services.install_protocol_interface_unchecked(
                None,
                &METRONOME_GUID,
                core::ptr::addr_of_mut!(METRONOME) as *mut c_void,
            )?;
            boot_services.install_protocol_interface_unchecked(
                None,
                &WATCHDOG_GUID,
                core::ptr::addr_of_mut!(WATCHDOG) as *mut c_void,
            )?;
            // Last: installing the timer is what makes the core register its
            // tick handler.
            boot_services.install_protocol_interface_unchecked(
                None,
                &TIMER_GUID,
                core::ptr::addr_of_mut!(TIMER) as *mut c_void,
            )?;
        }
        log::info!(
            "timer: EL1 physical timer on interrupt {TIMER_INTERRUPT}, {} Hz counter",
            frequency()
        );
        Ok(())
    }
}
