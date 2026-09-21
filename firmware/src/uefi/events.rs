//! Events, timers, and task priority levels.
//!
//! Timers are polled: an event's deadline is compared against the system
//! counter whenever something asks whether it is ready, which is what
//! `WaitForEvent` does in a loop anyway. That keeps the interrupt path out of
//! the event machinery - the GIC and the timer interrupt are there for the
//! firmware's own periodic work, not for dispatching notifications.
//!
//! Notifications run synchronously, at whatever priority the signaler is at,
//! which is the behaviour an application sees from `SignalEvent`.

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use r_efi::base::{Event, Guid, Status, Tpl};
use r_efi::system::{EventNotify, TIMER_CANCEL, TIMER_PERIODIC, TIMER_RELATIVE};

use crate::arch::timer;

const MAX_EVENTS: usize = 32;

pub const EVT_TIMER: u32 = 0x8000_0000;
pub const EVT_RUNTIME: u32 = 0x4000_0000;
pub const EVT_NOTIFY_WAIT: u32 = 0x0000_0100;
pub const EVT_NOTIFY_SIGNAL: u32 = 0x0000_0200;
pub const EVT_SIGNAL_EXIT_BOOT_SERVICES: u32 = 0x0000_0201;
pub const EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE: u32 = 0x6000_0202;

/// The group an event may register for that fires when boot services end.
pub const EVENT_GROUP_EXIT_BOOT_SERVICES: Guid = r_efi::system::EVENT_GROUP_EXIT_BOOT_SERVICES;

pub const TPL_APPLICATION: Tpl = 4;
pub const TPL_CALLBACK: Tpl = 8;
pub const TPL_NOTIFY: Tpl = 16;
pub const TPL_HIGH_LEVEL: Tpl = 31;

/// Units of the specification's timer: 100 nanoseconds.
const HUNDRED_NS: u64 = 100;

struct EventEntry {
    used: bool,
    event_type: u32,
    notify: Option<EventNotify>,
    context: *mut c_void,
    group: Option<Guid>,
    signaled: bool,
    /// A predicate that decides readiness for events the firmware polls rather
    /// than signals - console input, principally.
    readiness: Option<fn() -> bool>,
    timer_mode: u32,
    /// Deadline and period, in 100 ns units since the counter started.
    deadline: u64,
    period: u64,
}

const EMPTY: EventEntry = EventEntry {
    used: false,
    event_type: 0,
    notify: None,
    context: core::ptr::null_mut(),
    group: None,
    signaled: false,
    readiness: None,
    timer_mode: TIMER_CANCEL,
    deadline: 0,
    period: 0,
};

static mut EVENTS: MaybeUninit<[EventEntry; MAX_EVENTS]> = MaybeUninit::uninit();
static EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);
/// The current task priority level. Raised and restored by the application;
/// notifications are dispatched immediately, so this is bookkeeping rather than
/// a queue.
static CURRENT_TPL: AtomicUsize = AtomicUsize::new(TPL_APPLICATION as usize);

/// Prepares the event pool. Called once from `init`.
pub fn init() {
    // SAFETY: single-threaded bring-up; nothing has read the pool yet.
    unsafe { (*core::ptr::addr_of_mut!(EVENTS)).write([EMPTY; MAX_EVENTS]) };
}

/// The pool's entry for an event handle, if the handle is one of ours.
fn entry_of(event: Event) -> Option<&'static mut EventEntry> {
    if event.is_null() {
        return None;
    }
    let base = core::ptr::addr_of!(EVENTS) as usize;
    let end = base + core::mem::size_of::<[EventEntry; MAX_EVENTS]>();
    let address = event as usize;
    if address < base || address >= end {
        return None;
    }
    let index = (address - base) / core::mem::size_of::<EventEntry>();
    if index >= EVENT_COUNT.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: bounds checked against the static pool and the live count.
    let entry = unsafe { &mut *((core::ptr::addr_of_mut!(EVENTS)) as *mut EventEntry).add(index) };
    entry.used.then_some(entry)
}

/// The handle for a newly created event, with `event_type` and its
/// notification pair already set.
fn create(
    event_type: u32,
    notify_tpl: Tpl,
    notify: Option<EventNotify>,
    context: *mut c_void,
    group: Option<Guid>,
) -> Option<Event> {
    let _ = notify_tpl;
    let index = EVENT_COUNT.load(Ordering::Acquire);
    if index >= MAX_EVENTS {
        return None;
    }
    // SAFETY: single-threaded; the slot is ours.
    unsafe {
        let pool = core::ptr::addr_of_mut!(EVENTS) as *mut [EventEntry; MAX_EVENTS];
        (*pool)[index] = EventEntry {
            used: true,
            event_type,
            notify,
            context,
            group,
            signaled: false,
            readiness: None,
            timer_mode: TIMER_CANCEL,
            deadline: 0,
            period: 0,
        };
    }
    EVENT_COUNT.store(index + 1, Ordering::Release);
    // SAFETY: the slot is in the pool and now used.
    Some(unsafe { (core::ptr::addr_of!(EVENTS) as *const EventEntry).add(index) as Event })
}

/// Creates an event whose readiness is decided by polling `ready`, which is how
/// console input is exposed as an event without an interrupt path.
pub fn create_polled(readiness: fn() -> bool) -> Option<Event> {
    let event = create(
        EVT_NOTIFY_WAIT,
        TPL_CALLBACK,
        None,
        core::ptr::null_mut(),
        None,
    )?;
    // SAFETY: the handle came from `create`.
    if let Some(entry) = entry_of(event) {
        entry.readiness = Some(readiness);
    }
    Some(event)
}

/// Whether an event is ready: signaled, or its predicate says so, or its
/// deadline has passed.
fn is_ready(entry: &EventEntry) -> bool {
    if entry.signaled {
        return true;
    }
    if let Some(ready) = entry.readiness {
        if ready() {
            return true;
        }
    }
    if entry.event_type & EVT_TIMER != 0 && entry.timer_mode != TIMER_CANCEL {
        let now = timer::now_100ns();
        if now >= entry.deadline {
            return true;
        }
    }
    false
}

/// Consumes an event's signaled state, advancing a periodic timer's deadline.
fn consume(entry: &mut EventEntry) {
    entry.signaled = false;
    if entry.event_type & EVT_TIMER != 0 {
        match entry.timer_mode {
            TIMER_PERIODIC => entry.deadline += entry.period,
            TIMER_RELATIVE => entry.timer_mode = TIMER_CANCEL,
            _ => {}
        }
    }
}

/// Runs an event's notification function, if it has one.
fn notify(entry: &mut EventEntry) {
    if let Some(callback) = entry.notify {
        // SAFETY: the notification function and context came from the
        // application that created the event, and are valid for its lifetime.
        unsafe { callback(this_handle(entry), entry.context) };
    }
}

/// The handle for an entry, from its address in the pool.
fn this_handle(entry: &EventEntry) -> Event {
    entry as *const EventEntry as Event
}

/// Signals every event registered for `group`, running its notification.
///
/// Used at `ExitBootServices`, where the group's events are the last thing that
/// can still use boot services.
pub fn signal_group(group: &Guid) {
    let count = EVENT_COUNT.load(Ordering::Acquire);
    // SAFETY: single-threaded boot services; bounds checked against the live count.
    unsafe {
        let pool = (core::ptr::addr_of_mut!(EVENTS)).cast::<EventEntry>();
        for index in 0..count {
            let entry = pool.add(index);
            if (*entry).used && (*entry).group.as_ref() == Some(group) {
                (*entry).signaled = true;
                notify(&mut *entry);
            }
        }
    }
}

pub unsafe extern "efiapi" fn raise_tpl(new_tpl: Tpl) -> Tpl {
    let current = CURRENT_TPL.load(Ordering::Acquire);
    CURRENT_TPL.store(new_tpl as usize, Ordering::Release);
    current as Tpl
}

pub unsafe extern "efiapi" fn restore_tpl(new_tpl: Tpl) {
    CURRENT_TPL.store(new_tpl as usize, Ordering::Release);
}

pub unsafe extern "efiapi" fn create_event(
    event_type: u32,
    notify_tpl: Tpl,
    notify: Option<EventNotify>,
    context: *mut c_void,
    event: *mut Event,
) -> Status {
    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if event_type & EVT_TIMER == 0 && notify.is_none() && event_type & EVT_NOTIFY_WAIT == 0 {
        return Status::INVALID_PARAMETER;
    }
    match create(event_type, notify_tpl, notify, context, None) {
        Some(created) => {
            // SAFETY: the out-parameter is writable.
            unsafe { *event = created };
            Status::SUCCESS
        }
        None => Status::OUT_OF_RESOURCES,
    }
}

pub unsafe extern "efiapi" fn create_event_ex(
    event_type: u32,
    notify_tpl: Tpl,
    notify: Option<EventNotify>,
    context: *const c_void,
    group: *const Guid,
    event: *mut Event,
) -> Status {
    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller promises `group` is a GUID when the type needs one.
    let guid = unsafe { group.as_ref().copied() };
    match create(event_type, notify_tpl, notify, context as *mut c_void, guid) {
        Some(created) => {
            // SAFETY: the out-parameter is writable.
            unsafe { *event = created };
            Status::SUCCESS
        }
        None => Status::OUT_OF_RESOURCES,
    }
}

pub unsafe extern "efiapi" fn set_timer(
    event: Event,
    timer_type: u32,
    trigger_time: u64,
) -> Status {
    let entry = match entry_of(event) {
        Some(entry) => entry,
        None => return Status::INVALID_PARAMETER,
    };
    if entry.event_type & EVT_TIMER == 0 {
        return Status::INVALID_PARAMETER;
    }
    match timer_type {
        TIMER_CANCEL => {
            entry.timer_mode = TIMER_CANCEL;
            Status::SUCCESS
        }
        TIMER_PERIODIC | TIMER_RELATIVE => {
            let period = trigger_time;
            let now = timer::now_100ns();
            entry.timer_mode = timer_type;
            entry.period = period;
            entry.deadline = match timer_type {
                TIMER_PERIODIC => now + period.max(HUNDRED_NS),
                _ => now + period,
            };
            Status::SUCCESS
        }
        _ => Status::INVALID_PARAMETER,
    }
}

pub unsafe extern "efiapi" fn signal_event(event: Event) -> Status {
    let entry = match entry_of(event) {
        Some(entry) => entry,
        None => return Status::INVALID_PARAMETER,
    };
    entry.signaled = true;
    notify(entry);
    Status::SUCCESS
}

pub unsafe extern "efiapi" fn close_event(event: Event) -> Status {
    let entry = match entry_of(event) {
        Some(entry) => entry,
        None => return Status::INVALID_PARAMETER,
    };
    entry.used = false;
    entry.notify = None;
    Status::SUCCESS
}

pub unsafe extern "efiapi" fn check_event(event: Event) -> Status {
    let entry = match entry_of(event) {
        Some(entry) => entry,
        None => return Status::INVALID_PARAMETER,
    };
    if is_ready(entry) {
        consume(entry);
        Status::SUCCESS
    } else {
        Status::NOT_READY
    }
}

pub unsafe extern "efiapi" fn wait_for_event(
    number_of_events: usize,
    event: *mut Event,
    index: *mut usize,
) -> Status {
    if event.is_null() || index.is_null() || number_of_events == 0 {
        return Status::INVALID_PARAMETER;
    }
    // A single CPU: an event array with entries this firmware does not know is
    // an application error, and the specification asks for the first bad index.
    for position in 0..number_of_events {
        // SAFETY: the caller's array holds `number_of_events` handles.
        if unsafe { *event.add(position) }.is_null() {
            // SAFETY: the out-parameter is writable.
            unsafe { *index = position };
            return Status::INVALID_PARAMETER;
        }
    }

    loop {
        for position in 0..number_of_events {
            // SAFETY: bounds checked in the loop above.
            let handle = unsafe { *event.add(position) };
            if let Some(entry) = entry_of(handle) {
                if is_ready(entry) {
                    consume(entry);
                    notify(entry);
                    // SAFETY: the out-parameter is writable.
                    unsafe { *index = position };
                    return Status::SUCCESS;
                }
            } else {
                // SAFETY: the out-parameter is writable.
                unsafe { *index = position };
                return Status::INVALID_PARAMETER;
            }
        }
        core::hint::spin_loop();
    }
}

/// The event pool's capacity, for the boot log.
pub fn live_events() -> usize {
    EVENT_COUNT.load(Ordering::Acquire)
}
