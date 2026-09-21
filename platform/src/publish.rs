//! Firmware-lifetime ownership for protocol objects.
//!
//! Patina has no driver-unload phase. Once a protocol interface is installed,
//! its address may be retained by the handle database or by another driver, so
//! published objects cannot be reclaimed during boot. Keep that ownership
//! decision in one helper instead of scattering `Box::leak` through drivers.

use alloc::boxed::Box;
use core::ptr::NonNull;

/// Publishes a value with firmware lifetime and returns its stable address.
///
/// The allocation is intentionally not reclaimed: there is no safe unload
/// point before the firmware hands control to the next environment.
pub fn firmware_lifetime<T>(value: T) -> NonNull<T> {
    // SAFETY: the raw allocation remains valid for the entire firmware boot.
    unsafe { NonNull::new_unchecked(Box::into_raw(Box::new(value))) }
}
