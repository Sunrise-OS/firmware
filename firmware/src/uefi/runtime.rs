//! Runtime services: time, variables, reset.
//!
//! Time comes from the machine's PL031 real-time clock, converted from the
//! seconds-since-epoch count it keeps into the calendar fields the specification
//! uses. Reset and shutdown are PSCI calls, because that is the only way this
//! machine has to power off.
//!
//! `SetVirtualAddressMap` is the one service with a real decision in it: this
//! firmware does not relocate itself. If the map an operating system presents is
//! the identity map - virtual equals physical, which is what the firmware's
//! translations already do - the request is satisfied by doing nothing. If it is
//! anything else, the firmware says `EFI_UNSUPPORTED` rather than accepting a map
//! it will not honour, and the runtime-properties table tells the operating
//! system beforehand that no runtime service survives `ExitBootServices`.

use core::ffi::c_void;

use r_efi::base::{Boolean, Char16, Guid, PhysicalAddress, Status};
use r_efi::system::{MemoryDescriptor, RESET_SHUTDOWN, ResetType, Time, TimeCapabilities};

use crate::arch::psci;
use crate::platform;
use crate::uefi::{self, vars};

/// The PL031's registers.
const RTC_DR: usize = 0x00;
const RTC_CDR: usize = 0x04;

/// Reads the RTC's seconds-since-epoch counter, or `None` when the machine has
/// no clock. The epoch is 1970-01-01T00:00:00Z, which is what the PL031 keeps.
fn rtc_seconds() -> Option<u32> {
    if platform::RTC_BASE == 0 {
        return None;
    }
    // SAFETY: the PL031 is mapped as device memory at a known address.
    Some(unsafe { core::ptr::read_volatile((platform::RTC_BASE + RTC_DR) as *const u32) })
}

fn rtc_write(seconds: u32) -> bool {
    if platform::RTC_BASE == 0 {
        return false;
    }
    // SAFETY: as `rtc_seconds`.
    unsafe {
        core::ptr::write_volatile((platform::RTC_BASE + RTC_DR) as *mut u32, seconds);
        // Divide rate 1: the counter ticks in seconds, which is what we read.
        core::ptr::write_volatile((platform::RTC_BASE + RTC_CDR) as *mut u32, 0);
    }
    true
}

/// Converts seconds since the UNIX epoch into calendar fields.
///
/// Uses the civil-days algorithm: count days from 1970-01-01, then walk the
/// 400-year cycle. No table, no month arithmetic that drifts.
fn civil_from_epoch(seconds: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (seconds / 86_400) as i64;
    let second_of_day = (seconds % 86_400) as u32;
    let hour = second_of_day / 3600;
    let minute = (second_of_day % 3600) / 60;
    let second = second_of_day % 60;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    let year = if month <= 2 { year + 1 } else { year };

    (year, month, day, hour, minute, second)
}

/// The inverse of `civil_from_epoch`.
fn epoch_from_civil(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month = month as i64;
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    days as u64 * 86_400 + (hour as u64) * 3600 + minute as u64 * 60 + second as u64
}

pub unsafe extern "efiapi" fn get_time(
    time: *mut Time,
    capabilities: *mut TimeCapabilities,
) -> Status {
    if time.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let seconds = rtc_seconds().unwrap_or(0);
    let (year, month, day, hour, minute, second) = civil_from_epoch(seconds as u64);
    // SAFETY: the out-parameters are writable.
    unsafe {
        *time = Time {
            year: year as u16,
            month: month as u8,
            day: day as u8,
            hour: hour as u8,
            minute: minute as u8,
            second: second as u8,
            pad1: 0,
            nanosecond: 0,
            timezone: r_efi::system::UNSPECIFIED_TIMEZONE as i16,
            daylight: 0,
            pad2: 0,
        };
        if !capabilities.is_null() {
            *capabilities = TimeCapabilities {
                resolution: 1,        // one second, the clock's own granularity
                accuracy: 50_000_000, // fifty parts per million: a crystal's spec
                sets_to_zero: Boolean::FALSE,
            };
        }
    }
    Status::SUCCESS
}

pub unsafe extern "efiapi" fn set_time(time: *mut Time) -> Status {
    if time.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller promises a filled-in Time.
    let value = unsafe { &*time };
    if value.month < 1 || value.month > 12 || value.day < 1 || value.day > 31 {
        return Status::INVALID_PARAMETER;
    }
    let seconds = epoch_from_civil(
        value.year as i64,
        value.month as u32,
        value.day as u32,
        value.hour as u32,
        value.minute as u32,
        value.second as u32,
    );
    if rtc_write(seconds as u32) {
        Status::SUCCESS
    } else {
        Status::UNSUPPORTED
    }
}

pub unsafe extern "efiapi" fn stub_get_wakeup_time(
    _enabled: *mut r_efi::base::Boolean,
    _pending: *mut r_efi::base::Boolean,
    _time: *mut Time,
) -> Status {
    Status::UNSUPPORTED
}

pub unsafe extern "efiapi" fn stub_set_wakeup_time(
    _enable: r_efi::base::Boolean,
    _time: *mut Time,
) -> Status {
    Status::UNSUPPORTED
}

pub unsafe extern "efiapi" fn stub_update_capsule(
    _capsule_header: *mut *mut r_efi::system::CapsuleHeader,
    _count: usize,
    _scatter_gather_list: PhysicalAddress,
) -> Status {
    Status::UNSUPPORTED
}

pub unsafe extern "efiapi" fn stub_query_capsule_capabilities(
    _capsule_header: *mut *mut r_efi::system::CapsuleHeader,
    _count: usize,
    _maximum_capsule_size: *mut u64,
    _reset_type: *mut ResetType,
) -> Status {
    Status::UNSUPPORTED
}

/// `SetVirtualAddressMap`: accept an identity map, refuse any other.
pub unsafe extern "efiapi" fn set_virtual_address_map(
    _memory_map_size: usize,
    _descriptor_size: usize,
    _descriptor_version: u32,
    virtual_map: *mut MemoryDescriptor,
) -> Status {
    if virtual_map.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // The firmware's tables and code are linked where they run and are never
    // relocated, so the only map it can honour is one that leaves every runtime
    // address where it is. Anything else would silently break every pointer in
    // the system table.
    Status::SUCCESS
}

/// `ConvertPointer`: nothing to convert, because nothing moves. Refusing is
/// the honest answer, and the runtime-properties table already says no runtime
/// service survives `ExitBootServices`.
pub unsafe extern "efiapi" fn convert_pointer(
    _debug_disposition: usize,
    _address: *mut *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

pub unsafe extern "efiapi" fn get_variable(
    name: *mut Char16,
    vendor_guid: *mut Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Status {
    if name.is_null() || vendor_guid.is_null() || data_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let name_slice = match cstr16(name) {
        Some(slice) => slice,
        None => return Status::INVALID_PARAMETER,
    };
    // SAFETY: both pointers were checked above.
    let guid = unsafe { &*vendor_guid };
    match vars::get(name_slice, guid) {
        Some((found_attributes, value)) => {
            // SAFETY: the size out-parameter is writable.
            let capacity = unsafe { *data_size };
            // SAFETY: the attributes out-parameter may be null.
            if !attributes.is_null() {
                unsafe { *attributes = found_attributes };
            }
            if data.is_null() || capacity < value.len() {
                unsafe { *data_size = value.len() };
                return Status::BUFFER_TOO_SMALL;
            }
            // SAFETY: the caller's buffer holds `capacity` bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(value.as_ptr(), data as *mut u8, value.len());
                *data_size = value.len();
            }
            Status::SUCCESS
        }
        None => Status::NOT_FOUND,
    }
}

pub unsafe extern "efiapi" fn set_variable(
    name: *mut Char16,
    vendor_guid: *mut Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> Status {
    if name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let name_slice = match cstr16(name) {
        Some(slice) => slice,
        None => return Status::INVALID_PARAMETER,
    };
    if !vars::attributes_are_valid(attributes) && data_size != 0 {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: both pointers were checked above, and the caller promises
    // `data_size` bytes when a value is given.
    let value = if data.is_null() || data_size == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(data as *const u8, data_size) }
    };
    // SAFETY: as above.
    vars::set(name_slice, unsafe { &*vendor_guid }, attributes, value)
}

pub unsafe extern "efiapi" fn get_next_variable_name(
    size: *mut usize,
    name: *mut Char16,
    vendor_guid: *mut Guid,
) -> Status {
    vars::next_name(size, name, vendor_guid)
}

pub unsafe extern "efiapi" fn query_variable_info(
    _attributes: u32,
    max_storage: *mut u64,
    remaining_storage: *mut u64,
    max_variable_size: *mut u64,
) -> Status {
    vars::query_info(max_storage, remaining_storage, max_variable_size)
}

/// `GetNextHighMonotonicCount`: the high half of a 64-bit monotonic counter,
/// which only has to never go backwards.
pub unsafe extern "efiapi" fn get_next_high_monotonic_count(high_count: *mut u32) -> Status {
    if high_count.is_null() {
        return Status::INVALID_PARAMETER;
    }
    static HIGH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
    let value = HIGH.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the out-parameter is writable.
    unsafe { *high_count = value };
    Status::SUCCESS
}

/// `ResetSystem`: shutdown powers the machine off; everything else resets it.
/// This is a `noreturn` service - it does not return on success.
pub unsafe extern "efiapi" fn reset_system(
    reset_type: ResetType,
    _reset_status: Status,
    _data_size: usize,
    _reset_data: *mut c_void,
) {
    if reset_type == RESET_SHUTDOWN {
        psci::system_off();
    } else {
        psci::system_reset();
    }
}

/// Reads a NUL-terminated UTF-16 string into a slice, stopping at the buffer
/// the caller declared.
fn cstr16<'a>(string: *mut Char16) -> Option<&'a [Char16]> {
    if string.is_null() {
        return None;
    }
    for index in 0..(4 * 1024) {
        // SAFETY: the caller promises a NUL-terminated string.
        let unit = unsafe { *string.add(index) };
        if unit == 0 {
            // SAFETY: the string was terminated within the bound.
            return Some(unsafe { core::slice::from_raw_parts(string, index) });
        }
    }
    None
}

/// The system table, for code inside this module that needs it.
fn system_table() -> *mut r_efi::system::SystemTable {
    uefi::system_table()
}
