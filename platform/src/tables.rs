//! Raw access to the tables Patina publishes.
//!
//! Patina's `StandardBootServices` wrapper does not hand out the table pointer,
//! and the architectural-protocol and console drivers below are written the way
//! an EDK2 driver is: against `EFI_BOOT_SERVICES` and `EFI_SYSTEM_TABLE`. The
//! DXE core's own `EFI_LOADED_IMAGE_PROTOCOL` carries the system table, so that
//! is where the platform finds it.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, Ordering},
};

use patina::standard::efi;
use patina::uefi::boot_services::{BootServices, StandardBootServices};

static SYSTEM_TABLE: AtomicPtr<efi::SystemTable> = AtomicPtr::new(core::ptr::null_mut());

/// Finds the system table through the DXE core image's loaded-image protocol,
/// and remembers it for the callbacks that have no component parameters.
pub fn init(
    boot_services: &StandardBootServices,
    core_image: efi::Handle,
) -> Option<*mut efi::SystemTable> {
    let known = SYSTEM_TABLE.load(Ordering::Acquire);
    if !known.is_null() {
        return Some(known);
    }
    // SAFETY: the handle is the DXE core's image handle, which Patina installs
    // the loaded-image protocol on before any component is dispatched.
    let image = unsafe {
        boot_services
            .handle_protocol_unchecked(core_image, &efi::protocols::loaded_image::PROTOCOL_GUID)
    }
    .ok()? as *mut efi::protocols::loaded_image::Protocol;
    // SAFETY: the protocol interface is Patina's image record for the core.
    let table = unsafe { (*image).system_table };
    if table.is_null() {
        return None;
    }
    // SAFETY: a non-null system-table pointer from the core's image record;
    // the header is read to check it really is one.
    let signature = unsafe { (*table).hdr.signature };
    if signature != efi::SYSTEM_TABLE_SIGNATURE {
        log::error!(
            "the DXE core's loaded image names {table:p} as the system table, but its signature is {signature:#x}"
        );
        return None;
    }
    SYSTEM_TABLE.store(table, Ordering::Release);
    Some(table)
}

/// The system table, once `init` has found it.
pub fn system_table() -> *mut efi::SystemTable {
    SYSTEM_TABLE.load(Ordering::Acquire)
}

/// The boot services table, while boot services last.
pub fn boot_services() -> *mut efi::BootServices {
    let table = system_table();
    if table.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the table is Patina's system table; the field is read, not kept.
    unsafe { (*table).boot_services }
}

/// Recomputes the system table's header CRC after a field was changed.
///
/// # Safety
///
/// Boot services must still be available, and `table` must be the system table.
pub unsafe fn rechecksum(table: *mut efi::SystemTable) {
    let services = boot_services();
    if services.is_null() {
        return;
    }
    // SAFETY: the caller passes the live system table; its header describes its
    // extent, and the CRC field is zeroed first as the specification requires.
    unsafe {
        (*table).hdr.crc32 = 0;
        let mut crc = 0u32;
        let status = ((*services).calculate_crc32)(
            table as *mut c_void,
            (*table).hdr.header_size as usize,
            &mut crc,
        );
        if status == efi::Status::SUCCESS {
            (*table).hdr.crc32 = crc;
        }
    }
}
