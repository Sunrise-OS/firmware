//! The UEFI environment: system table, boot services, runtime services, and the
//! configuration tables the operating system reads.
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

use r_efi::base::{Boolean, Char16, Guid, Handle, Status};
use r_efi::protocols::device_path as efi_device_path;
use r_efi::system::{
    BOOT_SERVICES_SIGNATURE, BootServices, RUNTIME_SERVICES_SIGNATURE, RuntimeServices,
    SYSTEM_TABLE_SIGNATURE, SystemTable, TableHeader,
};

pub mod blockio;
pub mod device_path;
pub mod events;
pub mod gop;
pub mod handles;
pub mod initrd;
pub mod mem;
pub mod runtime;
pub mod simplefs;
pub mod text;
pub mod vars;

/// The firmware vendor, as UEFI wants it: UTF-16, NUL-terminated.
pub const VENDOR: &[Char16] = &[
    b'L' as Char16,
    b'i' as Char16,
    b'l' as Char16,
    b'i' as Char16,
    b't' as Char16,
    b'h' as Char16,
    b' ' as Char16,
    b'S' as Char16,
    b'e' as Char16,
    b'm' as Char16,
    b'i' as Char16,
    b' ' as Char16,
    b'W' as Char16,
    b'e' as Char16,
    b'i' as Char16,
    b'r' as Char16,
    0,
];

/// The revision the tables claim: UEFI 2.70.
pub const REVISION: u32 = r_efi::system::SYSTEM_TABLE_REVISION_2_70;

pub const LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x5b1b31a1,
    0x9562,
    0x11d2,
    0x8e,
    0x3f,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
pub const DEVICE_PATH_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x09576e91,
    0x6d3f,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
pub const SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x964e5b22,
    0x6459,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
pub const BLOCK_IO_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x964e5b21,
    0x6459,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
pub const GRAPHICS_OUTPUT_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x9042a9de,
    0x23dc,
    0x4a38,
    0x96,
    0xfb,
    &[0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
);
pub const LOAD_FILE2_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x4006c0c1,
    0xfcb3,
    0x403e,
    0x99,
    0x6d,
    &[0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d],
);
/// The configuration-table GUID for the device tree.
pub const DEVICE_TREE_GUID: Guid = Guid::from_fields(
    0xb1b621d5,
    0xf19c,
    0x41a5,
    0x83,
    0x0b,
    &[0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0],
);
/// The ACPI 2.0+ RSDP configuration-table GUID.
pub const ACPI_20_TABLE_GUID: Guid = Guid::from_fields(
    0x8868e871,
    0xe4f1,
    0x11d3,
    0xbc,
    0x22,
    &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);
/// The SMBIOS entry-point configuration-table GUID (3.x).
pub const SMBIOS_TABLE_GUID: Guid = Guid::from_fields(
    0xf2fd1544,
    0x9794,
    0x4a2c,
    0x99,
    0x2e,
    &[0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94],
);
/// The EFI runtime-properties table: which runtime services survive
/// `ExitBootServices`.
pub const RT_PROPERTIES_TABLE_GUID: Guid = Guid::from_fields(
    0xeb66918a,
    0x7eef,
    0x402a,
    0x84,
    0x2e,
    &[0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9],
);

/// The EFI runtime-properties table, describing what an operating system may
/// still call once boot services have ended.
#[repr(C)]
struct RtPropertiesTable {
    version: u16,
    length: u16,
    runtime_services_supported: u32,
}

/// The tables. All of them are program-lifetime state, filled in once by `init`.
static mut IMAGE_HANDLE: MaybeUninit<Handle> = MaybeUninit::uninit();
static mut SYSTEM_TABLE: MaybeUninit<SystemTable> = MaybeUninit::uninit();
static mut BOOT_SERVICES: MaybeUninit<BootServices> = MaybeUninit::uninit();
static mut RUNTIME_SERVICES: MaybeUninit<RuntimeServices> = MaybeUninit::uninit();
static mut RT_PROPERTIES: MaybeUninit<RtPropertiesTable> = MaybeUninit::uninit();

/// Set once `init` has finished, so callers can assert rather than read
/// uninitialised memory.
static INITIALIZED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The system table, valid once `init` has run.
pub fn system_table() -> *mut SystemTable {
    assert!(
        INITIALIZED.load(Ordering::Acquire),
        "uefi: the system table has not been built yet"
    );
    // SAFETY: `init` wrote the table before setting INITIALIZED, and the table
    // is never moved or freed.
    unsafe { core::ptr::addr_of_mut!(SYSTEM_TABLE) as *mut SystemTable }
}

/// The firmware's own image handle.
pub fn image_handle() -> Handle {
    assert!(
        INITIALIZED.load(Ordering::Acquire),
        "uefi: the system table has not been built yet"
    );
    // SAFETY: `init` wrote the handle before setting INITIALIZED.
    unsafe { (*core::ptr::addr_of!(IMAGE_HANDLE)).assume_init() }
}

/// The boot services table, for code that would rather not reach through the
/// system table.
pub fn boot_services() -> *mut BootServices {
    assert!(INITIALIZED.load(Ordering::Acquire), "uefi: not initialised");
    // SAFETY: as `system_table`.
    unsafe { core::ptr::addr_of_mut!(BOOT_SERVICES) as *mut BootServices }
}

/// Builds the `EFI_SYSTEM_TABLE`.
///
/// `boot_args` is the machine description from the boot protocol, if the boot
/// stage passed one; a tree is published in the configuration table so the
/// operating system can read the machine's own description.
pub fn init(boot_args: usize) -> *mut SystemTable {
    // The console protocols and the configuration-table array are their own
    // statics; this module owns only the three tables.
    events::init();
    vars::init();
    crate::boot::manager::init();
    blockio::init();
    simplefs::init();
    handles::init();
    text::init();

    let image_handle = handles::create_handle();
    // SAFETY: single-threaded bring-up; written before INITIALIZED is set.
    unsafe {
        (*core::ptr::addr_of_mut!(IMAGE_HANDLE)).write(image_handle);
    }

    build_boot_services();
    build_runtime_services();

    // SAFETY: BOOT_SERVICES and RUNTIME_SERVICES were built above, and the
    // system table outlives them.
    unsafe {
        (*core::ptr::addr_of_mut!(SYSTEM_TABLE)).write(SystemTable {
            hdr: header(SYSTEM_TABLE_SIGNATURE, core::mem::size_of::<SystemTable>()),
            firmware_vendor: VENDOR.as_ptr() as *mut Char16,
            firmware_revision: 0x0001_0001,
            console_in_handle: image_handle,
            con_in: text::input_protocol_ptr(),
            console_out_handle: image_handle,
            con_out: text::output_protocol_ptr(),
            standard_error_handle: image_handle,
            std_err: text::output_protocol_ptr(),
            runtime_services: core::ptr::addr_of_mut!(RUNTIME_SERVICES) as *mut RuntimeServices,
            boot_services: core::ptr::addr_of_mut!(BOOT_SERVICES) as *mut BootServices,
            number_of_table_entries: 0,
            configuration_table: handles::configuration_table_storage(),
        });
    }

    INITIALIZED.store(true, Ordering::Release);

    let table = system_table();
    install_rt_properties();
    if boot_args != 0 {
        install_config_table(&DEVICE_TREE_GUID, boot_args as *const c_void);
    }

    // SAFETY: every table is built; its CRC has never been computed.
    unsafe {
        recompute_crc(boot_services());
        recompute_crc(core::ptr::addr_of_mut!(RUNTIME_SERVICES) as *mut RuntimeServices);
        recompute_crc(table);
    }
    table
}

fn header(signature: u64, size: usize) -> TableHeader {
    TableHeader {
        signature,
        revision: REVISION,
        header_size: size as u32,
        crc32: 0,
        reserved: 0,
    }
}

/// Publishes a table in the system table's configuration list. Replaces an
/// entry with the same GUID; `OUT_OF_RESOURCES` when the list is full.
pub fn install_config_table(guid: &Guid, table: *const c_void) -> Status {
    let system = system_table();
    // SAFETY: `system` is the table this firmware built and never moves.
    unsafe {
        let entries = (*system).configuration_table;
        let count = (*system).number_of_table_entries;
        for index in 0..count {
            if &(*entries.add(index)).vendor_guid == guid {
                (*entries.add(index)).vendor_table = table as *mut c_void;
                recompute_crc(system);
                return Status::SUCCESS;
            }
        }
        if count >= handles::MAX_CONFIG_TABLES {
            return Status::OUT_OF_RESOURCES;
        }
        (*entries.add(count)).vendor_guid = *guid;
        (*entries.add(count)).vendor_table = table as *mut c_void;
        (*system).number_of_table_entries = count + 1;
        recompute_crc(system);
        Status::SUCCESS
    }
}

/// Publishes the runtime-properties table: which runtime services an operating
/// system may still call after `ExitBootServices`.
fn install_rt_properties() {
    const RUNTIME_GET_TIME: u32 = 1 << 0;
    const RUNTIME_SET_TIME: u32 = 1 << 1;
    const RUNTIME_GET_VARIABLE: u32 = 1 << 4;
    const RUNTIME_SET_VARIABLE: u32 = 1 << 5;
    const RUNTIME_RESET_SYSTEM: u32 = 1 << 10;

    // SAFETY: written once during bring-up.
    let table = unsafe {
        (*core::ptr::addr_of_mut!(RT_PROPERTIES)).write(RtPropertiesTable {
            version: 1,
            length: 8,
            runtime_services_supported: RUNTIME_GET_TIME
                | RUNTIME_SET_TIME
                | RUNTIME_GET_VARIABLE
                | RUNTIME_SET_VARIABLE
                | RUNTIME_RESET_SYSTEM,
        });
        core::ptr::addr_of!(RT_PROPERTIES) as *const RtPropertiesTable
    };
    install_config_table(&RT_PROPERTIES_TABLE_GUID, table as *const c_void);
}

/// Fills in the boot services table.
///
/// Every entry is assigned: a real implementation for what this firmware does,
/// a stub returning `EFI_UNSUPPORTED` for the rest. Listing them all in the
/// literal is what makes the compiler check each one against the
/// specification's signature, so a stub with the wrong argument list cannot
/// slip in.
fn build_boot_services() {
    use events as e;
    use handles as h;
    use mem::*;

    // SAFETY: written once during bring-up, before the table is published.
    unsafe {
        (*core::ptr::addr_of_mut!(BOOT_SERVICES)).write(BootServices {
            hdr: header(
                BOOT_SERVICES_SIGNATURE,
                core::mem::size_of::<BootServices>(),
            ),
            raise_tpl: e::raise_tpl,
            restore_tpl: e::restore_tpl,
            allocate_pages: allocate_pages,
            free_pages: free_pages,
            get_memory_map: get_memory_map,
            allocate_pool: allocate_pool,
            free_pool: free_pool,
            create_event: e::create_event,
            set_timer: e::set_timer,
            wait_for_event: e::wait_for_event,
            signal_event: e::signal_event,
            close_event: e::close_event,
            check_event: e::check_event,
            install_protocol_interface: h::install_protocol_interface,
            reinstall_protocol_interface: h::reinstall_protocol_interface,
            uninstall_protocol_interface: h::uninstall_protocol_interface,
            handle_protocol: h::handle_protocol,
            reserved: core::ptr::null_mut(),
            register_protocol_notify: h::register_protocol_notify,
            locate_handle: h::locate_handle,
            locate_device_path: h::locate_device_path,
            install_configuration_table: install_configuration_table_service,
            load_image: crate::boot::load_image,
            start_image: crate::boot::start_image,
            exit: exit,
            unload_image: crate::boot::unload_image,
            exit_boot_services: exit_boot_services,
            get_next_monotonic_count: get_next_monotonic_count,
            stall: stall,
            set_watchdog_timer: set_watchdog_timer,
            connect_controller: stub_connect_controller,
            disconnect_controller: stub_disconnect_controller,
            open_protocol: h::open_protocol,
            close_protocol: h::close_protocol,
            open_protocol_information: h::open_protocol_information,
            protocols_per_handle: h::protocols_per_handle,
            locate_handle_buffer: h::locate_handle_buffer,
            locate_protocol: h::locate_protocol,
            install_multiple_protocol_interfaces: stub_install_multiple,
            uninstall_multiple_protocol_interfaces: stub_uninstall_multiple,
            calculate_crc32: calculate_crc32,
            copy_mem: copy_mem,
            set_mem: set_mem,
            create_event_ex: e::create_event_ex,
        });
    }
}

/// Fills in the runtime services table.
fn build_runtime_services() {
    // SAFETY: written once during bring-up, before the table is published.
    unsafe {
        (*core::ptr::addr_of_mut!(RUNTIME_SERVICES)).write(RuntimeServices {
            hdr: header(
                RUNTIME_SERVICES_SIGNATURE,
                core::mem::size_of::<RuntimeServices>(),
            ),
            get_time: runtime::get_time,
            set_time: runtime::set_time,
            get_wakeup_time: runtime::stub_get_wakeup_time,
            set_wakeup_time: runtime::stub_set_wakeup_time,
            set_virtual_address_map: runtime::set_virtual_address_map,
            convert_pointer: runtime::convert_pointer,
            get_variable: runtime::get_variable,
            get_next_variable_name: runtime::get_next_variable_name,
            set_variable: runtime::set_variable,
            get_next_high_mono_count: runtime::get_next_high_monotonic_count,
            reset_system: runtime::reset_system,
            update_capsule: runtime::stub_update_capsule,
            query_capsule_capabilities: runtime::stub_query_capsule_capabilities,
            query_variable_info: runtime::query_variable_info,
        });
    }
}

/// `InstallConfigurationTable`, the service half of `install_config_table`.
unsafe extern "efiapi" fn install_configuration_table_service(
    guid: *mut Guid,
    table: *mut c_void,
) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller promises `guid` points at a GUID.
    unsafe { install_config_table(&*guid, table as *const c_void) }
}

/// `Exit`: the image is done, and with nothing to fall back to, the machine
/// stops.
unsafe extern "efiapi" fn exit(
    _handle: Handle,
    status: Status,
    _size: usize,
    _text: *mut Char16,
) -> Status {
    let _ = status;
    crate::arch::psci::system_off();
    Status::SUCCESS
}

/// `ExitBootServices`: boot services stop here. This firmware's tables are all
/// in static memory and the allocator keeps working for the operating system's
/// own use, so the only thing left to do is validate the map key - an
/// application that hands a stale key has an inconsistent view of the map, and
/// the specification says to fail rather than guess.
unsafe extern "efiapi" fn exit_boot_services(_image: Handle, map_key: usize) -> Status {
    if !mem::check_map_key(map_key) {
        return Status::INVALID_PARAMETER;
    }
    // Every event registered for the exit-boot-services group runs now, while
    // boot services still work: that is the last moment they can.
    events::signal_group(&events::EVENT_GROUP_EXIT_BOOT_SERVICES);
    mem::set_boot_services_ended();
    Status::SUCCESS
}

/// CRC-32 as UEFI and GPT use it: reflected polynomial 0xEDB88320.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut value = 0xffff_ffffu32;
    for byte in bytes {
        value ^= *byte as u32;
        for _ in 0..8 {
            let mask = (value & 1).wrapping_neg();
            value = (value >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !value
}

/// `CalculateCrc32`: the CRC-32 the specification uses - reflected polynomial
/// 0xEDB88320, the same one table headers carry.
unsafe extern "efiapi" fn calculate_crc32(data: *mut c_void, size: usize, crc: *mut u32) -> Status {
    if crc.is_null() || (size > 0 && data.is_null()) {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller guarantees `data` holds `size` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data as *const u8, size) };
    // SAFETY: the caller gave a writable out-parameter.
    unsafe { *crc = crc32(bytes) };
    Status::SUCCESS
}

/// `CopyMem`: overlapping-safe byte copy, as the specification requires.
unsafe extern "efiapi" fn copy_mem(destination: *mut c_void, source: *mut c_void, size: usize) {
    // SAFETY: the caller guarantees both regions hold `size` bytes.
    unsafe {
        core::ptr::copy(source as *const u8, destination as *mut u8, size);
    }
}

/// `SetMem`.
unsafe extern "efiapi" fn set_mem(buffer: *mut c_void, size: usize, value: u8) {
    // SAFETY: the caller guarantees the buffer holds `size` bytes.
    unsafe { core::ptr::write_bytes(buffer as *mut u8, value, size) }
}

/// `Stall`: busy-waits the given number of microseconds.
unsafe extern "efiapi" fn stall(microseconds: usize) -> Status {
    crate::arch::timer::stall_microseconds(microseconds as u64);
    Status::SUCCESS
}

/// `SetWatchdogTimer`: this firmware has no watchdog. Accept the request so an
/// application that arms one does not treat it as an error.
unsafe extern "efiapi" fn set_watchdog_timer(
    _timeout: usize,
    _watchdog_code: u64,
    _data_size: usize,
    _watchdog_data: *mut Char16,
) -> Status {
    Status::SUCCESS
}

/// `GetNextMonotonicCount`: a counter that only ever goes up, which an
/// increment satisfies.
unsafe extern "efiapi" fn get_next_monotonic_count(count: *mut u64) -> Status {
    if count.is_null() {
        return Status::INVALID_PARAMETER;
    }
    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    let value = NEXT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the out-parameter is writable.
    unsafe { *count = value };
    Status::SUCCESS
}

// Stubs for services this firmware does not implement. Each returns
// `EFI_UNSUPPORTED`, which is what a complete implementation returns for a
// service it has not provided - the alternative, leaving the entry unset, would
// send an application into invalid memory.

unsafe extern "efiapi" fn stub_connect_controller(
    _handle: Handle,
    _driver_image: *mut Handle,
    _remaining_device_path: *mut efi_device_path::Protocol,
    _recursive: Boolean,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn stub_disconnect_controller(
    _handle: Handle,
    _driver_image: Handle,
    _child: Handle,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn stub_install_multiple(
    _handle: *mut *mut c_void,
    _first: *mut c_void,
    _second: *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn stub_uninstall_multiple(
    _handle: *mut c_void,
    _first: *mut c_void,
    _second: *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

/// Recomputes a table's CRC-32 over its whole extent, header included, with the
/// field zeroed first as the specification requires.
///
/// # Safety
///
/// `table` must point at a table whose `header_size` describes its extent.
pub(crate) unsafe fn recompute_crc<T>(table: *mut T) {
    // SAFETY: the caller passes a real table.
    unsafe {
        let header = table as *mut TableHeader;
        (*header).crc32 = 0;
        let mut crc = 0u32;
        let status = calculate_crc32(
            table as *mut c_void,
            (*header).header_size as usize,
            &mut crc as *mut u32,
        );
        if status == Status::SUCCESS {
            (*header).crc32 = crc;
        }
    }
}
