//! The handle database and the protocol services.
//!
//! A handle is an opaque pointer that owns zero or more protocol interfaces,
//! each keyed by a GUID. The database is a static array: handles are addresses
//! inside it, which makes `EFI_HANDLE` a non-null pointer with meaning, and
//! makes validation (`is this handle ours?`) a bounds and state check rather
//! than a guess.

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use r_efi::base::{Event, Guid, Handle, Status};
use r_efi::protocols::device_path;
use r_efi::system::{ConfigurationTable, LocateSearchType, OPEN_PROTOCOL_BY_HANDLE_PROTOCOL};

use crate::uefi;

/// How many handles exist. More than a boot loader's worth: the disk, each
/// partition, the filesystem, the console, and the image.
pub const MAX_HANDLES: usize = 64;
/// How many protocols a single handle may carry.
pub const MAX_PROTOCOLS: usize = 8;
/// How many configuration tables the system table can publish.
pub const MAX_CONFIG_TABLES: usize = 16;
/// How many `OpenProtocol` calls may be outstanding on one protocol.
const MAX_OPENS: usize = 8;

#[derive(Clone, Copy)]
struct Open {
    agent: Handle,
    controller: Handle,
    attributes: u32,
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    protocols: [(Guid, *mut c_void); MAX_PROTOCOLS],
    opens: [Open; MAX_OPENS],
    protocol_count: usize,
    open_count: usize,
}

const EMPTY_SLOT: Slot = Slot {
    used: false,
    protocols: [(
        Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
        core::ptr::null_mut(),
    ); MAX_PROTOCOLS],
    opens: [Open {
        agent: core::ptr::null_mut(),
        controller: core::ptr::null_mut(),
        attributes: 0,
    }; MAX_OPENS],
    protocol_count: 0,
    open_count: 0,
};

static mut SLOTS: MaybeUninit<[Slot; MAX_HANDLES]> = MaybeUninit::uninit();
static mut CONFIG_TABLES: MaybeUninit<[ConfigurationTable; MAX_CONFIG_TABLES]> =
    MaybeUninit::uninit();
static SLOT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Prepares the database and the configuration-table array. Called once from
/// `init`, before anything else touches them.
pub fn init() {
    // SAFETY: single-threaded bring-up; nothing has read these yet.
    unsafe {
        (*core::ptr::addr_of_mut!(SLOTS)).write([EMPTY_SLOT; MAX_HANDLES]);
        (*core::ptr::addr_of_mut!(CONFIG_TABLES)).write(
            [ConfigurationTable {
                vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
                vendor_table: core::ptr::null_mut(),
            }; MAX_CONFIG_TABLES],
        );
    }
}

/// The system table's configuration-table array.
pub fn configuration_table_storage() -> *mut ConfigurationTable {
    // SAFETY: `init` ran; the array is static.
    unsafe { core::ptr::addr_of_mut!(CONFIG_TABLES) as *mut ConfigurationTable }
}

/// Allocates a fresh, empty handle.
pub fn create_handle() -> Handle {
    let count = SLOT_COUNT.load(Ordering::Acquire);
    assert!(count < MAX_HANDLES, "uefi: out of handles");
    // SAFETY: single-threaded boot services; the slot is ours to fill.
    unsafe {
        let slots = core::ptr::addr_of_mut!(SLOTS) as *mut [Slot; MAX_HANDLES];
        (*slots)[count] = EMPTY_SLOT;
        (*slots)[count].used = true;
    }
    SLOT_COUNT.store(count + 1, Ordering::Release);
    // SAFETY: the slot is in the static array and now used.
    unsafe {
        let slots = core::ptr::addr_of!(SLOTS) as *const [Slot; MAX_HANDLES];
        (slots as *const Slot).add(count) as Handle
    }
}

/// Whether `handle` is one this database handed out.
fn slot_of(handle: Handle) -> Option<&'static mut Slot> {
    if handle.is_null() {
        return None;
    }
    let base = core::ptr::addr_of!(SLOTS) as usize;
    let end = base + core::mem::size_of::<[Slot; MAX_HANDLES]>();
    let address = handle as usize;
    if address < base || address >= end {
        return None;
    }
    let index = (address - base) / core::mem::size_of::<Slot>();
    let count = SLOT_COUNT.load(Ordering::Acquire);
    if index >= count {
        return None;
    }
    // SAFETY: the address was checked against the static array and the live
    // count, and boot services are single-threaded.
    let slot = unsafe { &mut *((core::ptr::addr_of_mut!(SLOTS)) as *mut Slot).add(index) };
    slot.used.then_some(slot)
}

/// The index of a handle, for iteration.
fn index_of(handle: Handle) -> Option<usize> {
    let base = core::ptr::addr_of!(SLOTS) as usize;
    let address = handle as usize;
    if address < base {
        return None;
    }
    let index = (address - base) / core::mem::size_of::<Slot>();
    (slot_of(handle).is_some()).then_some(index)
}

/// Finds the first protocol slot on a handle matching `guid`.
fn find_protocol_index(slot: &Slot, guid: &Guid) -> Option<usize> {
    (0..slot.protocol_count).find(|&index| slot.protocols[index].0 == *guid)
}

/// Creates a handle with one protocol on it, and returns it.
pub fn install_new(guid: &Guid, interface: *mut c_void) -> Handle {
    let handle = create_handle();
    let status = unsafe { install_on(handle, guid, interface) };
    assert!(status == Status::SUCCESS, "uefi: protocol install failed");
    handle
}

/// Installs `interface` on `handle`, creating the handle when it is null.
///
/// # Safety
///
/// `interface` must point at a structure of the kind `guid` names, and must
/// outlive the handle.
pub unsafe fn install_on(handle: Handle, guid: &Guid, interface: *mut c_void) -> Status {
    let handle = if handle.is_null() {
        create_handle()
    } else {
        handle
    };
    let slot = match slot_of(handle) {
        Some(slot) => slot,
        None => return Status::INVALID_PARAMETER,
    };
    if find_protocol_index(slot, guid).is_some() {
        return Status::INVALID_PARAMETER;
    }
    if slot.protocol_count >= MAX_PROTOCOLS {
        return Status::OUT_OF_RESOURCES;
    }
    slot.protocols[slot.protocol_count] = (*guid, interface);
    slot.protocol_count += 1;
    Status::SUCCESS
}

/// The interface for `guid` on `handle`, if it is installed.
pub fn interface_on(handle: Handle, guid: &Guid) -> Option<*mut c_void> {
    let slot = slot_of(handle)?;
    let index = find_protocol_index(slot, guid)?;
    Some(slot.protocols[index].1)
}

/// The first handle carrying `guid`.
pub fn handle_with(guid: &Guid) -> Option<Handle> {
    let count = SLOT_COUNT.load(Ordering::Acquire);
    for index in 0..count {
        // SAFETY: bounds checked against the live count.
        let slot = unsafe { &mut *((core::ptr::addr_of_mut!(SLOTS)) as *mut Slot).add(index) };
        if slot.used && find_protocol_index(slot, guid).is_some() {
            return Some(slot as *mut Slot as Handle);
        }
    }
    None
}

/// Calls `f` for every handle carrying `guid`.
pub fn for_each_with(guid: &Guid, mut f: impl FnMut(Handle, *mut c_void)) {
    let count = SLOT_COUNT.load(Ordering::Acquire);
    for index in 0..count {
        // SAFETY: bounds checked against the live count.
        let slot = unsafe { &mut *((core::ptr::addr_of_mut!(SLOTS)) as *mut Slot).add(index) };
        if !slot.used {
            continue;
        }
        if let Some(position) = find_protocol_index(slot, guid) {
            f(slot as *mut Slot as Handle, slot.protocols[position].1);
        }
    }
}

/// How many handles carry `guid`.
pub fn count_with(guid: &Guid) -> usize {
    let mut found = 0;
    for_each_with(guid, |_, _| found += 1);
    found
}

/// The service entry points below: thin wrappers with the specification's
/// signatures, over the database above.

pub unsafe extern "efiapi" fn install_protocol_interface(
    handle: *mut Handle,
    guid: *mut Guid,
    interface_type: r_efi::system::InterfaceType,
    interface: *mut c_void,
) -> Status {
    if guid.is_null() || handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if interface_type != r_efi::system::NATIVE_INTERFACE {
        // Only EFI_NATIVE_INTERFACE exists.
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    let status = unsafe { install_on(*handle, &*guid, interface) };
    if status == Status::SUCCESS && (*handle).is_null() {
        // `install_on` created a handle; find it back through the interface.
        if let Some(created) = handle_of_interface(&*guid, interface) {
            // SAFETY: the out-parameter is writable.
            unsafe { *handle = created };
        }
    }
    status
}

fn handle_of_interface(guid: &Guid, interface: *mut c_void) -> Option<Handle> {
    let mut found = None;
    for_each_with(guid, |handle, candidate| {
        if candidate == interface {
            found = Some(handle);
        }
    });
    found
}

pub unsafe extern "efiapi" fn reinstall_protocol_interface(
    handle: Handle,
    guid: *mut Guid,
    old_interface: *mut c_void,
    new_interface: *mut c_void,
) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let slot = match slot_of(handle) {
        Some(slot) => slot,
        None => return Status::INVALID_PARAMETER,
    };
    // SAFETY: checked non-null above.
    let guid = unsafe { &*guid };
    match find_protocol_index(slot, guid) {
        Some(index) if slot.protocols[index].1 == old_interface => {
            slot.protocols[index].1 = new_interface;
            Status::SUCCESS
        }
        Some(_) => Status::INVALID_PARAMETER,
        None => Status::NOT_FOUND,
    }
}

pub unsafe extern "efiapi" fn uninstall_protocol_interface(
    handle: Handle,
    guid: *mut Guid,
    interface: *mut c_void,
) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let slot = match slot_of(handle) {
        Some(slot) => slot,
        None => return Status::INVALID_PARAMETER,
    };
    // SAFETY: checked non-null above.
    let guid = unsafe { &*guid };
    match find_protocol_index(slot, guid) {
        Some(index) if slot.protocols[index].1 == interface => {
            for following in index..slot.protocol_count - 1 {
                slot.protocols[following] = slot.protocols[following + 1];
            }
            slot.protocol_count -= 1;
            Status::SUCCESS
        }
        Some(_) => Status::INVALID_PARAMETER,
        None => Status::NOT_FOUND,
    }
}

pub unsafe extern "efiapi" fn handle_protocol(
    handle: Handle,
    guid: *mut Guid,
    interface: *mut *mut c_void,
) -> Status {
    if guid.is_null() || interface.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    match interface_on(handle, unsafe { &*guid }) {
        Some(found) => {
            // SAFETY: the out-parameter is writable.
            unsafe { *interface = found };
            Status::SUCCESS
        }
        None => Status::UNSUPPORTED,
    }
}

pub unsafe extern "efiapi" fn locate_protocol(
    guid: *mut Guid,
    _registration: *mut c_void,
    interface: *mut *mut c_void,
) -> Status {
    if guid.is_null() || interface.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    match handle_with(unsafe { &*guid }).and_then(|handle| interface_on(handle, unsafe { &*guid }))
    {
        Some(found) => {
            // SAFETY: the out-parameter is writable.
            unsafe { *interface = found };
            Status::SUCCESS
        }
        None => Status::NOT_FOUND,
    }
}

pub unsafe extern "efiapi" fn locate_handle(
    search_type: LocateSearchType,
    guid: *mut Guid,
    _device_path: *mut c_void,
    size: *mut usize,
    buffer: *mut Handle,
) -> Status {
    if size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if search_type == r_efi::system::BY_PROTOCOL && guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let mut handles = [core::ptr::null_mut::<c_void>(); MAX_HANDLES];
    let mut count = 0;
    // SAFETY: `guid` is checked for the only search type that uses it.
    collect_handles(search_type, guid, &mut handles, &mut count);

    let needed = count * core::mem::size_of::<Handle>();
    // SAFETY: the out-parameters are writable.
    unsafe {
        let capacity = *size;
        *size = needed;
        if capacity < needed {
            return Status::BUFFER_TOO_SMALL;
        }
        if count == 0 {
            return Status::NOT_FOUND;
        }
        if buffer.is_null() {
            return Status::INVALID_PARAMETER;
        }
        for index in 0..count {
            *buffer.add(index) = handles[index] as Handle;
        }
    }
    Status::SUCCESS
}

fn collect_handles(
    search_type: LocateSearchType,
    guid: *mut Guid,
    out: &mut [Handle],
    count: &mut usize,
) {
    match search_type {
        r_efi::system::ALL_HANDLES => {
            let live = SLOT_COUNT.load(Ordering::Acquire);
            for index in 0..live {
                // SAFETY: bounds checked against the live count.
                let slot =
                    unsafe { &mut *((core::ptr::addr_of_mut!(SLOTS)) as *mut Slot).add(index) };
                if slot.used && *count < out.len() {
                    out[*count] = slot as *mut Slot as Handle;
                    *count += 1;
                }
            }
        }
        r_efi::system::BY_PROTOCOL => {
            if guid.is_null() {
                return;
            }
            // SAFETY: the caller checked the pointer.
            let guid = unsafe { &*guid };
            for_each_with(guid, |handle, _| {
                if *count < out.len() {
                    out[*count] = handle;
                    *count += 1;
                }
            });
        }
        _ => {}
    }
}

pub unsafe extern "efiapi" fn locate_handle_buffer(
    search_type: LocateSearchType,
    guid: *mut Guid,
    device_path: *mut c_void,
    no_handles: *mut usize,
    buffer: *mut *mut Handle,
) -> Status {
    if no_handles.is_null() || buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // `LocateHandle` reports the byte size it would need; the buffer this call
    // returns is counted in handles, which is what its out-parameter means.
    let mut bytes = 0usize;
    let status = unsafe {
        locate_handle(
            search_type,
            guid,
            device_path,
            &mut bytes,
            core::ptr::null_mut(),
        )
    };
    if status != Status::BUFFER_TOO_SMALL {
        return status;
    }
    let count = bytes / core::mem::size_of::<Handle>();
    if count == 0 {
        return Status::NOT_FOUND;
    }

    // Pool memory, not pages: the specification says the caller releases this
    // with `FreePool`, so it has to be a pool allocation.
    let memory = uefi::mem::pool_allocate(bytes);
    if memory.is_null() {
        return Status::OUT_OF_RESOURCES;
    }
    let handles = memory as *mut Handle;
    let mut written = 0usize;
    // SAFETY: `handles` points at `bytes` bytes of memory we own.
    unsafe {
        collect_handles(
            search_type,
            guid,
            core::slice::from_raw_parts_mut(handles, count),
            &mut written,
        );
        *no_handles = written;
        *buffer = handles;
    }
    Status::SUCCESS
}

pub unsafe extern "efiapi" fn open_protocol(
    handle: Handle,
    guid: *mut Guid,
    interface: *mut *mut c_void,
    agent_handle: Handle,
    controller_handle: Handle,
    attributes: u32,
) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    let guid = unsafe { &*guid };
    let slot = match slot_of(handle) {
        Some(slot) => slot,
        None => return Status::INVALID_PARAMETER,
    };
    let found = match find_protocol_index(slot, guid) {
        Some(index) => slot.protocols[index].1,
        None => return Status::UNSUPPORTED,
    };

    if attributes & OPEN_PROTOCOL_BY_HANDLE_PROTOCOL != 0 || attributes == 0 {
        if slot.open_count < MAX_OPENS {
            slot.opens[slot.open_count] = Open {
                agent: agent_handle,
                controller: controller_handle,
                attributes,
            };
            slot.open_count += 1;
        }
    }
    if !interface.is_null() {
        // SAFETY: the out-parameter is writable.
        unsafe { *interface = found };
    }
    Status::SUCCESS
}

pub unsafe extern "efiapi" fn close_protocol(
    handle: Handle,
    guid: *mut Guid,
    agent_handle: Handle,
    _controller_handle: Handle,
) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    let guid = unsafe { &*guid };
    let slot = match slot_of(handle) {
        Some(slot) => slot,
        None => return Status::INVALID_PARAMETER,
    };
    if find_protocol_index(slot, guid).is_none() {
        return Status::UNSUPPORTED;
    }
    for index in 0..slot.open_count {
        if slot.opens[index].agent == agent_handle {
            slot.opens[index] = slot.opens[slot.open_count - 1];
            slot.open_count -= 1;
            return Status::SUCCESS;
        }
    }
    Status::NOT_FOUND
}

/// `OpenProtocolInformation`: reports who has the protocol open, which is what
/// an application uses to decide whether it may uninstall it.
pub unsafe extern "efiapi" fn open_protocol_information(
    handle: Handle,
    guid: *mut Guid,
    entries: *mut *mut r_efi::system::OpenProtocolInformationEntry,
    entry_count: *mut usize,
) -> Status {
    if guid.is_null() || entry_count.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    let guid = unsafe { &*guid };
    let slot = match slot_of(handle) {
        Some(slot) => slot,
        None => return Status::INVALID_PARAMETER,
    };
    if find_protocol_index(slot, guid).is_none() {
        return Status::UNSUPPORTED;
    }
    let needed =
        slot.open_count * core::mem::size_of::<r_efi::system::OpenProtocolInformationEntry>();
    // SAFETY: the out-parameters are writable.
    unsafe {
        let capacity = *entry_count;
        *entry_count = slot.open_count;
        if slot.open_count == 0 {
            return Status::SUCCESS;
        }
        if entries.is_null() || capacity < slot.open_count {
            return Status::BUFFER_TOO_SMALL;
        }
        let memory = uefi::mem::pool_allocate(needed);
        if memory.is_null() {
            return Status::OUT_OF_RESOURCES;
        }
        let list = memory as *mut r_efi::system::OpenProtocolInformationEntry;
        for index in 0..slot.open_count {
            let open = slot.opens[index];
            let entry = r_efi::system::OpenProtocolInformationEntry {
                agent_handle: open.agent,
                controller_handle: open.controller,
                attributes: open.attributes,
                open_count: 1,
            };
            *list.add(index) = entry;
        }
        *entries = list;
    }
    Status::SUCCESS
}

pub unsafe extern "efiapi" fn protocols_per_handle(
    handle: Handle,
    protocols: *mut *mut *mut Guid,
    protocol_count: *mut usize,
) -> Status {
    if protocols.is_null() || protocol_count.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let slot = match slot_of(handle) {
        Some(slot) => slot,
        None => return Status::INVALID_PARAMETER,
    };
    let bytes = slot.protocol_count * core::mem::size_of::<*mut Guid>();
    let memory = uefi::mem::pool_allocate(bytes);
    if memory.is_null() {
        return Status::OUT_OF_RESOURCES;
    }
    let list = memory as *mut *mut Guid;
    // SAFETY: the pages are ours and big enough for the GUID list.
    unsafe {
        for index in 0..slot.protocol_count {
            let guid = uefi::mem::pool_allocate(16) as *mut Guid;
            if guid.is_null() {
                return Status::OUT_OF_RESOURCES;
            }
            *guid = slot.protocols[index].0;
            *list.add(index) = guid;
        }
        *protocol_count = slot.protocol_count;
        *protocols = list;
    }
    Status::SUCCESS
}

/// `RegisterProtocolNotify`: this firmware has no protocol-notification
/// machinery, so it answers with the status an application can act on.
pub unsafe extern "efiapi" fn register_protocol_notify(
    _guid: *mut Guid,
    _event: Event,
    _registration: *mut *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

/// `LocateDevicePath`: walks a device path and finds the handle whose device
/// path is the longest prefix of it.
pub unsafe extern "efiapi" fn locate_device_path(
    guid: *mut Guid,
    device_path: *mut *mut device_path::Protocol,
    handle: *mut Handle,
) -> Status {
    if guid.is_null() || device_path.is_null() || handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if (*device_path).is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    let guid = unsafe { &*guid };
    let mut best: Option<(Handle, usize)> = None;
    for_each_with(guid, |candidate, _| {
        if let Some(length) = crate::uefi::device_path::match_prefix(candidate, *device_path) {
            if best.map_or(true, |(_, best_length)| length > best_length) {
                best = Some((candidate, length));
            }
        }
    });
    match best {
        Some((found, _)) => {
            // SAFETY: both out-parameters are writable.
            unsafe { *handle = found };
            Status::SUCCESS
        }
        None => Status::NOT_FOUND,
    }
}
