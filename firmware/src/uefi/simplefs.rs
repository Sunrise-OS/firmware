//! `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` and `EFI_FILE_PROTOCOL`, over the
//! filesystem abstraction.
//!
//! An application's view of a volume: open it, get a handle for the root, then
//! open, read, and close files by name. This firmware's volumes are read-only,
//! so the write side of the protocol answers `WRITE_PROTECTED` rather than
//! pretending - a caller that gets that answer knows the volume will not change
//! under it.
//!
//! File handles live in a static table: an application may hold one for as long
//! as it runs, and `Close` is the only thing that releases it.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use r_efi::base::{Boolean, Char16, Guid, Status};
use r_efi::protocols::file;
use r_efi::protocols::simple_file_system;
use r_efi::system::Time;

use crate::fs::{FileNode, FileSystem};
use crate::uefi::handles;

/// How many files may be open at once.
const MAX_FILES: usize = 32;
/// How many volumes the firmware will publish.
const MAX_VOLUMES: usize = 4;

/// `EFI_FILE_INFO`'s identifying GUID.
const FILE_INFO_GUID: Guid = Guid::from_fields(
    0x09576e92,
    0x6d3f,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
/// `EFI_FILE_SYSTEM_INFO`'s identifying GUID.
const FILE_SYSTEM_INFO_GUID: Guid = Guid::from_fields(
    0x09576e93,
    0x6d3f,
    0x11d2,
    0x8e,
    0x39,
    &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
/// `EFI_FILE_SYSTEM_VOLUME_LABEL`'s identifying GUID.
const FILE_SYSTEM_VOLUME_LABEL_GUID: Guid = Guid::from_fields(
    0xdb47d7d3,
    0xfe81,
    0x11d3,
    0x9a,
    0x35,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// The label every volume this firmware publishes carries.
const VOLUME_LABEL: &str = "WEIR";

/// An open file: the node it points at and where the reader is in it.
struct FileState {
    node: Box<dyn FileNode>,
    position: u64,
}

struct FileSlot {
    used: bool,
    address: usize,
    state: Option<FileState>,
}

const EMPTY_FILE: FileSlot = FileSlot {
    used: false,
    address: 0,
    state: None,
};

struct VolumeSlot {
    used: bool,
    address: usize,
    filesystem: Option<Arc<dyn FileSystem>>,
}

const EMPTY_VOLUME: VolumeSlot = VolumeSlot {
    used: false,
    address: 0,
    filesystem: None,
};

static mut FILES: MaybeUninit<[FileSlot; MAX_FILES]> = MaybeUninit::uninit();
static mut FILE_COUNT: usize = 0;
static mut VOLUMES: MaybeUninit<[VolumeSlot; MAX_VOLUMES]> = MaybeUninit::uninit();
static mut VOLUME_COUNT: usize = 0;

/// Prepares the tables. Called once from `uefi::init`.
pub fn init() {
    // SAFETY: single-threaded bring-up; nothing has read the tables yet.
    unsafe {
        (*core::ptr::addr_of_mut!(FILES)).write([EMPTY_FILE; MAX_FILES]);
        (*core::ptr::addr_of_mut!(VOLUMES)).write([EMPTY_VOLUME; MAX_VOLUMES]);
        FILE_COUNT = 0;
        VOLUME_COUNT = 0;
    }
}

/// Installs the protocol on an existing handle, which is the one that carries
/// the volume's device path.
pub fn install(handle: r_efi::base::Handle, filesystem: Arc<dyn FileSystem>) -> Result<(), Status> {
    let count = unsafe { core::ptr::read(core::ptr::addr_of!(VOLUME_COUNT)) };
    if count >= MAX_VOLUMES {
        return Err(Status::OUT_OF_RESOURCES);
    }
    let protocol = crate::uefi::mem::pages_for(
        r_efi::system::BOOT_SERVICES_DATA,
        core::mem::size_of::<simple_file_system::Protocol>(),
    ) as *mut simple_file_system::Protocol;
    if protocol.is_null() {
        return Err(Status::OUT_OF_RESOURCES);
    }
    // SAFETY: the pages are ours and large enough for the protocol.
    unsafe {
        (*protocol) = simple_file_system::Protocol {
            revision: simple_file_system::REVISION,
            open_volume,
        };
    }

    // SAFETY: the slot index is inside the static table.
    unsafe {
        core::ptr::write(
            ((core::ptr::addr_of_mut!(VOLUMES)) as *mut VolumeSlot).add(count),
            VolumeSlot {
                used: true,
                address: protocol as usize,
                filesystem: Some(filesystem),
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(VOLUME_COUNT), count + 1);
    }

    let status = unsafe {
        handles::install_on(
            handle,
            &crate::uefi::SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
            protocol as *mut c_void,
        )
    };
    if status == Status::SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// The filesystem behind a simple-file-system protocol pointer.
fn volume_of(protocol: *mut simple_file_system::Protocol) -> Option<&'static Arc<dyn FileSystem>> {
    let address = protocol as usize;
    let count = unsafe { core::ptr::read(core::ptr::addr_of!(VOLUME_COUNT)) };
    for index in 0..count {
        // SAFETY: the index is inside the live range of the static table.
        let slot =
            unsafe { &mut *((core::ptr::addr_of_mut!(VOLUMES)) as *mut VolumeSlot).add(index) };
        if slot.used && slot.address == address {
            return slot.filesystem.as_ref();
        }
    }
    None
}

/// The file slot a protocol pointer came from.
fn file_slot(protocol: *mut file::Protocol) -> Option<&'static mut FileSlot> {
    let address = protocol as usize;
    let count = unsafe { core::ptr::read(core::ptr::addr_of!(FILE_COUNT)) };
    for index in 0..count {
        // SAFETY: the index is inside the live range of the static table.
        let slot = unsafe { &mut *((core::ptr::addr_of_mut!(FILES)) as *mut FileSlot).add(index) };
        if slot.used && slot.address == address {
            return Some(slot);
        }
    }
    None
}

/// Creates a file handle for `node`.
fn open_handle(node: Box<dyn FileNode>) -> Result<*mut file::Protocol, Status> {
    let count = unsafe { core::ptr::read(core::ptr::addr_of!(FILE_COUNT)) };
    if count >= MAX_FILES {
        return Err(Status::OUT_OF_RESOURCES);
    }
    let protocol = crate::uefi::mem::pages_for(
        r_efi::system::BOOT_SERVICES_DATA,
        core::mem::size_of::<file::Protocol>(),
    ) as *mut file::Protocol;
    if protocol.is_null() {
        return Err(Status::OUT_OF_RESOURCES);
    }
    // SAFETY: the pages are ours and large enough for the protocol.
    unsafe {
        (*protocol) = file::Protocol {
            revision: file::REVISION,
            open,
            close,
            delete,
            read,
            write,
            get_position,
            set_position,
            get_info,
            set_info,
            flush,
            open_ex: unsupported_open_ex,
            read_ex: unsupported_read_ex,
            write_ex: unsupported_write_ex,
            flush_ex: unsupported_flush_ex,
        };
    }

    // SAFETY: the slot index is inside the static table.
    unsafe {
        core::ptr::write(
            ((core::ptr::addr_of_mut!(FILES)) as *mut FileSlot).add(count),
            FileSlot {
                used: true,
                address: protocol as usize,
                state: Some(FileState { node, position: 0 }),
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(FILE_COUNT), count + 1);
    }
    Ok(protocol)
}

/// `OpenVolume`: the root of the volume, as a file handle.
unsafe extern "efiapi" fn open_volume(
    this: *mut simple_file_system::Protocol,
    root: *mut *mut file::Protocol,
) -> Status {
    if this.is_null() || root.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(filesystem) = volume_of(this) else {
        return Status::INVALID_PARAMETER;
    };
    match open_handle(filesystem.root()) {
        Ok(protocol) => {
            // SAFETY: the out-parameter is writable.
            unsafe { *root = protocol };
            Status::SUCCESS
        }
        Err(status) => status,
    }
}

/// `Open`: a file or directory relative to this one.
unsafe extern "efiapi" fn open(
    this: *mut file::Protocol,
    new_handle: *mut *mut file::Protocol,
    file_name: *mut Char16,
    open_mode: u64,
    attributes: u64,
) -> Status {
    if new_handle.is_null() || file_name.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(slot) = file_slot(this) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(state) = slot.state.as_mut() else {
        return Status::INVALID_PARAMETER;
    };
    if !state.node.is_dir() {
        return Status::NOT_FOUND;
    }
    if open_mode & file::MODE_CREATE != 0 {
        // Nothing on this volume can be created: it is mounted read-only.
        return Status::WRITE_PROTECTED;
    }
    let _ = attributes;

    // The name is relative: a directory's children are what this can open.
    let name = match cstring16(file_name) {
        Some(name) => name,
        None => return Status::INVALID_PARAMETER,
    };
    let Some(child) = state.node.child(&name) else {
        return Status::NOT_FOUND;
    };
    match open_handle(child) {
        Ok(protocol) => {
            // SAFETY: the out-parameter is writable.
            unsafe { *new_handle = protocol };
            Status::SUCCESS
        }
        Err(status) => status,
    }
}

/// `Close`: release the slot. The handle is not usable afterwards, which is
/// what the specification says.
unsafe extern "efiapi" fn close(this: *mut file::Protocol) -> Status {
    let Some(slot) = file_slot(this) else {
        return Status::INVALID_PARAMETER;
    };
    slot.state = None;
    slot.used = false;
    Status::SUCCESS
}

/// `Delete`: a read-only volume cannot delete.
unsafe extern "efiapi" fn delete(_this: *mut file::Protocol) -> Status {
    Status::WRITE_PROTECTED
}

/// `Read`: fills the caller's buffer from the current position.
unsafe extern "efiapi" fn read(
    this: *mut file::Protocol,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(slot) = file_slot(this) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(state) = slot.state.as_mut() else {
        return Status::INVALID_PARAMETER;
    };
    // SAFETY: the size out-parameter is writable.
    let capacity = unsafe { *buffer_size };
    if capacity > 0 && buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if state.node.is_dir() {
        return Status::ACCESS_DENIED;
    }

    // SAFETY: the caller promises `capacity` writable bytes at `buffer`.
    let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, capacity) };
    let read = state.node.read_at(state.position, destination);
    state.position += read as u64;
    // SAFETY: the size out-parameter is writable.
    unsafe { *buffer_size = read };
    Status::SUCCESS
}

/// `Write`: a read-only volume cannot write.
unsafe extern "efiapi" fn write(
    _this: *mut file::Protocol,
    _buffer_size: *mut usize,
    _buffer: *mut c_void,
) -> Status {
    Status::WRITE_PROTECTED
}

/// `GetPosition`.
unsafe extern "efiapi" fn get_position(this: *mut file::Protocol, position: *mut u64) -> Status {
    if position.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(slot) = file_slot(this) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(state) = slot.state.as_ref() else {
        return Status::INVALID_PARAMETER;
    };
    // SAFETY: the out-parameter is writable.
    unsafe { *position = state.position };
    Status::SUCCESS
}

/// `SetPosition`.
unsafe extern "efiapi" fn set_position(this: *mut file::Protocol, position: u64) -> Status {
    let Some(slot) = file_slot(this) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(state) = slot.state.as_mut() else {
        return Status::INVALID_PARAMETER;
    };
    // Past the end is allowed: the next read returns nothing, which is what the
    // specification describes. Beyond that, a position is meaningless.
    if position > state.node.len() {
        return Status::INVALID_PARAMETER;
    }
    state.position = position;
    Status::SUCCESS
}

/// `GetInfo`: `EFI_FILE_INFO`, `EFI_FILE_SYSTEM_INFO`, or the volume label,
/// depending on the GUID the caller asks for.
unsafe extern "efiapi" fn get_info(
    this: *mut file::Protocol,
    information_type: *mut Guid,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if information_type.is_null() || buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(slot) = file_slot(this) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(state) = slot.state.as_ref() else {
        return Status::INVALID_PARAMETER;
    };
    // SAFETY: both pointers were checked above.
    let kind = unsafe { *information_type };
    // SAFETY: the size out-parameter is writable.
    let capacity = unsafe { *buffer_size };

    if kind == FILE_INFO_GUID {
        let name: alloc::vec::Vec<Char16> = state.node.name().encode_utf16().collect();
        let name_bytes = (name.len() + 1) * 2;
        let needed = core::mem::size_of::<file::Info>() + name_bytes;
        // SAFETY: the size out-parameter is writable.
        unsafe { *buffer_size = needed };
        if capacity < needed {
            return Status::BUFFER_TOO_SMALL;
        }
        if buffer.is_null() {
            return Status::INVALID_PARAMETER;
        }
        // SAFETY: the caller's buffer holds `capacity` bytes, which is at least
        // `needed`, and the fields plus the name fit inside it.
        unsafe {
            let info = buffer as *mut file::Info<0>;
            (*info).size = needed as u64;
            (*info).file_size = state.node.len();
            (*info).physical_size = state.node.len();
            (*info).create_time = ZERO_TIME;
            (*info).last_access_time = ZERO_TIME;
            (*info).modification_time = ZERO_TIME;
            (*info).attribute = if state.node.is_dir() {
                file::DIRECTORY
            } else {
                file::READ_ONLY
            };
            let target = (buffer as *mut u8).add(core::mem::size_of::<file::Info>()) as *mut Char16;
            core::ptr::copy_nonoverlapping(name.as_ptr(), target, name.len());
            *target.add(name.len()) = 0;
        }
        return Status::SUCCESS;
    }

    if kind == FILE_SYSTEM_INFO_GUID {
        let needed = core::mem::size_of::<file::SystemInfo>();
        // SAFETY: the size out-parameter is writable.
        unsafe { *buffer_size = needed };
        if capacity < needed {
            return Status::BUFFER_TOO_SMALL;
        }
        if buffer.is_null() {
            return Status::INVALID_PARAMETER;
        }
        // SAFETY: the caller's buffer holds at least `needed` bytes.
        unsafe {
            let info = buffer as *mut file::SystemInfo;
            (*info).size = needed as u64;
            (*info).read_only = Boolean::TRUE;
            (*info).volume_size = 0;
            (*info).free_space = 0;
            (*info).block_size = 512;
            (*info).volume_label = [];
        }
        return Status::SUCCESS;
    }

    if kind == FILE_SYSTEM_VOLUME_LABEL_GUID {
        let label: alloc::vec::Vec<Char16> = VOLUME_LABEL.encode_utf16().collect();
        let needed = 4 + (label.len() + 1) * 2;
        // SAFETY: the size out-parameter is writable.
        unsafe { *buffer_size = needed };
        if capacity < needed {
            return Status::BUFFER_TOO_SMALL;
        }
        if buffer.is_null() {
            return Status::INVALID_PARAMETER;
        }
        // SAFETY: the caller's buffer holds at least `needed` bytes; the label
        // structure is a size, then the name.
        unsafe {
            let size = buffer as *mut u32;
            *size = needed as u32;
            let target = (buffer as *mut u8).add(4) as *mut Char16;
            core::ptr::copy_nonoverlapping(label.as_ptr(), target, label.len());
            *target.add(label.len()) = 0;
        }
        return Status::SUCCESS;
    }

    Status::UNSUPPORTED
}

/// `SetInfo`: a read-only volume has nothing to rename or resize.
unsafe extern "efiapi" fn set_info(
    _this: *mut file::Protocol,
    _information_type: *mut Guid,
    _buffer_size: usize,
    _buffer: *mut c_void,
) -> Status {
    Status::WRITE_PROTECTED
}

/// `Flush`: writes go straight to the device, so there is nothing to flush -
/// but a caller that flushes is about to trust the file, and gets a success.
unsafe extern "efiapi" fn flush(_this: *mut file::Protocol) -> Status {
    Status::SUCCESS
}

// The extended variants belong to `EFI_FILE_PROTOCOL` revision 2. This firmware
// publishes revision 1 semantics and says so, rather than implementing a second
// file API.

unsafe extern "efiapi" fn unsupported_open_ex(
    _this: *mut file::Protocol,
    _new_handle: *mut *mut file::Protocol,
    _file_name: *mut Char16,
    _open_mode: u64,
    _attributes: u64,
    _token: *mut file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn unsupported_read_ex(
    _this: *mut file::Protocol,
    _token: *mut file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn unsupported_write_ex(
    _this: *mut file::Protocol,
    _token: *mut file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn unsupported_flush_ex(
    _this: *mut file::Protocol,
    _token: *mut file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}

/// The time a file entry that carries no timestamps reports: the specification's
/// own "unknown" value.
const ZERO_TIME: Time = Time {
    year: 0,
    month: 0,
    day: 0,
    hour: 0,
    minute: 0,
    second: 0,
    pad1: 0,
    nanosecond: 0,
    timezone: r_efi::system::UNSPECIFIED_TIMEZONE as i16,
    daylight: 0,
    pad2: 0,
};

/// Reads a NUL-terminated UTF-16 string into ASCII, the only alphabet this
/// firmware's volumes use for a path component it compares.
fn cstring16(text: *mut Char16) -> Option<alloc::string::String> {
    let mut units: alloc::vec::Vec<Char16> = vec::Vec::new();
    for index in 0..1024 {
        // SAFETY: the caller promises a NUL-terminated string.
        let unit = unsafe { *text.add(index) };
        if unit == 0 {
            return Some(
                units
                    .iter()
                    .map(|unit| char::from_u32(*unit as u32).unwrap_or('?'))
                    .collect(),
            );
        }
        units.push(unit);
    }
    None
}

/// Kept so `Boolean` is nameable where the protocol's revision 2 functions take
/// one, even though they all answer `UNSUPPORTED`.
const _: Option<Boolean> = None;
