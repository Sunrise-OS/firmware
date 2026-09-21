//! `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` and `EFI_FILE_PROTOCOL` over a
//! `FileSystem`.
//!
//! Volumes are read-only: the write side of the file protocol answers
//! `WRITE_PROTECTED`. Every file handle is a heap object whose first field is
//! the protocol; `Close` frees it.
//!
//! `Open` resolves names the way the specification describes them: a leading
//! `\` is from the root, `.` and `..` are the current and parent directory, and
//! a name may have several components - Patina's `LoadImage` opens a file path
//! node's whole `\EFI\BOOT\BOOTAA64.EFI` in one call.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;

use patina::standard::efi::{
    self, Boolean, Char16, Guid, Time,
    protocols::{file, simple_file_system},
};

use super::fs::{FileNode, FileSystem};

/// The label every volume carries.
const VOLUME_LABEL: &str = "ESP";

#[repr(C)]
struct Volume {
    protocol: simple_file_system::Protocol,
    filesystem: Arc<dyn FileSystem>,
    /// The volume's size in bytes, for `EFI_FILE_SYSTEM_INFO`.
    size: u64,
    block_size: u32,
}

#[repr(C)]
struct File {
    protocol: file::Protocol,
    volume: *const Volume,
    /// The node's path from the root, normalised and backslash-separated.
    path: String,
    node: Box<dyn FileNode>,
    /// A file's byte offset, or a directory's entry index.
    position: u64,
    /// A directory's entries, read once on the first directory read.
    entries: Option<Vec<Box<dyn FileNode>>>,
}

/// Builds a published Simple File System instance for `filesystem`.
pub fn new(filesystem: Arc<dyn FileSystem>, size: u64, block_size: u32) -> *mut c_void {
    let volume = crate::publish::firmware_lifetime(Volume {
        protocol: simple_file_system::Protocol {
            revision: simple_file_system::REVISION,
            open_volume,
        },
        filesystem,
        size,
        block_size,
    });
    let volume = unsafe { &mut *volume.as_ptr() };
    volume as *mut Volume as *mut c_void
}

fn open_file(volume: *const Volume, path: String, node: Box<dyn FileNode>) -> *mut file::Protocol {
    let file = Box::leak(Box::new(File {
        protocol: file::Protocol {
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
            open_ex,
            read_ex,
            write_ex,
            flush_ex,
        },
        volume,
        path,
        node,
        position: 0,
        entries: None,
    }));
    file as *mut File as *mut file::Protocol
}

/// # Safety
///
/// `this` must be a file protocol this driver created and has not closed.
unsafe fn file_of<'a>(this: *mut file::Protocol) -> Option<&'a mut File> {
    // SAFETY: forwarded from the caller; the protocol is the first field.
    unsafe { (this as *mut File).as_mut() }
}

extern "efiapi" fn open_volume(
    this: *mut simple_file_system::Protocol,
    root: *mut *mut file::Protocol,
) -> efi::Status {
    if this.is_null() || root.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let volume = this as *const Volume;
    // SAFETY: every simple file system this driver publishes is a `Volume`.
    let node = unsafe { (*volume).filesystem.root() };
    // SAFETY: the out-parameter was checked.
    unsafe { root.write_unaligned(open_file(volume, String::new(), node)) };
    efi::Status::SUCCESS
}

/// Reads a NUL-terminated UCS-2 string.
fn string16(text: *const Char16) -> Option<String> {
    let mut units = Vec::new();
    for index in 0..4096 {
        // SAFETY: the caller of the protocol promises a terminated string.
        let unit = unsafe { text.add(index).read_unaligned() };
        if unit == 0 {
            return Some(
                char::decode_utf16(units)
                    .map(|c| c.unwrap_or('?'))
                    .collect(),
            );
        }
        units.push(unit);
    }
    None
}

/// Resolves `name` against the directory at `base`.
fn resolve(base: &str, name: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !name.starts_with(['\\', '/']) {
        parts.extend(base.split('\\').filter(|part| !part.is_empty()));
    }
    for component in name.split(['\\', '/']) {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            component => parts.push(component),
        }
    }
    parts.join("\\")
}

extern "efiapi" fn open(
    this: *mut file::Protocol,
    new_handle: *mut *mut file::Protocol,
    file_name: *mut Char16,
    open_mode: u64,
    _attributes: u64,
) -> efi::Status {
    if new_handle.is_null() || file_name.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: `this` is one of this driver's open files.
    let Some(file) = (unsafe { file_of(this) }) else {
        return efi::Status::INVALID_PARAMETER;
    };
    if open_mode & (file::MODE_WRITE | file::MODE_CREATE) != 0 {
        return efi::Status::WRITE_PROTECTED;
    }
    let Some(name) = string16(file_name) else {
        return efi::Status::INVALID_PARAMETER;
    };
    // A relative name is resolved against the directory, or a file's parent.
    let base = if file.node.is_dir() {
        file.path.as_str()
    } else {
        file.path.rsplit_once('\\').map_or("", |(parent, _)| parent)
    };
    let path = resolve(base, &name);
    // SAFETY: the volume outlives every file opened on it.
    let Some(node) = (unsafe { (*file.volume).filesystem.open(&path) }) else {
        return efi::Status::NOT_FOUND;
    };
    // SAFETY: the out-parameter was checked.
    unsafe { new_handle.write_unaligned(open_file(file.volume, path, node)) };
    efi::Status::SUCCESS
}

extern "efiapi" fn close(this: *mut file::Protocol) -> efi::Status {
    if this.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: `this` is one of this driver's files, created by `Box::leak`, and
    // the specification makes the handle invalid once closed.
    drop(unsafe { Box::from_raw(this as *mut File) });
    efi::Status::SUCCESS
}

extern "efiapi" fn delete(this: *mut file::Protocol) -> efi::Status {
    // Delete closes the handle even when the file cannot be deleted.
    close(this);
    efi::Status::WARN_DELETE_FAILURE
}

extern "efiapi" fn read(
    this: *mut file::Protocol,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> efi::Status {
    if buffer_size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: `this` is one of this driver's open files.
    let Some(file) = (unsafe { file_of(this) }) else {
        return efi::Status::INVALID_PARAMETER;
    };
    // SAFETY: the size pointer was checked.
    let capacity = unsafe { buffer_size.read_unaligned() };
    if capacity > 0 && buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }

    if file.node.is_dir() {
        // A directory read returns the next entry's EFI_FILE_INFO, or zero bytes
        // at the end.
        let entries = file.entries.get_or_insert_with(|| file.node.children());
        let Some(entry) = entries.get(file.position as usize) else {
            // SAFETY: the size pointer was checked.
            unsafe { buffer_size.write_unaligned(0) };
            return efi::Status::SUCCESS;
        };
        let status = write_file_info(entry.as_ref(), buffer_size, buffer);
        if status == efi::Status::SUCCESS {
            file.position += 1;
        }
        return status;
    }

    // SAFETY: the caller promises `capacity` writable bytes at `buffer`.
    let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, capacity) };
    let count = file.node.read_at(file.position, destination);
    file.position += count as u64;
    // SAFETY: the size pointer was checked.
    unsafe { buffer_size.write_unaligned(count) };
    efi::Status::SUCCESS
}

extern "efiapi" fn write(
    _this: *mut file::Protocol,
    _size: *mut usize,
    _buffer: *mut c_void,
) -> efi::Status {
    efi::Status::WRITE_PROTECTED
}

extern "efiapi" fn get_position(this: *mut file::Protocol, position: *mut u64) -> efi::Status {
    if position.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: `this` is one of this driver's open files.
    let Some(file) = (unsafe { file_of(this) }) else {
        return efi::Status::INVALID_PARAMETER;
    };
    if file.node.is_dir() {
        return efi::Status::UNSUPPORTED;
    }
    // SAFETY: the out-parameter was checked.
    unsafe { position.write_unaligned(file.position) };
    efi::Status::SUCCESS
}

extern "efiapi" fn set_position(this: *mut file::Protocol, position: u64) -> efi::Status {
    // SAFETY: `this` is one of this driver's open files.
    let Some(file) = (unsafe { file_of(this) }) else {
        return efi::Status::INVALID_PARAMETER;
    };
    if file.node.is_dir() {
        // Only rewinding a directory is defined.
        if position != 0 {
            return efi::Status::UNSUPPORTED;
        }
        file.position = 0;
        return efi::Status::SUCCESS;
    }
    // All ones means the end of the file.
    file.position = if position == u64::MAX {
        file.node.len()
    } else {
        position
    };
    efi::Status::SUCCESS
}

const ZERO_TIME: Time = Time {
    year: 0,
    month: 0,
    day: 0,
    hour: 0,
    minute: 0,
    second: 0,
    pad1: 0,
    nanosecond: 0,
    timezone: efi::UNSPECIFIED_TIMEZONE,
    daylight: 0,
    pad2: 0,
};

/// Writes `node`'s `EFI_FILE_INFO`, or reports the size it needs.
fn write_file_info(
    node: &dyn FileNode,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> efi::Status {
    let name: Vec<Char16> = node.name().encode_utf16().chain([0]).collect();
    let header = core::mem::size_of::<file::Info>();
    let needed = header + name.len() * 2;
    // SAFETY: the caller checked the size pointer.
    let capacity = unsafe { buffer_size.read_unaligned() };
    // SAFETY: as above.
    unsafe { buffer_size.write_unaligned(needed) };
    if capacity < needed {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let info = file::Info::<0> {
        size: needed as u64,
        file_size: node.len(),
        physical_size: node.len(),
        create_time: ZERO_TIME,
        last_access_time: ZERO_TIME,
        modification_time: ZERO_TIME,
        attribute: if node.is_dir() {
            file::DIRECTORY | file::READ_ONLY
        } else {
            file::READ_ONLY
        },
        file_name: [],
    };
    // SAFETY: the buffer holds at least `needed` bytes; the name follows the
    // fixed part, and unaligned writes make no assumption about the buffer.
    unsafe {
        (buffer as *mut file::Info<0>).write_unaligned(info);
        let target = (buffer as *mut u8).add(header);
        for (index, unit) in name.iter().enumerate() {
            (target.add(index * 2) as *mut Char16).write_unaligned(*unit);
        }
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn get_info(
    this: *mut file::Protocol,
    information_type: *mut Guid,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> efi::Status {
    if information_type.is_null() || buffer_size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: `this` is one of this driver's open files.
    let Some(file) = (unsafe { file_of(this) }) else {
        return efi::Status::INVALID_PARAMETER;
    };
    // SAFETY: the GUID pointer was checked.
    let kind = unsafe { information_type.read_unaligned() };
    // SAFETY: the volume outlives its files.
    let volume = unsafe { &*file.volume };

    if kind == file::INFO_ID {
        return write_file_info(file.node.as_ref(), buffer_size, buffer);
    }

    let label: Vec<Char16> = VOLUME_LABEL.encode_utf16().chain([0]).collect();
    let (header, fill_system_info) = if kind == file::SYSTEM_INFO_ID {
        (core::mem::size_of::<file::SystemInfo>(), true)
    } else if kind == file::SYSTEM_VOLUME_LABEL_ID {
        (0, false)
    } else {
        return efi::Status::UNSUPPORTED;
    };
    let needed = header + label.len() * 2;
    // SAFETY: the size pointer was checked.
    let capacity = unsafe { buffer_size.read_unaligned() };
    // SAFETY: as above.
    unsafe { buffer_size.write_unaligned(needed) };
    if capacity < needed {
        return efi::Status::BUFFER_TOO_SMALL;
    }
    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: the buffer holds at least `needed` bytes.
    unsafe {
        if fill_system_info {
            (buffer as *mut file::SystemInfo<0>).write_unaligned(file::SystemInfo {
                size: needed as u64,
                read_only: Boolean::TRUE,
                volume_size: volume.size,
                free_space: 0,
                block_size: volume.block_size,
                volume_label: [],
            });
        }
        let target = (buffer as *mut u8).add(header);
        for (index, unit) in label.iter().enumerate() {
            (target.add(index * 2) as *mut Char16).write_unaligned(*unit);
        }
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn set_info(
    _this: *mut file::Protocol,
    _information_type: *mut Guid,
    _buffer_size: usize,
    _buffer: *mut c_void,
) -> efi::Status {
    efi::Status::WRITE_PROTECTED
}

extern "efiapi" fn flush(_this: *mut file::Protocol) -> efi::Status {
    efi::Status::SUCCESS
}

// Revision 2's asynchronous variants: not provided, and the revision field says
// revision 1 semantics.

extern "efiapi" fn open_ex(
    _this: *mut file::Protocol,
    _new_handle: *mut *mut file::Protocol,
    _file_name: *mut Char16,
    _open_mode: u64,
    _attributes: u64,
    _token: *mut file::IoToken,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn read_ex(_this: *mut file::Protocol, _token: *mut file::IoToken) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn write_ex(_this: *mut file::Protocol, _token: *mut file::IoToken) -> efi::Status {
    efi::Status::UNSUPPORTED
}

extern "efiapi" fn flush_ex(_this: *mut file::Protocol, _token: *mut file::IoToken) -> efi::Status {
    efi::Status::UNSUPPORTED
}
