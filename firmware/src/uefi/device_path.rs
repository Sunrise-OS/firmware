//! Device paths: the linked lists of nodes that describe where something is.
//!
//! A node is a type, a subtype, and its length in bytes including its own
//! header, so a path walks in fixed steps until the end node. The firmware
//! needs two things from them: how long a path is (to compare and copy one),
//! and which handle's path is a prefix of another's, which is how
//! `LocateDevicePath` and the boot manager decide what an application is asking
//! about.

use r_efi::base::{Char16, Handle, Status};
use r_efi::protocols::device_path;

use crate::uefi;

pub const HARDWARE_DEVICE: u8 = 0x01;
pub const ACPI_DEVICE: u8 = 0x02;
pub const MESSAGING_DEVICE: u8 = 0x03;
pub const MEDIA_DEVICE: u8 = 0x04;
pub const MEDIA_PROTOCOL: u8 = 0x04;
pub const END_DEVICE_PATH: u8 = 0x7f;
pub const END_DEVICE_PATH_INSTANCE: u8 = 0xff;

pub const MEDIA_FILE_PATH: u8 = 0x04;
pub const MEDIA_VENDOR: u8 = 0x01;

/// The single node that ends every path.
static END_NODE: device_path::Protocol = device_path::Protocol {
    r#type: END_DEVICE_PATH,
    sub_type: END_DEVICE_PATH_INSTANCE,
    length: [0x04, 0x00],
};

/// A pointer to a terminator, for paths the firmware builds itself (a bare end
/// node is what a `LoadedImage` with no file path carries).
pub fn end_node() -> *const device_path::Protocol {
    core::ptr::addr_of!(END_NODE)
}

/// The length of a path in bytes, including the terminator. Stops after a
/// bounded number of nodes so a malformed path cannot loop forever.
pub fn length(mut path: *const device_path::Protocol) -> usize {
    if path.is_null() {
        return 0;
    }
    let mut total = 0usize;
    for _ in 0..256 {
        // SAFETY: the caller passes a path of at least its header.
        let header = unsafe { &*path };
        let node_length = header.length[0] as usize | ((header.length[1] as usize) << 8);
        if node_length < 4 {
            return total;
        }
        total += node_length;
        if header.r#type == END_DEVICE_PATH && header.sub_type == END_DEVICE_PATH_INSTANCE {
            return total;
        }
        // SAFETY: the node was just read; step to the next one.
        path = unsafe { (path as *const u8).add(node_length) as *const device_path::Protocol };
    }
    total
}

/// Whether `candidate` begins with `prefix`, and how many bytes of it matched.
pub fn match_prefix_bytes(
    mut candidate: *const device_path::Protocol,
    mut prefix: *const device_path::Protocol,
) -> Option<usize> {
    if candidate.is_null() || prefix.is_null() {
        return None;
    }
    let mut matched = 0usize;
    for _ in 0..256 {
        // SAFETY: both pointers are inside paths of at least their headers.
        let candidate_node = unsafe { &*candidate };
        let prefix_node = unsafe { &*prefix };
        let prefix_length =
            prefix_node.length[0] as usize | ((prefix_node.length[1] as usize) << 8);
        let candidate_length =
            candidate_node.length[0] as usize | ((candidate_node.length[1] as usize) << 8);
        if prefix_length < 4 || candidate_length < 4 {
            return None;
        }
        let prefix_is_end = prefix_node.r#type == END_DEVICE_PATH
            && prefix_node.sub_type == END_DEVICE_PATH_INSTANCE;
        if prefix_is_end {
            return Some(matched);
        }
        // SAFETY: both nodes were read; their lengths are in bounds of their own
        // paths by construction of the walk.
        let prefix_bytes =
            unsafe { core::slice::from_raw_parts(prefix as *const u8, prefix_length) };
        let candidate_bytes =
            unsafe { core::slice::from_raw_parts(candidate as *const u8, candidate_length) };
        if prefix_bytes != candidate_bytes {
            return None;
        }
        matched += prefix_length;
        // SAFETY: stepping within the paths just read.
        unsafe {
            candidate =
                (candidate as *const u8).add(candidate_length) as *const device_path::Protocol;
            prefix = (prefix as *const u8).add(prefix_length) as *const device_path::Protocol;
        }
    }
    None
}

/// The `EFI_DEVICE_PATH_PROTOCOL` a handle carries, if it has one.
pub fn path_of(handle: Handle) -> Option<*const device_path::Protocol> {
    uefi::handles::interface_on(handle, &uefi::DEVICE_PATH_PROTOCOL_GUID)
        .map(|interface| interface as *const device_path::Protocol)
}

/// How much of `path` matches the device path installed on `handle`: the number
/// of matched bytes, or `None` when the handle does not describe that path.
///
/// This is what `LocateDevicePath` uses to pick the handle that describes the
/// longest prefix of a path.
pub fn match_prefix(handle: Handle, path: *const device_path::Protocol) -> Option<usize> {
    let installed = path_of(handle)?;
    match_prefix_bytes(installed, path)
}

/// Builds a file-path node for a `\`-separated name, writing it into `buffer`
/// and returning the number of bytes written, including the terminator node.
///
/// # Safety
///
/// `buffer` must hold `20 + name_utf16_bytes` bytes: a file-path node is a
/// header plus UTF-16 units, and every path ends with an end node.
pub unsafe fn write_file_path(
    buffer: *mut u8,
    name: &[Char16],
    buffer_size: usize,
) -> Result<usize, Status> {
    let node_bytes = 4 + name.len() * 2;
    let total = node_bytes + 4;
    if total > buffer_size {
        return Err(Status::BUFFER_TOO_SMALL);
    }
    // SAFETY: the caller guarantees the buffer's size.
    unsafe {
        let node = buffer as *mut device_path::Protocol;
        (*node).r#type = MEDIA_DEVICE;
        (*node).sub_type = MEDIA_FILE_PATH;
        (*node).length = [node_bytes as u8, (node_bytes >> 8) as u8];
        core::ptr::copy_nonoverlapping(name.as_ptr() as *const u8, buffer.add(4), name.len() * 2);
        let end = buffer.add(node_bytes) as *mut device_path::Protocol;
        (*end).r#type = END_DEVICE_PATH;
        (*end).sub_type = END_DEVICE_PATH_INSTANCE;
        (*end).length = [0x04, 0x00];
    }
    Ok(total)
}

/// The file-path node's name, as a vector of UTF-16 units, when a node is one.
pub fn file_path_name(node: *const device_path::Protocol) -> Option<alloc::vec::Vec<Char16>> {
    // SAFETY: the caller passes a real node.
    let header = unsafe { &*node };
    if header.r#type != MEDIA_DEVICE || header.sub_type != MEDIA_FILE_PATH {
        return None;
    }
    let node_length = header.length[0] as usize | ((header.length[1] as usize) << 8);
    if node_length < 4 {
        return None;
    }
    let units = (node_length - 4) / 2;
    // SAFETY: the node was read; its payload follows its header.
    let payload =
        unsafe { core::slice::from_raw_parts((node as *const u8).add(4) as *const Char16, units) };
    Some(payload.to_vec())
}
