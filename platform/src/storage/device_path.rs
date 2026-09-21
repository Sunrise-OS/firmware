//! Device paths for the storage stack.
//!
//! `LoadImage` resolves a file path by finding the handle whose device path is
//! the longest prefix of it, and an application finds its own volume from the
//! device handle it was loaded from. Both need real paths:
//!
//! ```text
//! disk       PciRoot(0x0)/Pci(slot,func)
//! partition  PciRoot(0x0)/Pci(slot,func)/HD(n,GPT,<guid>,start,size)
//! file       ...partition.../\EFI\BOOT\BOOTAA64.EFI
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use patina::standard::efi::protocols::device_path;

use super::gpt::Partition;

const TYPE_HARDWARE: u8 = 0x01;
const SUBTYPE_PCI: u8 = 0x01;
const TYPE_ACPI: u8 = 0x02;
const SUBTYPE_ACPI: u8 = 0x01;
const TYPE_MEDIA: u8 = 0x04;
const SUBTYPE_HARD_DRIVE: u8 = 0x01;
const SUBTYPE_FILE_PATH: u8 = 0x04;
const TYPE_END: u8 = 0x7f;
const SUBTYPE_END_ENTIRE: u8 = 0xff;

/// `EISA_PNP_ID(0x0A08)`: a PCI Express root bridge.
const PNP_PCIE_ROOT: u32 = 0x0a08_41d0;

fn node(path: &mut Vec<u8>, kind: u8, sub_type: u8, data: &[u8]) {
    let length = (4 + data.len()) as u16;
    path.extend_from_slice(&[kind, sub_type]);
    path.extend_from_slice(&length.to_le_bytes());
    path.extend_from_slice(data);
}

fn end(path: &mut Vec<u8>) {
    node(path, TYPE_END, SUBTYPE_END_ENTIRE, &[]);
}

/// The nodes of a disk's path, without the end node.
fn disk_nodes(slot: u8, func: u8) -> Vec<u8> {
    let mut path = Vec::new();
    let mut acpi = [0u8; 8];
    acpi[..4].copy_from_slice(&PNP_PCIE_ROOT.to_le_bytes());
    node(&mut path, TYPE_ACPI, SUBTYPE_ACPI, &acpi);
    node(&mut path, TYPE_HARDWARE, SUBTYPE_PCI, &[func, slot]);
    path
}

fn partition_nodes(slot: u8, func: u8, partition: &Partition) -> Vec<u8> {
    let mut path = disk_nodes(slot, func);
    let mut data = Vec::with_capacity(38);
    data.extend_from_slice(&partition.number.to_le_bytes());
    data.extend_from_slice(&partition.first_lba.to_le_bytes());
    data.extend_from_slice(&partition.blocks().to_le_bytes());
    data.extend_from_slice(&partition.unique_guid);
    data.push(0x02); // partition format: GPT
    data.push(0x02); // signature type: GUID
    node(&mut path, TYPE_MEDIA, SUBTYPE_HARD_DRIVE, &data);
    path
}

/// A path that lives as long as the handle it is installed on.
fn leak(mut path: Vec<u8>) -> *mut device_path::Protocol {
    end(&mut path);
    Box::leak(path.into_boxed_slice()).as_mut_ptr() as *mut device_path::Protocol
}

pub fn disk(slot: u8, func: u8) -> *mut device_path::Protocol {
    leak(disk_nodes(slot, func))
}

pub fn partition(slot: u8, func: u8, partition: &Partition) -> *mut device_path::Protocol {
    leak(partition_nodes(slot, func, partition))
}

/// The byte length of a device path up to, not including, its end node.
///
/// # Safety
///
/// `path` must be a well-formed device path.
pub unsafe fn length_without_end(path: *const device_path::Protocol) -> usize {
    let mut offset = 0usize;
    loop {
        // SAFETY: the caller promises a well-formed path, so each node header
        // is readable and its length leads to the next one.
        let (kind, length) = unsafe {
            let node = (path as *const u8).add(offset);
            (
                *node,
                u16::from_le_bytes([*node.add(2), *node.add(3)]) as usize,
            )
        };
        if kind == TYPE_END || length < 4 {
            return offset;
        }
        offset += length;
    }
}

/// `prefix` followed by a file-path node naming `file`, as owned bytes.
///
/// # Safety
///
/// `prefix` must be a well-formed device path.
pub unsafe fn append_file(prefix: *const device_path::Protocol, file: &str) -> Box<[u8]> {
    // SAFETY: forwarded from the caller.
    let length = unsafe { length_without_end(prefix) };
    let mut path = Vec::with_capacity(length + 8 + file.len() * 2);
    // SAFETY: the first `length` bytes are the prefix's nodes.
    path.extend_from_slice(unsafe { core::slice::from_raw_parts(prefix as *const u8, length) });
    let mut name: Vec<u8> = file
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    node(
        &mut path,
        TYPE_MEDIA,
        SUBTYPE_FILE_PATH,
        &core::mem::take(&mut name),
    );
    end(&mut path);
    path.into_boxed_slice()
}
