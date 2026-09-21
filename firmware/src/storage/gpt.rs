//! GPT: finding the EFI System Partition on a disk.
//!
//! A GPT disk starts with a protective MBR, a header at LBA 1, and an entry
//! array naming the partitions. The header carries a CRC32 of itself and one of
//! the array, and both are checked here: a disk whose header does not match its
//! own checksum is a disk this firmware should not read files from, and saying
//! so is more useful than parsing whatever the bytes happen to say.

use alloc::vec;
use alloc::vec::Vec;

use crate::block::{BlockDevice, BlockError};
use crate::uefi::crc32;

/// The type GUID of an EFI System Partition.
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x93, 0xec, 0x93,
];
/// Windows' basic-data GUID, which some tools put on an ESP; recognised only
/// when the partition is also named `EFI`.
const BASIC_DATA_TYPE: [u8; 16] = [
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
];

/// Where the ESP is, in 512-byte-style logical blocks of its device.
#[derive(Clone, Copy, Debug)]
pub struct EspInfo {
    pub first_lba: u64,
    pub last_lba: u64,
    /// The partition's one-based number in the entry array.
    pub number: u32,
}

/// Finds the ESP on `device`, or `None` when there is no readable GPT.
///
/// The reference firmware's fallback is kept: if no entry claims to be an ESP,
/// the first defined partition is used, because a disk with one partition and
/// no type GUID is far more likely to be a hand-made boot disk than a mistake.
pub fn find_esp(device: &dyn BlockDevice) -> Option<EspInfo> {
    let block = device.block_size() as usize;
    if block < 512 {
        return None;
    }

    let mut header = vec![0u8; block];
    device.read(1, &mut header).ok()?;
    if &header[0..8] != b"EFI PART" {
        return None;
    }

    let header_size = read_u32(&header, 12)? as usize;
    if header_size < 92 || header_size > block {
        return None;
    }
    let stored_crc = read_u32(&header, 16)?;
    let mut without_crc = header[..header_size].to_vec();
    without_crc[16..20].fill(0);
    if crc32(&without_crc) != stored_crc {
        crate::println!("[gpt] the header's CRC32 does not match its contents");
        return None;
    }

    let entries_lba = read_u64(&header, 72)?;
    let count = read_u32(&header, 80)? as usize;
    let entry_size = read_u32(&header, 84)? as usize;
    let entries_crc = read_u32(&header, 88)?;
    // A GPT has 128 entries of 128 bytes; anything wildly different is not one.
    if entry_size < 128 || count == 0 || count > 256 {
        return None;
    }

    let mut entries = vec![0u8; count * entry_size];
    read_range(device, entries_lba * block as u64, &mut entries).ok()?;
    if crc32(&entries) != entries_crc {
        crate::println!("[gpt] the partition array's CRC32 does not match its contents");
        return None;
    }

    let mut fallback = None;
    for index in 0..count {
        let entry = &entries[index * entry_size..(index + 1) * entry_size];
        let kind = &entry[0..16];
        if kind.iter().all(|byte| *byte == 0) {
            continue;
        }
        let first_lba = read_u64(entry, 32)?;
        let last_lba = read_u64(entry, 40)?;
        let info = EspInfo {
            first_lba,
            last_lba,
            number: index as u32 + 1,
        };

        if kind == ESP_TYPE {
            return Some(info);
        }
        if kind == BASIC_DATA_TYPE && name_is(entry, "EFI") {
            return Some(info);
        }
        if fallback.is_none() {
            fallback = Some(info);
        }
    }
    fallback
}

/// Whether an entry's partition name is `expected`.
fn name_is(entry: &[u8], expected: &str) -> bool {
    let name = &entry[56..56 + 36 * 2];
    let mut units: Vec<u16> = Vec::with_capacity(36);
    for pair in name.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    let actual: alloc::string::String = units[..end]
        .iter()
        .map(|unit| char::from_u32(*unit as u32).unwrap_or('?'))
        .collect();
    actual == expected
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Reads an arbitrary byte range through whole-block reads: the GPT's entry
/// array is at a block boundary in every disk this firmware meets, but the
/// helper does not assume it.
fn read_range(device: &dyn BlockDevice, offset: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    let block = device.block_size() as u64;
    let mut done = 0usize;
    let mut sector = vec![0u8; block as usize];
    while done < buffer.len() {
        let position = offset + done as u64;
        let lba = position / block;
        let within = (position % block) as usize;
        device.read(lba, &mut sector)?;
        let take = (buffer.len() - done).min(block as usize - within);
        buffer[done..done + take].copy_from_slice(&sector[within..within + take]);
        done += take;
    }
    Ok(())
}
