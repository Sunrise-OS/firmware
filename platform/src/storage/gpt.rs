//! GPT: the partitions on a disk.
//!
//! The header at LBA 1 carries a CRC32 of itself and of the entry array, and
//! both are checked: a disk whose header does not match its own checksum is one
//! to leave alone rather than to read files from.

use alloc::vec;
use alloc::vec::Vec;

use patina::crc32::calculate_crc32;

use super::block::BlockDevice;

/// The type GUID of an EFI System Partition, in on-disk byte order.
pub const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x93, 0xec, 0x93,
];

/// One defined partition.
#[derive(Clone, Copy, Debug)]
pub struct Partition {
    /// One-based index in the entry array: the number a device path carries.
    pub number: u32,
    pub first_lba: u64,
    pub last_lba: u64,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
}

impl Partition {
    pub fn blocks(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }

    pub fn is_esp(&self) -> bool {
        self.type_guid == ESP_TYPE
    }
}

/// The partitions on `device`, or `None` when it has no valid GPT.
pub fn partitions(device: &dyn BlockDevice) -> Option<Vec<Partition>> {
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
    if !(92..=block).contains(&header_size) {
        return None;
    }
    let stored_crc = read_u32(&header, 16)?;
    let mut without_crc = header[..header_size].to_vec();
    without_crc[16..20].fill(0);
    if calculate_crc32(&without_crc) != stored_crc {
        log::warn!("gpt: the header's CRC32 does not match its contents");
        return None;
    }

    let entries_lba = read_u64(&header, 72)?;
    let count = read_u32(&header, 80)? as usize;
    let entry_size = read_u32(&header, 84)? as usize;
    let entries_crc = read_u32(&header, 88)?;
    if entry_size < 128 || count == 0 || count > 256 {
        return None;
    }
    let mut entries = vec![0u8; (count * entry_size).div_ceil(block) * block];
    device.read(entries_lba, &mut entries).ok()?;
    let entries = &entries[..count * entry_size];
    if calculate_crc32(entries) != entries_crc {
        log::warn!("gpt: the partition array's CRC32 does not match its contents");
        return None;
    }

    let mut found = Vec::new();
    for (index, entry) in entries.chunks_exact(entry_size).enumerate() {
        let type_guid: [u8; 16] = entry[0..16].try_into().ok()?;
        if type_guid == [0; 16] {
            continue;
        }
        let first_lba = read_u64(entry, 32)?;
        let last_lba = read_u64(entry, 40)?;
        if last_lba < first_lba || last_lba >= device.block_count() {
            continue;
        }
        found.push(Partition {
            number: index as u32 + 1,
            first_lba,
            last_lba,
            type_guid,
            unique_guid: entry[16..32].try_into().ok()?,
        });
    }
    Some(found)
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
