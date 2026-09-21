//! The EFI variable store.
//!
//! Variables live in a fixed RAM window. A record is a state word, the
//! attributes, the vendor GUID, then the name and data; records are kept sorted
//! by (name, GUID), which is also the order `GetNextVariableName` must hand
//! them out in.
//!
//! The machine this firmware runs on has no writable non-volatile storage
//! attached, so a variable marked `NON_VOLATILE` survives in this store for the
//! life of the boot and not beyond. `QueryVariableInfo` reports what the store
//! can hold; persistence across a reset needs a flash device, which is the one
//! thing this store does not have.

use core::mem::MaybeUninit;

use r_efi::base::{Char16, Guid, Status};
use r_efi::system::{VARIABLE_BOOTSERVICE_ACCESS, VARIABLE_NON_VOLATILE, VARIABLE_RUNTIME_ACCESS};

use crate::uefi;

/// The store's size. Sixty-four kilobytes is what the reference firmware uses
/// and comfortably holds a boot manager's `Boot####` entries.
const STORE_SIZE: usize = 64 * 1024;
/// The largest variable (name and data) the store will accept.
const MAX_VARIABLE_SIZE: usize = 1024;
/// How many variables fit at worst: the store's minimum record overhead.
const MAX_VARIABLES: usize = 64;

/// Record header, before the name and data.
#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    state: u32,
    attributes: u32,
    guid: Guid,
    name_bytes: u32,
    data_bytes: u32,
}

const STATE_VALID: u32 = 1;
const HEADER_SIZE: usize = core::mem::size_of::<Header>();

static mut STORE: MaybeUninit<[u8; STORE_SIZE]> = MaybeUninit::uninit();
/// The offset just past the last record, in bytes.
static mut USED: usize = 0;

/// Prepares an empty store. Called once from bring-up.
pub fn init() {
    // SAFETY: single-threaded bring-up; nothing has read the store yet.
    unsafe {
        let bytes = (*core::ptr::addr_of_mut!(STORE)).write([0xff; STORE_SIZE]);
        bytes.write_word(0, MAGIC);
        USED = HEADER_SIZE; // records start after the magic
    }
}

const MAGIC: u32 = 0x3153_5657; // "WVS1", little-endian

/// Helper: word access into the store.
trait StoreWord {
    unsafe fn write_word(&mut self, offset: usize, value: u32);
    unsafe fn read_word(&self, offset: usize) -> u32;
}

impl StoreWord for [u8; STORE_SIZE] {
    unsafe fn write_word(&mut self, offset: usize, value: u32) {
        // SAFETY: the caller passes an offset inside the store.
        self[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    unsafe fn read_word(&self, offset: usize) -> u32 {
        // SAFETY: the caller passes an offset inside the store.
        u32::from_le_bytes(self[offset..offset + 4].try_into().unwrap())
    }
}

/// Where a record begins, as an offset into the store.
struct Record {
    offset: usize,
}

impl Record {
    fn header(&self) -> Header {
        // SAFETY: `offset` is a record boundary.
        unsafe {
            let bytes = (*core::ptr::addr_of!(STORE)).assume_init_ref();
            Header {
                state: bytes.read_word(self.offset),
                attributes: bytes.read_word(self.offset + 4),
                guid: core::ptr::read_unaligned(
                    (bytes.as_ptr().add(self.offset + 8)) as *const Guid,
                ),
                name_bytes: bytes.read_word(self.offset + 8 + 16),
                data_bytes: bytes.read_word(self.offset + 8 + 16 + 4),
            }
        }
    }

    fn name(&self) -> alloc::vec::Vec<Char16> {
        let header = self.header();
        // SAFETY: `offset` is a record boundary and the lengths came from it.
        unsafe {
            let bytes = (*core::ptr::addr_of!(STORE)).assume_init_ref();
            let start = self.offset + HEADER_SIZE;
            let end = start + header.name_bytes as usize;
            core::slice::from_raw_parts(
                bytes.as_ptr().add(start) as *const Char16,
                header.name_bytes as usize / 2,
            )
            .to_vec()
        }
    }

    fn data(&self) -> alloc::vec::Vec<u8> {
        let header = self.header();
        // SAFETY: as `name`.
        unsafe {
            let bytes = (*core::ptr::addr_of!(STORE)).assume_init_ref();
            let start = self.offset + HEADER_SIZE + header.name_bytes as usize;
            bytes[start..start + header.data_bytes as usize].to_vec()
        }
    }

    /// The record's length, padded to a 4-byte boundary.
    fn size(&self) -> usize {
        let header = self.header();
        (HEADER_SIZE + header.name_bytes as usize + header.data_bytes as usize + 3) & !3
    }
}

/// The first record, if the store has one.
fn first() -> Option<Record> {
    // SAFETY: `init` ran.
    let used = unsafe { USED };
    if used <= HEADER_SIZE {
        return None;
    }
    let record = Record {
        offset: HEADER_SIZE,
    };
    (record.header().state == STATE_VALID).then_some(record)
}

/// The record after `record`, in storage - and therefore sorted - order.
fn next(record: &Record) -> Option<Record> {
    // SAFETY: `record.offset` is a record boundary.
    let used = unsafe { USED };
    let following = record.offset + record.size();
    if following + HEADER_SIZE > used {
        return None;
    }
    let candidate = Record { offset: following };
    (candidate.header().state == STATE_VALID).then_some(candidate)
}

/// Finds the record for `(name, guid)`.
fn find(name: &[Char16], guid: &Guid) -> Option<Record> {
    let mut record = first()?;
    loop {
        let header = record.header();
        if &header.guid == guid && record.name() == name {
            return Some(record);
        }
        record = next(&record)?;
    }
}

/// `GetVariable`.
pub fn get(name: &[Char16], guid: &Guid) -> Option<(u32, alloc::vec::Vec<u8>)> {
    let record = find(name, guid)?;
    Some((record.header().attributes, record.data()))
}

/// `SetVariable`. A zero-length value deletes the variable, as the
/// specification requires.
pub fn set(name: &[Char16], guid: &Guid, attributes: u32, data: &[u8]) -> Status {
    if name.is_empty() {
        return Status::INVALID_PARAMETER;
    }
    let name_bytes = name.len() * 2;
    if name_bytes + data.len() > MAX_VARIABLE_SIZE {
        return Status::OUT_OF_RESOURCES;
    }
    let wanted = (HEADER_SIZE + name_bytes + data.len() + 3) & !3;

    if data.is_empty() {
        // Delete: drop the record by moving the ones after it down.
        return match find(name, guid) {
            Some(record) => {
                // SAFETY: as above; `record` is a live boundary.
                unsafe {
                    let bytes = (*core::ptr::addr_of_mut!(STORE)).assume_init_mut();
                    let from = record.offset + record.size();
                    let to = record.offset;
                    let used = USED;
                    bytes.copy_within(from..used, to);
                    USED = used - (from - to);
                }
                Status::SUCCESS
            }
            None => Status::NOT_FOUND,
        };
    }

    // Overwrite in place when the record is the same size or smaller, so a
    // variable an application refreshes does not move.
    if let Some(record) = find(name, guid) {
        let header = record.header();
        if header.attributes == attributes && wanted <= record.size() {
            // SAFETY: `record` is a live boundary and the store has room.
            unsafe {
                let bytes = (*core::ptr::addr_of_mut!(STORE)).assume_init_mut();
                let start = record.offset + HEADER_SIZE;
                bytes[start..start + name_bytes].copy_from_slice(&core::slice::from_raw_parts(
                    name.as_ptr() as *const u8,
                    name_bytes,
                ));
                bytes[start + name_bytes..start + name_bytes + data.len()].copy_from_slice(data);
            }
            return Status::SUCCESS;
        }
    }

    // Insert, keeping records sorted by (name, GUID), which is the order the
    // iteration API must present.
    // SAFETY: `init` ran; the write stays inside the store.
    unsafe {
        let bytes = (*core::ptr::addr_of_mut!(STORE)).assume_init_mut();
        let used = USED;
        if used + wanted > STORE_SIZE {
            return Status::OUT_OF_RESOURCES;
        }

        // Find the insertion point.
        let mut position = HEADER_SIZE;
        while position + HEADER_SIZE <= used {
            let record = Record { offset: position };
            let header = record.header();
            let record_name = record.name();
            if name < record_name.as_slice() || (record_name == name && *guid < header.guid) {
                break;
            }
            position += record.size();
        }

        // Make room, then write the new record in.
        bytes.copy_within(position..used, position + wanted);
        let record = Header {
            state: STATE_VALID,
            attributes,
            guid: *guid,
            name_bytes: name_bytes as u32,
            data_bytes: data.len() as u32,
        };
        core::ptr::write_unaligned(bytes.as_mut_ptr().add(position) as *mut Header, record);
        let start = position + HEADER_SIZE;
        bytes[start..start + name_bytes].copy_from_slice(core::slice::from_raw_parts(
            name.as_ptr() as *const u8,
            name_bytes,
        ));
        bytes[start + name_bytes..start + name_bytes + data.len()].copy_from_slice(data);
        for byte in start + name_bytes + data.len()..position + wanted {
            bytes[byte] = 0;
        }
        USED = used + wanted;
    }
    Status::SUCCESS
}

/// `GetNextVariableName`: walks the store in order. A null terminator in
/// `name[0]` means "start at the beginning".
pub fn next_name(size: *mut usize, name: *mut Char16, guid: *mut Guid) -> Status {
    if size.is_null() || name.is_null() || guid.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the out-parameters are writable.
    let starting = unsafe { *name } == 0;
    let previous: alloc::vec::Vec<Char16> = if starting {
        alloc::vec::Vec::new()
    } else {
        let mut units = 0usize;
        while unsafe { *name.add(units) } != 0 {
            units += 1;
            if units > MAX_VARIABLE_SIZE {
                return Status::INVALID_PARAMETER;
            }
        }
        unsafe { core::slice::from_raw_parts(name, units).to_vec() }
    };
    let previous_guid = unsafe { *guid };

    let mut record = match first() {
        Some(record) => record,
        None => return Status::NOT_FOUND,
    };

    // Skip past the variable the caller just saw.
    if !starting {
        loop {
            let header = record.header();
            if &header.guid == &previous_guid && record.name() == previous {
                match next(&record) {
                    Some(following) => record = following,
                    None => return Status::NOT_FOUND,
                }
                break;
            }
            match next(&record) {
                Some(following) => record = following,
                None => return Status::NOT_FOUND,
            }
        }
    }

    let header = record.header();
    let record_name = record.name();
    let bytes = (record_name.len() + 1) * 2;
    // SAFETY: the caller's buffer holds `*size` bytes.
    if unsafe { *size } < bytes {
        // SAFETY: the out-parameters are writable.
        unsafe { *size = bytes };
        return Status::BUFFER_TOO_SMALL;
    }
    // SAFETY: the buffer is big enough, as checked.
    unsafe {
        core::ptr::copy_nonoverlapping(
            record_name.as_ptr() as *const u8,
            name as *mut u8,
            record_name.len() * 2,
        );
        *name.add(record_name.len()) = 0;
        *guid = header.guid;
        *size = bytes;
    }
    Status::SUCCESS
}

/// `QueryVariableInfo`.
pub fn query_info(
    max_storage: *mut u64,
    remaining_storage: *mut u64,
    max_variable_size: *mut u64,
) -> Status {
    if max_storage.is_null() || remaining_storage.is_null() || max_variable_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the out-parameters are writable.
    unsafe {
        let used = USED;
        *max_storage = STORE_SIZE as u64;
        *remaining_storage = (STORE_SIZE - used) as u64;
        *max_variable_size = MAX_VARIABLE_SIZE as u64;
    }
    Status::SUCCESS
}

/// How many variables the store currently holds, for the boot log.
pub fn count() -> usize {
    let mut found = 0;
    let mut record = first();
    while let Some(current) = record {
        found += 1;
        record = next(&current);
    }
    found
}

/// Whether the store accepts writes of the given attribute combination, which
/// the reference implementation checks before doing anything.
pub fn attributes_are_valid(attributes: u32) -> bool {
    const KNOWN: u32 =
        VARIABLE_NON_VOLATILE | VARIABLE_BOOTSERVICE_ACCESS | VARIABLE_RUNTIME_ACCESS;
    attributes != 0 && attributes & !KNOWN == 0
}

/// Kept so `uefi` can reference the store's limits when reporting.
pub const VARIABLE_LIMIT: usize = MAX_VARIABLES;
