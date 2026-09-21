//! `EFI_BLOCK_IO_PROTOCOL`, over the block-device abstraction.
//!
//! The protocol is what a boot loader or an operating system's EFI stub uses to
//! read a disk without knowing anything about virtio. It is also what an
//! application reads `Media` from to find out how big a device is and whether it
//! is removable - so the media structure is filled in from the device rather
//! than assumed.
//!
//! Each install owns a slot: the protocol and its media live in static storage,
//! because an application may hold the pointer for as long as it runs.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use alloc::sync::Arc;
use r_efi::base::{Boolean, Handle, Lba, Status};
use r_efi::protocols::block_io::{Media, Protocol};

use crate::block::{BlockDevice, BlockError};
use crate::uefi::handles;

/// How many block devices the firmware will publish.
const MAX_SLOTS: usize = 8;
/// `EFI_BLOCK_IO_PROTOCOL` revision 2: the one with `lowest_aligned_lba`.
const REVISION: u64 = 0x0002_0001;

struct Slot {
    used: bool,
    address: usize,
    /// The device, once a slot is in use. `MaybeUninit` because the published
    /// slots live in a `static` table and are written in place.
    device: MaybeUninit<alloc::sync::Arc<dyn BlockDevice>>,
}

const EMPTY: Slot = Slot {
    used: false,
    address: 0,
    device: MaybeUninit::uninit(),
};

/// The slots, and how many are in use.
static mut SLOTS: MaybeUninit<[Slot; MAX_SLOTS]> = MaybeUninit::uninit();
static mut SLOT_COUNT: usize = 0;

/// The device of a slot that is in use.
///
/// # Safety
///
/// `slot.used` must be true.
unsafe fn device_of(slot: &Slot) -> &alloc::sync::Arc<dyn BlockDevice> {
    // SAFETY: the caller guarantees the slot is in use, and `install` wrote the
    // device before marking it so.
    unsafe { &*slot.device.as_ptr() }
}

/// Prepares the slot table. Called once from `uefi::init`.
pub fn init() {
    // SAFETY: single-threaded bring-up; nothing has read the table yet.
    unsafe {
        (*core::ptr::addr_of_mut!(SLOTS)).write([EMPTY; MAX_SLOTS]);
        SLOT_COUNT = 0;
    }
}

/// The slot a protocol pointer came from.
fn slot_of(protocol: *mut Protocol) -> Option<&'static mut Slot> {
    if protocol.is_null() {
        return None;
    }
    let address = protocol as usize;
    let count = unsafe { core::ptr::read(core::ptr::addr_of!(SLOT_COUNT)) };
    for index in 0..count {
        // SAFETY: the index is inside the live range of the static table.
        let slot = unsafe { &mut *((core::ptr::addr_of_mut!(SLOTS)) as *mut Slot).add(index) };
        if slot.used && slot.address == address {
            return Some(slot);
        }
    }
    None
}

/// Publishes `device` as an EFI block device, returning the handle it lives on.
///
/// `removable` and `partition` describe the device to the application: a whole
/// disk is not a logical partition, and a disk the machine may swap out is
/// removable.
pub fn install(
    device: Arc<dyn BlockDevice>,
    removable: bool,
    partition: bool,
) -> Result<Handle, Status> {
    let count = unsafe { core::ptr::read(core::ptr::addr_of!(SLOT_COUNT)) };
    if count >= MAX_SLOTS {
        return Err(Status::OUT_OF_RESOURCES);
    }

    // The protocol and the media: both static, and both filled in once.
    let protocol =
        crate::uefi::mem::pages_for(r_efi::system::BOOT_SERVICES_DATA, 4096) as *mut Protocol;
    let media = crate::uefi::mem::pages_for(r_efi::system::BOOT_SERVICES_DATA, 4096) as *mut Media;
    if protocol.is_null() || media.is_null() {
        return Err(Status::OUT_OF_RESOURCES);
    }

    let block_size = device.block_size();
    let blocks = device.block_count();
    // SAFETY: the pages above are ours, zeroed, and large enough for both
    // structures.
    unsafe {
        (*media) = Media {
            media_id: count as u32 + 1,
            removable_media: removable,
            media_present: true,
            logical_partition: partition,
            read_only: !device.is_writable(),
            write_caching: true,
            block_size,
            io_align: 0,
            last_block: blocks.saturating_sub(1),
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 0,
        };
        (*protocol) = Protocol {
            revision: REVISION,
            media,
            reset: reset,
            read_blocks: read_blocks,
            write_blocks: write_blocks,
            flush_blocks: flush_blocks,
        };
    }

    // SAFETY: the slot index is inside the static table, and nothing else has
    // written this slot.
    unsafe {
        core::ptr::write(
            ((core::ptr::addr_of_mut!(SLOTS)) as *mut Slot).add(count),
            Slot {
                used: true,
                address: protocol as usize,
                device: MaybeUninit::new(device),
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(SLOT_COUNT), count + 1);
    }

    Ok(handles::install_new(
        &crate::uefi::BLOCK_IO_PROTOCOL_GUID,
        protocol as *mut c_void,
    ))
}

/// `Reset`: nothing to reset, so anything that asks gets a clean answer.
unsafe extern "efiapi" fn reset(_this: *mut Protocol, _extended_verification: Boolean) -> Status {
    Status::SUCCESS
}

/// `ReadBlocks`.
unsafe extern "efiapi" fn read_blocks(
    this: *mut Protocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    transfer(this, media_id, lba, buffer_size, buffer, false)
}

/// `WriteBlocks`.
unsafe extern "efiapi" fn write_blocks(
    this: *mut Protocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    transfer(this, media_id, lba, buffer_size, buffer, true)
}

/// The shared body of the two transfer calls: the specification's media id,
/// alignment, and range checks, then the device.
fn transfer(
    this: *mut Protocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
    writing: bool,
) -> Status {
    let Some(slot) = slot_of(this) else {
        return Status::INVALID_PARAMETER;
    };
    if buffer.is_null() || buffer_size == 0 {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the protocol is one of ours, so its media pointer is the one
    // `install` wrote.
    let media = unsafe { &*(*this).media };
    if media_id != media.media_id {
        return Status::INVALID_PARAMETER;
    }
    if buffer_size % media.block_size as usize != 0 {
        return Status::BAD_BUFFER_SIZE;
    }

    let blocks = buffer_size / media.block_size as usize;
    if lba + blocks as u64 > media.last_block + 1 {
        return Status::INVALID_PARAMETER;
    }

    // SAFETY: the caller promises `buffer_size` readable - or writable, when
    // writing - bytes at `buffer`.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, buffer_size) };
    // SAFETY: the slot came from the table and is in use.
    let device = unsafe { device_of(slot) };
    let result = if writing {
        device.write(lba, bytes)
    } else {
        device.read(lba, bytes)
    };
    match result {
        Ok(()) => Status::SUCCESS,
        Err(BlockError::WriteProtected) => Status::WRITE_PROTECTED,
        Err(BlockError::OutOfRange) => Status::INVALID_PARAMETER,
        Err(BlockError::Io) => Status::DEVICE_ERROR,
    }
}

/// `FlushBlocks`: this firmware's writes go straight to the device, but the
/// call has to succeed for a caller that flushes before it trusts what it wrote.
unsafe extern "efiapi" fn flush_blocks(_this: *mut Protocol) -> Status {
    Status::SUCCESS
}
