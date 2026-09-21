//! `EFI_BLOCK_IO_PROTOCOL` over a `BlockDevice`.
//!
//! Each instance is a heap object whose first field is the protocol, so the
//! protocol pointer an application calls through is also the pointer back to
//! the device. Instances are published for the life of the firmware and never
//! freed.

use alloc::sync::Arc;
use core::ffi::c_void;

use patina::standard::efi::{
    self, Boolean, Lba,
    protocols::block_io::{Media, Protocol},
};

use super::block::{BlockDevice, BlockError};

/// Revision 2 of the protocol: the one with `lowest_aligned_lba`.
const REVISION: u64 = 0x0002_0001;

#[repr(C)]
struct BlockIo {
    protocol: Protocol,
    media: Media,
    device: Arc<dyn BlockDevice>,
}

/// Builds a published Block I/O instance for `device`.
pub fn new(device: Arc<dyn BlockDevice>, media_id: u32, partition: bool) -> *mut c_void {
    let instance = crate::publish::firmware_lifetime(BlockIo {
        protocol: Protocol {
            revision: REVISION,
            media: core::ptr::null(),
            reset,
            read_blocks,
            write_blocks,
            flush_blocks,
        },
        media: Media {
            media_id,
            removable_media: false,
            media_present: true,
            logical_partition: partition,
            read_only: !device.is_writable(),
            write_caching: false,
            block_size: device.block_size(),
            io_align: 0,
            last_block: device.block_count().saturating_sub(1),
            lowest_aligned_lba: 0,
            logical_blocks_per_physical_block: 1,
            optimal_transfer_length_granularity: 0,
        },
        device,
    });
    // SAFETY: the published allocation remains valid for firmware lifetime.
    let instance = unsafe { &mut *instance.as_ptr() };
    instance.protocol.media = &instance.media;
    instance as *mut BlockIo as *mut c_void
}

extern "efiapi" fn reset(_this: *mut Protocol, _extended: Boolean) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn read_blocks(
    this: *mut Protocol,
    media_id: u32,
    lba: Lba,
    size: usize,
    buffer: *mut c_void,
) -> efi::Status {
    transfer(this, media_id, lba, size, buffer, false)
}

extern "efiapi" fn write_blocks(
    this: *mut Protocol,
    media_id: u32,
    lba: Lba,
    size: usize,
    buffer: *mut c_void,
) -> efi::Status {
    transfer(this, media_id, lba, size, buffer, true)
}

/// The specification's media, size and range checks, then the device.
fn transfer(
    this: *mut Protocol,
    media_id: u32,
    lba: Lba,
    size: usize,
    buffer: *mut c_void,
    writing: bool,
) -> efi::Status {
    if this.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: every Block I/O this driver publishes is a `BlockIo` whose first
    // field is the protocol.
    let instance = unsafe { &*(this as *const BlockIo) };
    let media = &instance.media;
    if media_id != media.media_id {
        return efi::Status::MEDIA_CHANGED;
    }
    if size == 0 {
        return efi::Status::SUCCESS;
    }
    if buffer.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    if size % media.block_size as usize != 0 {
        return efi::Status::BAD_BUFFER_SIZE;
    }
    let blocks = (size / media.block_size as usize) as u64;
    match lba.checked_add(blocks) {
        Some(end) if end <= media.last_block + 1 => {}
        _ => return efi::Status::INVALID_PARAMETER,
    }
    // SAFETY: the caller promises `size` bytes at `buffer`, readable for a write
    // and writable for a read.
    let bytes = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, size) };
    let result = if writing {
        instance.device.write(lba, bytes)
    } else {
        instance.device.read(lba, bytes)
    };
    match result {
        Ok(()) => efi::Status::SUCCESS,
        Err(BlockError::WriteProtected) => efi::Status::WRITE_PROTECTED,
        Err(BlockError::OutOfRange) => efi::Status::INVALID_PARAMETER,
        Err(BlockError::Io) => efi::Status::DEVICE_ERROR,
    }
}

extern "efiapi" fn flush_blocks(_this: *mut Protocol) -> efi::Status {
    efi::Status::SUCCESS
}
