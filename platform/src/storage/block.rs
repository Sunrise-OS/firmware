//! The block-device abstraction the storage stack is built on.
//!
//! Everything above the drivers - GPT, FAT, the Block I/O protocol - speaks this
//! and only this, so a disk can be virtio or anything else without the layers
//! above knowing.

use alloc::sync::Arc;

/// A failure from a block device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockError {
    /// The device did not answer, or answered with an error.
    Io,
    /// The request was outside the device's capacity.
    OutOfRange,
    /// The device is read-only.
    WriteProtected,
}

/// A block device: fixed-size blocks, addressed from zero.
pub trait BlockDevice: Send + Sync {
    /// The logical block size in bytes. Always a power of two.
    fn block_size(&self) -> u32;
    /// How many blocks the device has.
    fn block_count(&self) -> u64;
    /// Reads `buf.len()` bytes starting at `lba`; `buf.len()` is a multiple of
    /// the block size.
    fn read(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    /// Writes `buf.len()` bytes starting at `lba`.
    fn write(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;
    /// Whether the device accepts writes.
    fn is_writable(&self) -> bool {
        true
    }
}

/// A partition: a window onto part of a device, holding a share of it.
pub struct SubDevice {
    device: Arc<dyn BlockDevice>,
    first_lba: u64,
    block_count: u64,
}

impl SubDevice {
    pub fn new(device: Arc<dyn BlockDevice>, first_lba: u64, block_count: u64) -> Self {
        Self {
            device,
            first_lba,
            block_count,
        }
    }

    fn check(&self, lba: u64, bytes: usize) -> Result<(), BlockError> {
        let blocks = bytes as u64 / self.block_size() as u64;
        match lba.checked_add(blocks) {
            Some(end) if end <= self.block_count => Ok(()),
            _ => Err(BlockError::OutOfRange),
        }
    }
}

impl BlockDevice for SubDevice {
    fn block_size(&self) -> u32 {
        self.device.block_size()
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn read(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check(lba, buf.len())?;
        self.device.read(self.first_lba + lba, buf)
    }

    fn write(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check(lba, buf.len())?;
        self.device.write(self.first_lba + lba, buf)
    }

    fn is_writable(&self) -> bool {
        self.device.is_writable()
    }
}
