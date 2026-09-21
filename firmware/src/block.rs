//! The block-device abstraction.
//!
//! Everything above the drivers - GPT, the filesystem, the EFI Block I/O
//! protocol - speaks this and only this, so a driver can be a virtio disk, an
//! SD card, or a test double without the layers above knowing.

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
    /// The device's logical block size in bytes. Always a power of two.
    fn block_size(&self) -> u32;
    /// How many blocks the device has.
    fn block_count(&self) -> u64;
    /// Reads `buf.len()` bytes starting at `lba`. `buf.len()` must be a multiple
    /// of the block size.
    fn read(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    /// Writes `buf.len()` bytes starting at `lba`.
    fn write(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;
    /// Whether the device accepts writes.
    fn is_writable(&self) -> bool {
        true
    }
    /// A short name for the boot log, e.g. `virtio-blk0`.
    fn name(&self) -> &'static str;
}

/// An owned view of part of a block device.
///
/// `Partition` borrows its device, which suits a caller walking disks in a loop;
/// the filesystem keeps its device for as long as it is mounted, so it needs
/// this instead: the same offset arithmetic, holding a share of the disk.
pub struct SubDevice {
    device: alloc::sync::Arc<dyn BlockDevice>,
    first_lba: u64,
    block_count: u64,
    number: u32,
}

impl SubDevice {
    pub fn new(
        device: alloc::sync::Arc<dyn BlockDevice>,
        first_lba: u64,
        block_count: u64,
        number: u32,
    ) -> Self {
        Self {
            device,
            first_lba,
            block_count,
            number,
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
        let blocks = buf.len() as u64 / self.block_size() as u64;
        if lba + blocks > self.block_count {
            return Err(BlockError::OutOfRange);
        }
        self.device.read(self.first_lba + lba, buf)
    }

    fn write(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        let blocks = buf.len() as u64 / self.block_size() as u64;
        if lba + blocks > self.block_count {
            return Err(BlockError::OutOfRange);
        }
        self.device.write(self.first_lba + lba, buf)
    }

    fn is_writable(&self) -> bool {
        self.device.is_writable()
    }

    fn name(&self) -> &'static str {
        "partition"
    }
}

/// The partition number this view was made for, for device paths.
impl SubDevice {
    pub fn number(&self) -> u32 {
        self.number
    }
}

/// A read-only view of part of a block device, as a partition is.
pub struct Partition<'a> {
    device: &'a dyn BlockDevice,
    /// First LBA of the partition.
    pub first_lba: u64,
    /// Number of blocks in the partition.
    pub block_count: u64,
    /// One-based GPT partition number, or 0 for a whole disk.
    pub number: u32,
}

impl<'a> Partition<'a> {
    pub fn new(device: &'a dyn BlockDevice, first_lba: u64, block_count: u64, number: u32) -> Self {
        Self {
            device,
            first_lba,
            block_count,
            number,
        }
    }
}

/// `Partition` presents the same `BlockDevice` interface, offset to the
/// partition's own first LBA, so the filesystem layer needs no separate path.
impl BlockDevice for Partition<'_> {
    fn block_size(&self) -> u32 {
        self.device.block_size()
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn read(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if lba + (buf.len() as u64 / self.block_size() as u64) > self.block_count {
            return Err(BlockError::OutOfRange);
        }
        self.device.read(self.first_lba + lba, buf)
    }

    fn write(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if lba + (buf.len() as u64 / self.block_size() as u64) > self.block_count {
            return Err(BlockError::OutOfRange);
        }
        self.device.write(self.first_lba + lba, buf)
    }

    fn is_writable(&self) -> bool {
        self.device.is_writable()
    }

    fn name(&self) -> &'static str {
        "partition"
    }
}
