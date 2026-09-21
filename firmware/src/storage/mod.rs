//! Storage: the disks the firmware can boot from, and the partitions on them.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::block::BlockDevice;
use crate::drivers::{pci, virtio};

pub mod gpt;

/// Every disk the firmware can see, in bus order.
///
/// Discovery is a bus walk: each virtio function is offered to the block driver,
/// and the ones that answer become disks. A device that is not a block device,
/// or that fails to start, is skipped with a line on the console - a machine
/// with no disk at all is a machine that boots nothing, which is a normal
/// outcome and not an error to report as one.
pub fn discover() -> Vec<Arc<dyn BlockDevice>> {
    let mut disks: Vec<Arc<dyn BlockDevice>> = Vec::new();
    for device in pci::discover() {
        if !pci::is_virtio(&device) {
            continue;
        }
        if let Some(disk) = virtio::blk::VirtioBlk::open(&device, disks.len()) {
            let (bus, slot, func) = device.address();
            crate::println!(
                "[storage] {bus:02x}:{slot:02x}.{func} {}: {} sectors of {} bytes{}",
                disk.name(),
                disk.block_count(),
                disk.block_size(),
                if disk.is_writable() {
                    ""
                } else {
                    " (read-only)"
                }
            );
            disks.push(Arc::new(disk));
        }
    }
    disks
}
