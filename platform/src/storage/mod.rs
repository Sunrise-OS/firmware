//! The storage stack: PCI enumeration, virtio-blk, GPT, and FAT, published as
//! UEFI protocols.
//!
//! For each virtio disk the component installs, on its own handle, a device
//! path and `EFI_BLOCK_IO_PROTOCOL`; for each GPT partition on it, another
//! handle with the partition's device path and Block I/O; and on every
//! partition that holds a FAT volume, `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`. That is
//! the shape EDK2's partition and FAT drivers produce, which is what `LoadImage`
//! and boot loaders look for.
//!
//! Discovery is done once, when the component is dispatched: QEMU's `virt`
//! machine has no hot-plug to wait for.

mod block;
mod blockio;
pub(crate) mod device_path;
mod fat;
mod fs;
mod gpt;
pub(crate) mod pci;
mod simplefs;
pub(crate) mod virtio;

use alloc::sync::Arc;
use core::ffi::c_void;

use patina::component::{component, params::Handle};
use patina::error::{EfiError, Result};
use patina::standard::efi::{
    self, Guid,
    protocols::{block_io, device_path as efi_device_path, simple_file_system},
};
use patina::uefi::boot_services::{BootServices, StandardBootServices};

use block::{BlockDevice, SubDevice};

static DEVICE_PATH_GUID: Guid = efi_device_path::PROTOCOL_GUID;
static BLOCK_IO_GUID: Guid = block_io::PROTOCOL_GUID;
static SIMPLE_FILE_SYSTEM_GUID: Guid = simple_file_system::PROTOCOL_GUID;

/// Publishes the machine's disks, their partitions, and their FAT volumes.
pub struct Storage;

#[component]
impl Storage {
    fn entry_point(self, boot_services: StandardBootServices, image: Handle) -> Result<()> {
        // The virtio HAL allocates DMA pages through the raw table.
        crate::tables::init(&boot_services, *image).ok_or(EfiError::NotFound)?;

        let mut media_id = 1u32;
        let mut disks = 0;
        for device in pci::devices().iter().filter(|device| device.is_virtio()) {
            let Some(disk) = virtio::VirtioBlk::open(&device) else {
                continue;
            };
            let disk: Arc<dyn BlockDevice> = Arc::new(disk);
            log::info!(
                "storage: virtio-blk at {:02x}:{:02x}.{}: {} sectors{}",
                device.bus,
                device.slot,
                device.func,
                disk.block_count(),
                if disk.is_writable() {
                    ""
                } else {
                    " (read-only)"
                }
            );
            // SAFETY: the interfaces are leaked, so they outlive boot services.
            unsafe {
                let handle = install(
                    &boot_services,
                    None,
                    &DEVICE_PATH_GUID,
                    device_path::disk(device.slot, device.func).cast(),
                )?;
                install(
                    &boot_services,
                    Some(handle),
                    &BLOCK_IO_GUID,
                    blockio::new(Arc::clone(&disk), media_id, false),
                )?;
            }
            media_id += 1;
            disks += 1;

            let Some(partitions) = gpt::partitions(disk.as_ref()) else {
                log::info!("storage: no valid GPT on the disk");
                continue;
            };
            for partition in partitions {
                let view: Arc<dyn BlockDevice> = Arc::new(SubDevice::new(
                    Arc::clone(&disk),
                    partition.first_lba,
                    partition.blocks(),
                ));
                let path = device_path::partition(device.slot, device.func, &partition);
                // SAFETY: as above.
                let handle = unsafe {
                    let handle = install(&boot_services, None, &DEVICE_PATH_GUID, path.cast())?;
                    install(
                        &boot_services,
                        Some(handle),
                        &BLOCK_IO_GUID,
                        blockio::new(Arc::clone(&view), media_id, true),
                    )?;
                    handle
                };
                media_id += 1;
                let size = partition.blocks() * view.block_size() as u64;
                let Some(filesystem) = fat::mount(Arc::clone(&view)) else {
                    continue;
                };
                // SAFETY: as above.
                unsafe {
                    install(
                        &boot_services,
                        Some(handle),
                        &SIMPLE_FILE_SYSTEM_GUID,
                        simplefs::new(filesystem, size, view.block_size()),
                    )?;
                }
                log::info!(
                    "storage: partition {}{} ({} MiB) published as a FAT volume",
                    partition.number,
                    if partition.is_esp() { " (ESP)" } else { "" },
                    size >> 20
                );
            }
        }
        if disks == 0 {
            log::info!("storage: no virtio block devices");
        }
        Ok(())
    }
}

/// Installs one protocol interface, logging a failure.
///
/// # Safety
///
/// `interface` must be the structure `guid` names and outlive boot services.
unsafe fn install(
    boot_services: &StandardBootServices,
    handle: Option<efi::Handle>,
    guid: &'static Guid,
    interface: *mut c_void,
) -> Result<efi::Handle> {
    // SAFETY: forwarded from the caller.
    unsafe { boot_services.install_protocol_interface_unchecked(handle, guid, interface) }.map_err(
        |status| {
            log::error!("storage: installing a protocol failed: {status:?}");
            EfiError::from(status)
        },
    )
}
