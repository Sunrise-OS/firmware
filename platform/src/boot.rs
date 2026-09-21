//! The boot-device selection for the QEMU virt platform.
//!
//! BDS takes the removable-media fallback path, `\EFI\BOOT\BOOTAA64.EFI`, on each
//! volume the storage component published, in the order the handle database
//! lists them, and starts the first that loads. The image is loaded by device
//! path rather than from a buffer, so Patina's `LoadImage` reads the file
//! through the volume's Simple File System and records the volume as the
//! image's `DeviceHandle` - which is how a boot loader finds the disk it came
//! from. There are no variable services yet, so there is no `BootOrder` to
//! honour.

use core::{
    ffi::c_void,
    mem::MaybeUninit,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use patina::component::component;
use patina::error::Result;
use patina::pi::protocol::bds::{BdsProtocol, PROTOCOL_GUID};
use patina::standard::efi::{self, Guid};
use patina::uefi::boot_services::{
    BootServices, StandardBootServices, protocol_handler::HandleSearchType,
};

/// The removable-media fallback every bootable ESP carries.
const FALLBACK_PATH: &str = "\\EFI\\BOOT\\BOOTAA64.EFI";

/// The protocol GUID as a static, which is what installing an interface wants.
static BDS_GUID: Guid = PROTOCOL_GUID.into_inner();
static LOADED_IMAGE_GUID: Guid = efi::protocols::loaded_image::PROTOCOL_GUID;
static SIMPLE_FILE_SYSTEM_GUID: Guid = efi::protocols::simple_file_system::PROTOCOL_GUID;
static DEVICE_PATH_GUID: Guid = efi::protocols::device_path::PROTOCOL_GUID;
/// Arguments for q1n1's XNU handoff. Non-q1n1 EFI applications ignore them.
static Q1N1_OPTIONS: [u16; 6] = [
    '-' as u16, '-' as u16, 'x' as u16, 'n' as u16, 'u' as u16, 0,
];
static mut BOOT_SERVICES: MaybeUninit<StandardBootServices> = MaybeUninit::uninit();
static BOOT_SERVICES_READY: AtomicBool = AtomicBool::new(false);

static BDS: BdsProtocol = BdsProtocol { entry: boot };

extern "efiapi" fn boot(_this: *mut BdsProtocol) {
    log::info!("BDS: beginning boot selection");
    if !BOOT_SERVICES_READY.load(Ordering::Acquire) {
        log::error!("BDS: Boot Services were not captured during dispatch");
        park();
    }
    // SAFETY: Boot::entry_point initializes this once before the DXE dispatcher
    // enters BDS, and the value is immutable for the rest of the boot.
    let boot_services = unsafe { (*core::ptr::addr_of!(BOOT_SERVICES)).assume_init_ref() };

    // The DXE core's image is the parent of what BDS loads.
    let parent = match boot_services
        .locate_handle_buffer(HandleSearchType::ByProtocol(&LOADED_IMAGE_GUID))
    {
        Ok(handles) if !handles.is_empty() => handles[0],
        _ => {
            log::error!("BDS: no loaded-image parent handle");
            park();
        }
    };
    let volumes = match boot_services
        .locate_handle_buffer(HandleSearchType::ByProtocol(&SIMPLE_FILE_SYSTEM_GUID))
    {
        Ok(volumes) => volumes,
        Err(_) => {
            log::info!("BDS: no file system to boot from; halting");
            park();
        }
    };

    for &volume in volumes.iter() {
        // SAFETY: the handle came from the handle database, and the device path
        // interface is a well-formed path the storage component installed.
        let path =
            match unsafe { boot_services.handle_protocol_unchecked(volume, &DEVICE_PATH_GUID) } {
                Ok(path) => unsafe {
                    crate::storage::device_path::append_file(
                        path as *const efi::protocols::device_path::Protocol,
                        FALLBACK_PATH,
                    )
                },
                Err(_) => continue,
            };
        let path_pointer =
            NonNull::new(path.as_ptr() as *mut efi::protocols::device_path::Protocol);
        let image = match boot_services.load_image(true, parent, path_pointer, None) {
            Ok(image) => image,
            Err(status) => {
                log::info!("BDS: {FALLBACK_PATH} on volume {volume:p}: {status:?}");
                continue;
            }
        };
        // Pass the explicit XNU boot option. The buffer is static because
        // LoadedImage retains its pointer throughout StartImage.
        match unsafe { boot_services.handle_protocol_unchecked(image, &LOADED_IMAGE_GUID) } {
            Ok(loaded) => {
                let loaded = loaded as *mut efi::protocols::loaded_image::Protocol;
                unsafe {
                    (*loaded).load_options_size =
                        (Q1N1_OPTIONS.len() * core::mem::size_of::<u16>()) as u32;
                    (*loaded).load_options = Q1N1_OPTIONS.as_ptr() as *mut c_void;
                }
            }
            Err(status) => {
                log::error!(
                    "BDS: loaded-image protocol unavailable for the boot image: {status:?}"
                );
                park();
            }
        }
        log::info!("BDS: starting {FALLBACK_PATH} from volume {volume:p}");
        match boot_services.start_image(image) {
            Ok(()) => log::info!("BDS: the boot image returned successfully"),
            Err((status, _exit_data)) => log::error!("BDS: the boot image returned {status:?}"),
        }
        // An image that returns is a boot that did not happen; there is no boot
        // manager menu to return to, so stop here with the log intact.
        park();
    }
    log::info!("BDS: no volume carries {FALLBACK_PATH}; halting");
    park();
}

fn park() -> ! {
    loop {
        // SAFETY: waiting for an interrupt has no effect on memory; the timer
        // keeps waking the core, which goes straight back to sleep.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }
    }
}

/// Installs the BDS protocol. The core calls it once dispatch is finished.
pub struct Boot;

#[component]
impl Boot {
    fn entry_point(self, boot_services: StandardBootServices) -> Result<()> {
        // SAFETY: this component is dispatched once, and the services object
        // retains a pointer to Patina's firmware-lifetime boot-services table.
        unsafe {
            (*core::ptr::addr_of_mut!(BOOT_SERVICES)).write(boot_services.clone());
        }
        BOOT_SERVICES_READY.store(true, Ordering::Release);

        // SAFETY: `BDS` is a static of the structure the GUID names, and it
        // outlives the boot.
        unsafe {
            boot_services.install_protocol_interface_unchecked(
                None,
                &BDS_GUID,
                &BDS as *const BdsProtocol as *mut c_void,
            )?;
        }
        Ok(())
    }
}
