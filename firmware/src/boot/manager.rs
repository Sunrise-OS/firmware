//! The boot manager: finding the boot image, loading it, and running it.
//!
//! The path is the one a firmware walks: enumerate disks, find the ESP, mount
//! its filesystem, then take the first entry of `BootOrder` that resolves - or,
//! when there is no boot order at all, the removable-media fallback path
//! `\EFI\BOOT\BOOTAA64.EFI`. The image is loaded, given a handle carrying
//! `EFI_LOADED_IMAGE_PROTOCOL`, and entered with the handle and the system table
//! in `x0` and `x1`, which is the ABI every EFI application expects.
//!
//! Images live in a small static table: the firmware owns them, they outlive the
//! `StartImage` call, and nothing frees them - an image that returns is a boot
//! that failed, and the next candidate is tried.

use alloc::sync::Arc;
use alloc::vec::Vec;

use r_efi::base::{Boolean, Char16, Handle, Status};
use r_efi::protocols::device_path;
use r_efi::protocols::loaded_image;
use r_efi::system::SystemTable;

use crate::block::{BlockDevice, SubDevice};
use crate::fs::{FileNode, FileSystem};
use crate::storage::gpt;
use crate::uefi::{self, device_path as dp, handles, mem};

/// The removable-media fallback, which every ESP that can boot has.
const FALLBACK_PATH: &str = "\\EFI\\BOOT\\BOOTAA64.EFI";
/// How many images the firmware can have in flight: the boot manager's own, plus
/// whatever an application loads.
const MAX_IMAGES: usize = 4;
/// The load option's `LOAD_OPTION_ACTIVE` bit.
const LOAD_OPTION_ACTIVE: u32 = 0x1;
/// Room for a device path the firmware builds for a volume: a vendor node plus
/// the terminator.
const DEVICE_PATH_BYTES: usize = 4 + 16 + 4;

/// One loaded image.
#[derive(Clone, Copy)]
struct Image {
    used: bool,
    handle: Handle,
    entry: usize,
    protocol: *mut loaded_image::Protocol,
    device_path: *mut device_path::Protocol,
}

const EMPTY_IMAGE: Image = Image {
    used: false,
    handle: core::ptr::null_mut(),
    entry: 0,
    protocol: core::ptr::null_mut(),
    device_path: core::ptr::null_mut(),
};

static mut IMAGES: core::mem::MaybeUninit<[Image; MAX_IMAGES]> = core::mem::MaybeUninit::uninit();
static mut IMAGE_COUNT: usize = 0;

/// Prepares the image table. Called once from `uefi::init`.
pub fn init() {
    // SAFETY: single-threaded bring-up; nothing has read the table yet.
    unsafe {
        (*core::ptr::addr_of_mut!(IMAGES)).write([EMPTY_IMAGE; MAX_IMAGES]);
        IMAGE_COUNT = 0;
    }
}

/// The image table, as a pointer: the entries are static state.
fn images() -> *mut Image {
    (core::ptr::addr_of_mut!(IMAGES)) as *mut Image
}

fn image_count() -> usize {
    // SAFETY: written only by `remember`, read here.
    unsafe { core::ptr::read(core::ptr::addr_of!(IMAGE_COUNT)) }
}

/// Registers a loaded image and returns the protocol structure for it.
fn remember(
    handle: Handle,
    entry: usize,
    image_base: usize,
    image_size: u64,
) -> *mut loaded_image::Protocol {
    let count = image_count();
    assert!(count < MAX_IMAGES, "uefi: out of image slots");

    let protocol = mem::pages_for(r_efi::system::LOADER_DATA, 4096) as *mut loaded_image::Protocol;
    assert!(
        !protocol.is_null(),
        "uefi: out of memory for a loaded image"
    );

    let device_path =
        mem::pages_for(r_efi::system::LOADER_DATA, DEVICE_PATH_BYTES) as *mut device_path::Protocol;
    assert!(
        !device_path.is_null(),
        "uefi: out of memory for a device path"
    );
    // The end node: a bare terminator, which is a valid file path of its own.
    // SAFETY: the pages are ours, and a device path node is four bytes here.
    unsafe {
        (*device_path).r#type = dp::END_DEVICE_PATH;
        (*device_path).sub_type = dp::END_DEVICE_PATH_INSTANCE;
        (*device_path).length = [0x04, 0x00];
        (*protocol) = loaded_image::Protocol {
            revision: 0x1000,
            parent_handle: uefi::image_handle(),
            system_table: uefi::system_table(),
            device_handle: core::ptr::null_mut(),
            file_path: device_path,
            reserved: core::ptr::null_mut(),
            load_options_size: 0,
            load_options: core::ptr::null_mut(),
            image_base: image_base as *mut core::ffi::c_void,
            image_size,
            image_code_type: r_efi::system::LOADER_CODE,
            image_data_type: r_efi::system::LOADER_DATA,
            unload: None,
        };
    }
    // SAFETY: the slot index is inside the static table.
    unsafe {
        core::ptr::write(
            images().add(count),
            Image {
                used: true,
                handle,
                entry,
                protocol,
                device_path,
            },
        );
        core::ptr::write(core::ptr::addr_of_mut!(IMAGE_COUNT), count + 1);
    }
    protocol
}

/// The image registered for `handle`, if there is one.
fn image_for(handle: Handle) -> Option<Image> {
    let count = image_count();
    for index in 0..count {
        // SAFETY: the index is inside the live range of the static table.
        let image = unsafe { core::ptr::read(images().add(index)) };
        if image.used && image.handle == handle {
            return Some(image);
        }
    }
    None
}

/// Points an image at its file, and at the volume it came from.
fn set_file(image: *mut loaded_image::Protocol, path: &str, device: Handle) {
    let units: Vec<Char16> = path.encode_utf16().collect();
    // A file-path node is a four-byte header plus the name, and the path needs
    // somewhere to live for as long as the image does.
    let bytes = 4 + units.len() * 2 + 4;
    let storage = mem::pages_for(r_efi::system::LOADER_DATA, bytes.max(4096));
    assert!(!storage.is_null(), "uefi: out of memory for a file path");
    // SAFETY: the pages are ours and are at least `bytes` long.
    let total =
        unsafe { dp::write_file_path(storage, &units, bytes).expect("device path fits the pages") };
    unsafe {
        (*image).file_path = storage as *mut device_path::Protocol;
        (*image).device_handle = device;
        let _ = total;
    }
}

/// Gives an image its load options: the command line an operating system's EFI
/// stub, or an application, reads.
fn set_load_options(image: *mut loaded_image::Protocol, options: &[u8]) {
    if options.is_empty() {
        return;
    }
    let storage = mem::pages_for(r_efi::system::LOADER_DATA, options.len().max(4096));
    assert!(!storage.is_null(), "uefi: out of memory for load options");
    // SAFETY: the pages are at least `options.len()` long.
    unsafe {
        core::ptr::copy_nonoverlapping(options.as_ptr(), storage, options.len());
        (*image).load_options = storage as *mut core::ffi::c_void;
        (*image).load_options_size = options.len() as u32;
    }
}

/// `LoadImage`: loads an image from a buffer, or from a file on a volume the
/// firmware already mounted.
pub unsafe extern "efiapi" fn load_image(
    _boot_policy: Boolean,
    _parent_image_handle: Handle,
    _device_path: *mut device_path::Protocol,
    source_buffer: *mut core::ffi::c_void,
    source_size: usize,
    image_handle: *mut Handle,
) -> Status {
    if image_handle.is_null() || source_buffer.is_null() || source_size == 0 {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller promises `source_size` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(source_buffer as *const u8, source_size) };
    let loaded = match crate::loader::pe::load(bytes) {
        Ok(loaded) => loaded,
        Err(error) => {
            crate::println!("[boot] LoadImage: {error:?}");
            return Status::LOAD_ERROR;
        }
    };

    let handle = handles::create_handle();
    let protocol = remember(handle, loaded.entry, loaded.base, loaded.size as u64);
    let status = unsafe {
        handles::install_on(
            handle,
            &uefi::LOADED_IMAGE_PROTOCOL_GUID,
            protocol as *mut core::ffi::c_void,
        )
    };
    if status != Status::SUCCESS {
        return status;
    }
    unsafe {
        handles::install_on(
            handle,
            &uefi::DEVICE_PATH_PROTOCOL_GUID,
            (*protocol).file_path as *mut core::ffi::c_void,
        )
    };
    // SAFETY: the out-parameter is writable.
    unsafe { *image_handle = handle };
    Status::SUCCESS
}

/// `StartImage`: enters the image and returns what it returned.
pub unsafe extern "efiapi" fn start_image(
    image_handle: Handle,
    _exit_data_size: *mut usize,
    _exit_data: *mut *mut Char16,
) -> Status {
    let image = match image_for(image_handle) {
        Some(image) => image,
        None => return Status::INVALID_PARAMETER,
    };
    // SAFETY: the entry point is an AArch64 EFI image's entry, whose ABI is
    // exactly this signature (`efiapi` is the C ABI here).
    let entry: extern "efiapi" fn(Handle, *mut SystemTable) -> Status =
        unsafe { core::mem::transmute(image.entry) };
    entry(image_handle, uefi::system_table())
}

/// `UnloadImage`: images are not reclaimed. An image that loaded another and
/// wants the memory back would have to leave the firmware's tables pointing at
/// it, so this firmware keeps them; the memory is at most a few megabytes and
/// the machine is a boot away from being reset.
pub unsafe extern "efiapi" fn unload_image(_image_handle: Handle) -> Status {
    Status::UNSUPPORTED
}

/// Boots the machine: finds an ESP, resolves a boot path, loads it, and runs it.
/// Returns whether an image ran.
pub fn boot() -> bool {
    let disks = crate::storage::discover();
    if disks.is_empty() {
        crate::println!("[boot] no disks");
        return false;
    }

    for disk in disks {
        let Some(esp) = gpt::find_esp(disk.as_ref()) else {
            crate::println!("[boot] {}: no GPT ESP", disk.name());
            continue;
        };
        crate::println!(
            "[boot] {}: ESP at LBA {}..{} (partition {})",
            disk.name(),
            esp.first_lba,
            esp.last_lba,
            esp.number
        );

        let blocks = esp.last_lba - esp.first_lba + 1;
        let partition: Arc<dyn BlockDevice> = Arc::new(SubDevice::new(
            Arc::clone(&disk),
            esp.first_lba,
            blocks,
            esp.number,
        ));
        let Some(filesystem) = crate::fat::mount(Arc::clone(&partition)) else {
            continue;
        };

        // Publish the storage stack: the whole disk, the partition on it, and
        // the filesystem over the partition. An application that walks the
        // handle database finds a volume to read, and one that walks device
        // paths finds where it sits.
        publish_storage(
            &disk,
            Arc::clone(&partition),
            Arc::clone(&filesystem),
            esp.number,
        );

        let Some((path, options)) = choose_boot_image(filesystem.as_ref()) else {
            crate::println!("[boot] no boot image on {}", disk.name());
            continue;
        };
        let Some(node) = filesystem.open(&path) else {
            crate::println!("[boot] {path} could not be opened");
            continue;
        };
        let bytes = node.read_all();
        crate::println!("[boot] loading {path} ({} bytes)", bytes.len());

        match run(&bytes, &path, &options) {
            Ok(status) => {
                crate::println!("[boot] the image returned {status:?}");
                return true;
            }
            Err(error) => crate::println!("[boot] {path}: {error:?}"),
        }
    }
    false
}

/// Installs the block I/O and file-system protocols for a disk and the
/// partition the firmware boots from.
fn publish_storage(
    disk: &Arc<dyn BlockDevice>,
    partition: Arc<dyn BlockDevice>,
    filesystem: Arc<dyn FileSystem>,
    number: u32,
) {
    let disk_handle = match crate::uefi::blockio::install(Arc::clone(disk), false, false) {
        Ok(handle) => handle,
        Err(status) => {
            crate::println!("[boot] the disk could not be published: {status:?}");
            return;
        }
    };
    // SAFETY: the handle is ours and the path outlives it.
    unsafe {
        handles::install_on(
            disk_handle,
            &uefi::DEVICE_PATH_PROTOCOL_GUID,
            volume_device_path(disk.name(), 0) as *mut core::ffi::c_void,
        );
    }

    let volume_handle = match crate::uefi::blockio::install(Arc::clone(&partition), false, true) {
        Ok(handle) => handle,
        Err(status) => {
            crate::println!("[boot] the partition could not be published: {status:?}");
            return;
        }
    };
    // SAFETY: as above.
    unsafe {
        handles::install_on(
            volume_handle,
            &uefi::DEVICE_PATH_PROTOCOL_GUID,
            volume_device_path(disk.name(), number) as *mut core::ffi::c_void,
        );
    }
    match crate::uefi::simplefs::install(volume_handle, filesystem) {
        Ok(()) => crate::println!("[boot] published a volume on {volume_handle:p}"),
        Err(status) => crate::println!("[boot] the volume was not published: {status:?}"),
    }
}

/// Loads and enters one image.
fn run(bytes: &[u8], path: &str, options: &[u8]) -> Result<Status, crate::loader::pe::PeError> {
    let loaded = crate::loader::pe::load(bytes)?;
    crate::println!(
        "[boot] PE entry {:#x} (base {:#x}, {} bytes)",
        loaded.entry,
        loaded.base,
        loaded.size
    );

    let handle = handles::create_handle();
    let protocol = remember(handle, loaded.entry, loaded.base, loaded.size as u64);
    set_file(protocol, path, uefi::image_handle());
    set_load_options(protocol, options);
    // SAFETY: the structures were built above and outlive the handle.
    unsafe {
        let status = handles::install_on(
            handle,
            &uefi::LOADED_IMAGE_PROTOCOL_GUID,
            protocol as *mut core::ffi::c_void,
        );
        if status != Status::SUCCESS {
            return Ok(status);
        }
        handles::install_on(
            handle,
            &uefi::DEVICE_PATH_PROTOCOL_GUID,
            (*protocol).file_path as *mut core::ffi::c_void,
        );
        let entry: extern "efiapi" fn(Handle, *mut SystemTable) -> Status =
            core::mem::transmute(loaded.entry);
        Ok(entry(handle, uefi::system_table()))
    }
}

/// The boot path to use, and its optional data: `BootOrder` first, then the
/// removable-media fallback.
fn choose_boot_image(filesystem: &dyn FileSystem) -> Option<(alloc::string::String, Vec<u8>)> {
    for candidate in boot_order_paths() {
        if filesystem.open(&candidate.path).is_some() {
            crate::println!("[boot] BootOrder names {}", candidate.path);
            return Some((candidate.path, candidate.options));
        }
        crate::println!(
            "[boot] BootOrder entry {} is not on this volume",
            candidate.path
        );
    }

    if filesystem.open(FALLBACK_PATH).is_some() {
        crate::println!("[boot] using the removable-media fallback");
        return Some((alloc::string::String::from(FALLBACK_PATH), Vec::new()));
    }
    None
}

/// One entry of the boot order, resolved to a path on the ESP.
struct Candidate {
    path: alloc::string::String,
    options: Vec<u8>,
}

/// Reads `BootOrder` and the `Boot####` options it names.
///
/// The variable's payload is the specification's `EFI_LOAD_OPTION`: attributes,
/// a device path, a description, and optional data. Only the active entries are
/// honoured, and only the file path of each is used: this firmware has one
/// volume mounted, so an entry that names a file on it is the entry to run.
fn boot_order_paths() -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let Some(order) = crate::uefi::vars::get(&utf16("BootOrder"), &r_efi::system::GLOBAL_VARIABLE)
    else {
        return candidates;
    };
    let (_, order) = order;

    for chunk in order.chunks_exact(2) {
        let number = u16::from_le_bytes([chunk[0], chunk[1]]);
        let name = alloc::format!("Boot{number:04x}");
        let Some((_, payload)) =
            crate::uefi::vars::get(&utf16(&name), &r_efi::system::GLOBAL_VARIABLE)
        else {
            continue;
        };
        if let Some(candidate) = parse_load_option(&payload) {
            candidates.push(candidate);
        }
    }
    candidates
}

/// Parses `EFI_LOAD_OPTION`, returning the file it names.
pub fn parse_load_option(payload: &[u8]) -> Option<Candidate> {
    if payload.len() < 6 {
        return None;
    }
    let attributes = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if attributes & LOAD_OPTION_ACTIVE == 0 {
        return None;
    }
    let path_length = u16::from_le_bytes(payload[4..6].try_into().ok()?) as usize;
    let path_start = 6;
    let path_end = path_start + path_length;
    if path_end > payload.len() {
        return None;
    }

    // The description follows the path list, then the optional data.
    let mut cursor = path_end;
    while cursor + 1 < payload.len() {
        let unit = u16::from_le_bytes(payload[cursor..cursor + 2].try_into().ok()?);
        cursor += 2;
        if unit == 0 {
            break;
        }
    }
    let options = payload.get(cursor..).unwrap_or(&[]).to_vec();

    // Walk the device path nodes for the file-path node: that is the file this
    // entry names.
    let mut offset = path_start;
    while offset + 4 <= path_end {
        // SAFETY: the node was bounds checked against the payload.
        let node = unsafe { &*((payload.as_ptr().add(offset)) as *const device_path::Protocol) };
        let length = node.length[0] as usize | ((node.length[1] as usize) << 8);
        if length < 4 || offset + length > path_end {
            break;
        }
        if node.r#type == dp::END_DEVICE_PATH && node.sub_type == dp::END_DEVICE_PATH_INSTANCE {
            break;
        }
        if let Some(units) = dp::file_path_name(node) {
            let path: alloc::string::String = units
                .iter()
                .take_while(|unit| **unit != 0)
                .map(|unit| char::from_u32(*unit as u32).unwrap_or('?'))
                .collect();
            return Some(Candidate { path, options });
        }
        offset += length;
    }
    None
}

/// A UTF-16 string with its terminator, for the variable services.
fn utf16(text: &str) -> Vec<Char16> {
    let mut units: Vec<Char16> = text.encode_utf16().collect();
    units.push(0);
    units
}

/// The device path the firmware gives a volume: a vendor node naming the disk
/// and partition, which is enough for `LocateDevicePath` to tell volumes apart.
pub fn volume_device_path(disk: &str, partition: u32) -> *mut device_path::Protocol {
    let storage = mem::pages_for(r_efi::system::LOADER_DATA, DEVICE_PATH_BYTES);
    assert!(!storage.is_null(), "uefi: out of memory for a device path");
    // SAFETY: the pages are ours, and the node layout is fixed.
    unsafe {
        let node = storage as *mut device_path::Protocol;
        (*node).r#type = dp::MESSAGING_DEVICE;
        (*node).sub_type = dp::MEDIA_VENDOR;
        (*node).length = [20, 0];
        let payload = storage.add(4);
        let mut name = [0u8; 16];
        for (index, byte) in disk.bytes().take(12).enumerate() {
            name[index] = byte;
        }
        name[12] = partition as u8;
        core::ptr::copy_nonoverlapping(name.as_ptr(), payload, name.len());
        let end = storage.add(20) as *mut device_path::Protocol;
        (*end).r#type = dp::END_DEVICE_PATH;
        (*end).sub_type = dp::END_DEVICE_PATH_INSTANCE;
        (*end).length = [0x04, 0x00];
    }
    storage as *mut device_path::Protocol
}

/// The file node for a path, for callers that need the file itself.
pub fn open_file(
    filesystem: &dyn FileSystem,
    path: &str,
) -> Option<alloc::boxed::Box<dyn FileNode>> {
    filesystem.open(path)
}
