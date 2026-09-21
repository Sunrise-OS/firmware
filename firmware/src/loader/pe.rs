//! PE32+ loading: the image format an EFI application is in.
//!
//! The work is the same a loader does anywhere: check the image is for this
//! machine at this exception level's hand-off point, lay its sections out in
//! memory at the addresses they were linked for, and fix up the absolute
//! addresses inside it for wherever it actually landed. Only then can its entry
//! point be called.
//!
//! The headers are read with the `object` crate, which knows PE's shape; the
//! layout and the relocations are applied here, where the firmware knows what it
//! allocated and why.

use object::LittleEndian as LE;
use object::pe;
use object::read::pe::PeFile64;

/// `IMAGE_FILE_MACHINE_ARM64`.
const MACHINE_ARM64: u16 = 0xaa64;
/// The subsystems an EFI image may declare: application, boot service driver,
/// runtime driver. Anything else is a Windows image.
const SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
const SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
/// `PE\0\0`, the signature at the start of the NT headers.
const NT_SIGNATURE: u16 = 0x4550;
/// `PE32+`, the optional-header magic of a 64-bit image.
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20b;

/// An image, resident in memory and ready to run.
pub struct Loaded {
    /// Where the image was placed.
    pub base: usize,
    /// `SizeOfImage`: the whole span the image reserves.
    pub size: usize,
    /// The address of the entry point: `base + AddressOfEntryPoint`.
    pub entry: usize,
}

#[derive(Debug)]
pub enum PeError {
    /// Not a PE image at all.
    NotPe,
    /// Not AArch64.
    WrongMachine,
    /// Not an EFI application, boot driver, or runtime driver.
    WrongSubsystem,
    /// A relocation this loader does not implement.
    UnsupportedRelocation,
    /// The image asks for more memory than the firmware has.
    OutOfMemory,
}

/// `IMAGE_REL_BASED_HIGHLOW`: a 32-bit absolute address.
const RELOCATION_ABSOLUTE: u16 = 0;
/// `IMAGE_REL_BASED_DIR64`: a 64-bit absolute address, which is what an AArch64
/// image's pointers are.
const RELOCATION_DIR64: u16 = 10;

/// Loads `bytes` into memory.
pub fn load(bytes: &[u8]) -> Result<Loaded, PeError> {
    let size_of_image = size_of_image(bytes)?;
    // One allocation for the whole image, zeroed: the firmware's page allocator
    // hands back zeroed pages, which is what the parts of a section beyond its
    // raw data are supposed to be.
    let memory = crate::uefi::mem::pages_for(r_efi::system::LOADER_CODE, size_of_image);
    if memory.is_null() {
        return Err(PeError::OutOfMemory);
    }
    load_at(bytes, memory as usize)
}

/// The size of the image the optional header declares: what a caller has to have
/// room for before it can load anything.
pub fn size_of_image(bytes: &[u8]) -> Result<usize, PeError> {
    let nt = read_u32(bytes, 0x3c)? as usize;
    let size = read_u32(bytes, nt + 24 + 56)? as usize;
    if size == 0 {
        return Err(PeError::NotPe);
    }
    Ok(size)
}

/// Loads `bytes` at `base`, which the caller has to have reserved and which must
/// be large enough for the image's size of image.
pub fn load_at(bytes: &[u8], base: usize) -> Result<Loaded, PeError> {
    let file = PeFile64::parse(bytes).map_err(|_| PeError::NotPe)?;

    // The optional header's scalar fields are read straight out of the image.
    // The crate parses them into types that carry their meaning in the type
    // itself, which is the right shape for a general-purpose reader but not for
    // a loader that only has to answer "is this an AArch64 EFI image, and where
    // do its parts go".
    // `e_lfanew` at the DOS header's 0x3c is where the NT headers start.
    let nt = read_u32(bytes, 0x3c)? as usize;
    if read_u16(bytes, nt)? != NT_SIGNATURE || read_u16(bytes, nt + 24)? != OPTIONAL_MAGIC_PE32_PLUS
    {
        return Err(PeError::NotPe);
    }
    if read_u16(bytes, nt + 4)? != MACHINE_ARM64 {
        return Err(PeError::WrongMachine);
    }
    if !matches!(
        read_u16(bytes, nt + 24 + 68)?,
        SUBSYSTEM_EFI_APPLICATION
            | SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
            | SUBSYSTEM_EFI_RUNTIME_DRIVER
    ) {
        return Err(PeError::WrongSubsystem);
    }
    let entry_rva = read_u32(bytes, nt + 24 + 16)? as usize;
    let image_base = read_u64(bytes, nt + 24 + 24)?;
    let size_of_image = size_of_image(bytes)?;
    let size_of_headers = read_u32(bytes, nt + 24 + 60)? as usize;

    // The destination may be memory nobody has written: clear what the image will
    // occupy, so the parts of a section beyond its raw data read as zero.
    // SAFETY: the caller guarantees `base` covers the image's size of image.
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, size_of_image);
    }

    // The headers go in first: they are part of the image, and a reader that
    // wants to know what it is running - the DXE core's paging setup, a debugger,
    // the application itself - finds them at the image's base. A loader that
    // copies only the sections leaves zeroes there.
    if size_of_headers > bytes.len() || size_of_headers > size_of_image {
        return Err(PeError::NotPe);
    }
    // SAFETY: the allocation covers `size_of_image` bytes, and `size_of_headers`
    // was just checked to be no larger.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), base as *mut u8, size_of_headers);
    }

    for header in file.section_table().iter() {
        let raw_size: u32 = header.size_of_raw_data.get(LE);
        let virtual_size: u32 = header.virtual_size.get(LE);
        if raw_size == 0 || virtual_size == 0 {
            continue;
        }
        let raw_start: usize = header.pointer_to_raw_data.get(LE) as usize;
        let raw_end = raw_start + raw_size as usize;
        if raw_end > bytes.len() {
            return Err(PeError::NotPe);
        }
        // A section's size on disk may exceed its size in memory; the image
        // only wants the part it said it has.
        let length = (raw_size as usize).min(virtual_size as usize);
        let destination = base + header.virtual_address.get(LE) as usize;
        if destination + length > base + size_of_image {
            return Err(PeError::NotPe);
        }
        // SAFETY: the pages were allocated for `size_of_image` bytes and the
        // copy was bounds checked against that just above.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(raw_start),
                destination as *mut u8,
                length,
            );
        }
    }

    // Fix up the absolute addresses, unless the image landed exactly where it
    // asked to be.
    let delta = base as i64 - image_base as i64;
    if delta != 0 {
        apply_relocations(&file, bytes, base, size_of_image, delta)?;
    }

    Ok(Loaded {
        base,
        size: size_of_image,
        entry: base + entry_rva,
    })
}

/// Applies the base relocations in `.reloc` for a load address that is not the
/// preferred one.
fn apply_relocations(
    file: &PeFile64,
    bytes: &[u8],
    base: usize,
    size_of_image: usize,
    delta: i64,
) -> Result<(), PeError> {
    let Some(directory) = file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC as usize) else {
        // No relocations and not at the preferred base: the image cannot run
        // where it landed.
        return Err(PeError::UnsupportedRelocation);
    };
    let directory_size: u32 = directory.size.get(LE);
    if directory_size == 0 {
        return Err(PeError::UnsupportedRelocation);
    }

    let blocks = section_bytes(
        file,
        bytes,
        directory.virtual_address.get(LE),
        directory_size,
    )
    .ok_or(PeError::NotPe)?;
    let mut cursor = 0usize;
    while cursor + 8 <= blocks.len() {
        let page = u32::from_le_bytes(blocks[cursor..cursor + 4].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(blocks[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        if block_size < 8 || cursor + block_size > blocks.len() {
            return Err(PeError::NotPe);
        }

        let mut entry = cursor + 8;
        while entry + 2 <= cursor + block_size {
            let value = u16::from_le_bytes(blocks[entry..entry + 2].try_into().unwrap());
            let kind = value >> 12;
            let offset = (value & 0x0fff) as usize;
            match kind {
                RELOCATION_ABSOLUTE => {}
                RELOCATION_DIR64 => {
                    let address = base + page + offset;
                    if address + 8 > base + size_of_image {
                        return Err(PeError::NotPe);
                    }
                    // SAFETY: the target is inside the image the firmware just
                    // allocated, and eight bytes of it are a pointer.
                    unsafe {
                        let slot = address as *mut u64;
                        *slot = (*slot).wrapping_add(delta as u64);
                    }
                }
                _ => return Err(PeError::UnsupportedRelocation),
            }
            entry += 2;
        }
        cursor += block_size;
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PeError> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .ok_or(PeError::NotPe)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PeError> {
    let slice = bytes.get(offset..offset + 4).ok_or(PeError::NotPe)?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PeError> {
    let slice = bytes.get(offset..offset + 8).ok_or(PeError::NotPe)?;
    Ok(u64::from_le_bytes(slice.try_into().unwrap()))
}

/// The bytes of a directory identified by an RVA, translated to a file offset
/// through the section table.
fn section_bytes<'a>(
    file: &PeFile64<'_>,
    bytes: &'a [u8],
    rva: u32,
    size: u32,
) -> Option<&'a [u8]> {
    for header in file.section_table().iter() {
        let start: u32 = header.virtual_address.get(LE);
        let virtual_size: u32 = header.virtual_size.get(LE);
        let raw_size: u32 = header.size_of_raw_data.get(LE);
        let end = start + virtual_size.max(raw_size);
        if rva >= start && rva < end {
            let within = rva - start;
            let file_offset = (header.pointer_to_raw_data.get(LE) + within) as usize;
            let length = (raw_size.saturating_sub(within)).min(size) as usize;
            let end = file_offset.checked_add(length)?;
            if end <= bytes.len() {
                return Some(&bytes[file_offset..end]);
            }
            return None;
        }
    }
    None
}
