//! Rewrites the DXE core inside a QEMU firmware ROM.
//!
//! Patina is the DXE phase of an EDK2 firmware rather than a whole firmware, so
//! a platform brings its own DXE core image and puts it where the firmware
//! expects to find one. This is that step for QEMU's AArch64 `virt` machine:
//! the ROM carries a firmware volume holding the DXE core, and this replaces
//! the image with a platform's own.
//!
//! The vendor tool for this (`patina-fw-patcher`) drives EDK2's BaseTools
//! binaries, which are Linux executables; this does the same edit in place, so
//! the firmware can be rebuilt and run from any host.
//!
//! # What it edits
//!
//! Every structure is the PI specification's, little-endian:
//!
//! ```text
//! code flash, pflash unit 1 (QEMU_EFI.fd)
//! └── firmware volume
//!     └── FFS file, type FV image, name 7bb6c4a8-fecd-4f0d-9f5a-2e03add35b96
//!         └── section, GUID-defined, compressed with LZMA
//!             └── firmware volume
//!                 └── FFS file, type DXE core
//!                     └── section, PE32+   <- the platform's DXE core goes here
//! ```
//!
//! The replacement keeps every size field, checksum, and section header of the
//! layers it rebuilds consistent with what an EDK2 firmware volume driver
//! reads. The compression is the LZMA stream format EDK2's decompressor
//! expects: five bytes of properties, a four-byte dictionary size, the
//! eight-byte uncompressed size, then the stream.
//!
//! # Usage
//!
//! ```text
//! rompatch --rom QEMU_EFI.fd --pe qemu_armvirt_dxe_core.efi --out patched.fd
//! rompatch --rom QEMU_EFI.fd --dump
//! rompatch --rom QEMU_EFI.fd --extract dxe_core.efi
//! ```

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::process::ExitCode;

/// This tool reports failures as messages: there is nothing to recover from,
/// and the caller is a person reading a console.
type Result<T, E = String> = std::result::Result<T, E>;

/// `EFI_FFS_FILE_HEADER`.
const FFS_HEADER_SIZE: usize = 24;
/// `EFI_COMMON_SECTION_HEADER`.
const SECTION_HEADER_SIZE: usize = 4;
/// `EFI_GUID_DEFINED_SECTION`: the common header, the GUID, a data offset, and
/// the attributes.
const GUIDED_HEADER_SIZE: usize = SECTION_HEADER_SIZE + 16 + 2 + 2;
/// `EFI_FIRMWARE_VOLUME_HEADER` fixed part: the signature sits 40 bytes in, the
/// header length 48, and the checksum 50.
const FV_SIGNATURE_OFFSET: usize = 40;
const FV_LENGTH_OFFSET: usize = 32;
const FV_HEADER_LENGTH_OFFSET: usize = 48;
const FV_CHECKSUM_OFFSET: usize = 50;
const FV_SIGNATURE: [u8; 4] = *b"_FVH";

/// `EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE`.
const TYPE_FV_IMAGE: u8 = 0x0b;
/// `EFI_FV_FILETYPE_DXE_CORE`.
const TYPE_DXE_CORE: u8 = 0x05;
/// `EFI_SECTION_GUID_DEFINED`.
const TYPE_GUID_DEFINED: u8 = 0x02;
/// `EFI_SECTION_PE32`, which EDK2 uses for PE32 and PE32+ images alike.
const TYPE_PE32: u8 = 0x10;
/// `EFI_SECTION_PE32_PLUS`, which some builders write instead.
const TYPE_PE32_PLUS: u8 = 0x1b;
/// `EFI_SECTION_FIRMWARE_VOLUME_IMAGE`.
const TYPE_FV_IMAGE_SECTION: u8 = 0x17;

/// The FFS file name of the firmware volume image that carries the DXE core,
/// `7bb6c4a8-fecd-4f0d-9f5a-2e03add35b96`, in the mixed-endian byte order an
/// FFS header stores a GUID in.
const DXE_CORE_FV_GUID: [u8; 16] = [
    0xa8, 0xc4, 0xb6, 0x7b, 0xcd, 0xfe, 0x0d, 0x4f, 0x9f, 0x5a, 0x2e, 0x03, 0xad, 0xd3, 0x5b, 0x96,
];
/// `ee4e5898-3914-4259-9d6e-dc7bd79403cf`, the LZMA custom-decompression GUID.
const LZMA_GUID: [u8; 16] = [
    0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42, 0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf,
];

/// `EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID`.
const FFS_STATE_VALID: u8 = 0xf8;
/// `FFS_ATTRIB_CHECKSUM`: the file header's second checksum covers the body.
const FFS_ATTRIB_CHECKSUM: u8 = 0x40;
/// `FFS_FIXED_CHECKSUM`, written when the file carries no checksum.
const FFS_FIXED_CHECKSUM: u8 = 0xaa;

fn main() -> ExitCode {
    match run() {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rompatch: {error}");
            ExitCode::FAILURE
        }
    }
}

struct Arguments {
    rom: String,
    pe: Option<String>,
    out: Option<String>,
    extract: Option<String>,
    dump: bool,
}

fn parse_arguments() -> Result<Arguments> {
    let mut arguments = Arguments {
        rom: String::new(),
        pe: None,
        out: None,
        extract: None,
        dump: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("{argument} needs a value"))
        };
        match argument.as_str() {
            "--rom" => arguments.rom = value()?,
            "--pe" => arguments.pe = Some(value()?),
            "--out" => arguments.out = Some(value()?),
            "--extract" => arguments.extract = Some(value()?),
            "--dump" => arguments.dump = true,
            "--help" | "-h" => {
                println!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if arguments.rom.is_empty() {
        return Err(format!("--rom is required\n{USAGE}"));
    }
    if !arguments.dump
        && arguments.extract.is_none()
        && (arguments.pe.is_none() || arguments.out.is_none())
    {
        return Err(format!("--pe and --out are required\n{USAGE}"));
    }
    Ok(arguments)
}

const USAGE: &str = "\
usage: rompatch --rom <code flash> [--dump]
       rompatch --rom <code flash> --extract <path>
       rompatch --rom <code flash> --pe <dxe core> --out <patched flash>";

fn run() -> Result<String> {
    let arguments = parse_arguments()?;
    let rom = fs::read(&arguments.rom).map_err(|error| format!("{}: {error}", arguments.rom))?;

    if arguments.dump {
        return dump(&rom);
    }
    let location = locate(&rom)?;
    if let Some(path) = &arguments.extract {
        let image = &location.blob
            [location.pe.offset + SECTION_HEADER_SIZE..location.pe.offset + location.pe.size];
        fs::write(path, image).map_err(|error| format!("{path}: {error}"))?;
        return Ok(format!("wrote {} bytes to {path}", image.len()));
    }

    let pe_path = arguments.pe.as_deref().expect("checked by parse_arguments");
    let pe = fs::read(pe_path).map_err(|error| format!("{pe_path}: {error}"))?;
    if pe.len() < 2 || &pe[..2] != b"MZ" {
        return Err(format!("{pe_path} is not a PE image"));
    }

    let patched = replace_dxe_core(&rom, &pe)?;
    let out_path = arguments
        .out
        .as_deref()
        .expect("checked by parse_arguments");
    fs::write(out_path, &patched).map_err(|error| format!("{out_path}: {error}"))?;

    // Read the result back the way a firmware volume driver would, and check
    // that the DXE core the ROM now carries is the one asked for. A patcher
    // that writes an image nothing can find is worse than one that refuses.
    let verify = locate(&patched)?;
    let carried =
        &verify.blob[verify.pe.offset + SECTION_HEADER_SIZE..verify.pe.offset + verify.pe.size];
    if carried != pe {
        return Err("the patched ROM does not read back as the requested image".into());
    }

    let before = rom.len();
    Ok(format!(
        "patched {out_path}: {pe_path} is now the DXE core ({} bytes, {} byte ROM verified)",
        pe.len(),
        before
    ))
}

// ---------------------------------------------------------------------------
// Reading the ROM
// ---------------------------------------------------------------------------

/// A firmware volume: where it starts, how long it is, and how much of that is
/// its header.
#[derive(Clone, Copy, Debug)]
struct Volume {
    base: usize,
    length: usize,
    header_length: usize,
}

/// An FFS file: its offset, its size including the header, its type and
/// attributes, and the name it is filed under.
#[derive(Clone, Copy, Debug)]
struct FfsFile {
    offset: usize,
    size: usize,
    file_type: u8,
    name: [u8; 16],
}

/// A section inside an FFS file.
#[derive(Clone, Copy, Debug)]
struct Section {
    offset: usize,
    size: usize,
    section_type: u8,
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| format!("truncated u16 at {offset:#x}"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u24_at(data: &[u8], offset: usize) -> Result<usize> {
    let bytes = data
        .get(offset..offset + 3)
        .ok_or_else(|| format!("truncated u24 at {offset:#x}"))?;
    Ok(bytes[0] as usize | (bytes[1] as usize) << 8 | (bytes[2] as usize) << 16)
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| format!("truncated u32 at {offset:#x}"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| format!("truncated u64 at {offset:#x}"))?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u24(data: &mut [u8], offset: usize, value: usize) {
    data[offset] = value as u8;
    data[offset + 1] = (value >> 8) as u8;
    data[offset + 2] = (value >> 16) as u8;
}

/// EDK2's `CalculateCheckSum8`: the value that brings a byte sum to zero.
fn checksum8(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    0u8.wrapping_sub(sum)
}

/// The FFS header checksum, over the header with the two checksum fields and
/// the state byte treated as zero. `GenFfs` computes it the same way.
fn ffs_header_checksum(header: &[u8]) -> u8 {
    let mut copy = header.to_vec();
    copy[16] = 0;
    copy[17] = 0;
    copy[23] = 0;
    checksum8(&copy)
}

/// The firmware volume header checksum: 16-bit words summing to zero, over the
/// header with the checksum field itself zero.
fn fv_header_checksum(header: &[u8]) -> Result<u16> {
    if header.len() % 2 != 0 {
        return Err("firmware volume header length is not even".into());
    }
    let mut copy = header.to_vec();
    write_u16(&mut copy, FV_CHECKSUM_OFFSET, 0);
    let sum = copy.chunks(2).fold(0u16, |sum, word| {
        sum.wrapping_add(u16::from_le_bytes([word[0], word[1]]))
    });
    Ok(0u16.wrapping_sub(sum))
}

/// Every firmware volume in the image, found by its signature. The signature
/// sits forty bytes into the header, so a candidate starts forty bytes before
/// it; the header is then checked for a plausible length and a checksum that
/// matches, which rules out the signature appearing inside data.
fn volumes(data: &[u8]) -> Vec<Volume> {
    let mut found = Vec::new();
    for start in 0..data.len().saturating_sub(FV_SIGNATURE_OFFSET + 4) {
        if data[start + FV_SIGNATURE_OFFSET..start + FV_SIGNATURE_OFFSET + 4] != FV_SIGNATURE {
            continue;
        }
        let Ok(length) = u64_at(data, start + FV_LENGTH_OFFSET) else {
            continue;
        };
        let Ok(header_length) = u16_at(data, start + FV_HEADER_LENGTH_OFFSET) else {
            continue;
        };
        let header_length = header_length as usize;
        let length = length as usize;
        if header_length < FV_CHECKSUM_OFFSET + 2
            || header_length > 0x1000
            || length < header_length + FFS_HEADER_SIZE
            || start + length > data.len()
        {
            continue;
        }
        let Ok(checksum) = fv_header_checksum(&data[start..start + header_length]) else {
            continue;
        };
        let Ok(stored) = u16_at(data, start + FV_CHECKSUM_OFFSET) else {
            continue;
        };
        if checksum != stored {
            continue;
        }
        found.push(Volume {
            base: start,
            length,
            header_length,
        });
    }
    found
}

/// The FFS files of a volume, in the order the volume lists them. The walk
/// stops at the first erased entry, which is how a volume marks its free space.
fn files_in(data: &[u8], volume: &Volume) -> Result<Vec<FfsFile>> {
    let mut files = Vec::new();
    let end = volume.base + volume.length;
    let mut offset = volume.base + volume.header_length;
    while offset + FFS_HEADER_SIZE <= end {
        let name: [u8; 16] = data[offset..offset + 16].try_into().expect("sixteen bytes");
        if name == [0xff; 16] || name == [0x00; 16] {
            break;
        }
        let size = u24_at(data, offset + 20)?;
        if size < FFS_HEADER_SIZE || offset + size > end {
            return Err(format!(
                "FFS file at {offset:#x} claims {size} bytes, past the volume end"
            ));
        }
        files.push(FfsFile {
            offset,
            size,
            file_type: data[offset + 18],
            name,
        });
        offset += (size + 7) & !7;
    }
    Ok(files)
}

/// The sections of an FFS file, in file order.
fn sections_in(data: &[u8], file: &FfsFile) -> Result<Vec<Section>> {
    let mut sections = Vec::new();
    let end = file.offset + file.size;
    let mut offset = file.offset + FFS_HEADER_SIZE;
    while offset + SECTION_HEADER_SIZE <= end {
        let size = u24_at(data, offset)?;
        if size < SECTION_HEADER_SIZE || offset + size > end {
            return Err(format!(
                "section at {offset:#x} claims {size} bytes, past the file end"
            ));
        }
        sections.push(Section {
            offset,
            size,
            section_type: data[offset + 3],
        });
        offset += size;
    }
    Ok(sections)
}

/// The DXE core image in an image: the FFS file that carries it, and the volume
/// that file sits in.
///
/// Two arrangements exist. Patina's QEMU platform files the image under a name
/// of its own, `7bb6c4a8-...`; a firmware built from TianoCore keeps it inside
/// the compressed main volume, where the name is the platform's business and
/// the *type*, `EFI_FV_FILETYPE_DXE_CORE`, is what identifies it. Both are
/// searched for, most specific first.
fn find_dxe_core_fv(data: &[u8]) -> Result<(Volume, FfsFile, Vec<u8>)> {
    let mut candidate = None;
    for volume in volumes(data) {
        for file in files_in(data, &volume)? {
            if file.file_type != TYPE_FV_IMAGE {
                continue;
            }
            let Ok(section) = lzma_section(data, &file) else {
                continue;
            };
            let payload = &data[section.offset + GUIDED_HEADER_SIZE..section.offset + section.size];
            let Ok(blob) = decompress(payload) else {
                continue;
            };
            if file.name == DXE_CORE_FV_GUID {
                return Ok((volume, file, blob));
            }
            if candidate.is_none() {
                let holds_core = volumes(&blob).into_iter().any(|inner| {
                    files_in(&blob, &inner)
                        .map(|files| files.iter().any(|file| file.file_type == TYPE_DXE_CORE))
                        .unwrap_or(false)
                });
                if holds_core {
                    candidate = Some((volume, file, blob));
                }
            }
        }
    }
    candidate.ok_or_else(|| "no firmware volume in this image holds a DXE core image".into())
}

/// The extent of the LZMA-guided section inside `file`, checking that the
/// compression is the one this tool writes.
fn lzma_section(data: &[u8], file: &FfsFile) -> Result<Section> {
    let sections = sections_in(data, file)?;
    let section = sections
        .first()
        .copied()
        .ok_or_else(|| "the DXE core file has no sections".to_string())?;
    if section.section_type != TYPE_GUID_DEFINED {
        return Err(format!(
            "the DXE core file's first section is type {:#x}, not a guided section",
            section.section_type
        ));
    }
    let guid: [u8; 16] = data[section.offset + 4..section.offset + 20]
        .try_into()
        .expect("sixteen bytes");
    if guid != LZMA_GUID {
        return Err("the DXE core file is not LZMA compressed".into());
    }
    let data_offset = u16_at(data, section.offset + 20)? as usize;
    if data_offset < GUIDED_HEADER_SIZE || data_offset > section.size {
        return Err(format!(
            "guided section data offset {data_offset} is out of range"
        ));
    }
    Ok(section)
}

/// Decompresses a `.lzma` stream: five bytes of properties, a four-byte
/// dictionary size, the eight-byte uncompressed size, then the stream.
fn decompress(payload: &[u8]) -> Result<Vec<u8>> {
    let mut reader = lzma_rust2::LzmaReader::new_mem_limit(payload, u32::MAX, None)
        .map_err(|error| format!("LZMA header: {error}"))?;
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|error| format!("LZMA stream: {error}"))?;
    Ok(out)
}

/// Compresses to the same stream format, with the uncompressed size in the
/// header: EDK2's decompressor sizes its output from that field, so the
/// unknown-size marker an ordinary `.lzma` file may carry would not do.
fn compress(blob: &[u8]) -> Result<Vec<u8>> {
    let options = lzma_rust2::LzmaOptions::with_preset(6);
    let mut writer =
        lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &options, Some(blob.len() as u64))
            .map_err(|error| format!("LZMA encoder: {error}"))?;
    use std::io::Write;
    writer
        .write_all(blob)
        .map_err(|error| format!("LZMA encoder: {error}"))?;
    writer
        .finish()
        .map_err(|error| format!("LZMA encoder: {error}"))
}

/// The DXE core image in a ROM, as the layers that carry it.
struct DxeCore {
    /// The volume holding the FFS file.
    volume: Volume,
    /// The FV-image FFS file that carries the compressed volume.
    file: FfsFile,
    /// The guided section inside it.
    section: Section,
    /// The decompressed content: wrapper sections and the inner volume.
    blob: Vec<u8>,
    /// The inner volume's offset in `blob`.
    inner_base: usize,
    /// The inner volume's length.
    inner_length: usize,
    /// The inner volume's header length.
    inner_header_length: usize,
    /// The FFS files of the inner volume.
    inner_files: Vec<FfsFile>,
    /// The DXE core file, and the PE section inside it.
    core: FfsFile,
    pe: Section,
}

fn locate(rom: &[u8]) -> Result<DxeCore> {
    let (volume, file, blob) = find_dxe_core_fv(rom)?;
    let section = lzma_section(rom, &file)?;
    let inner = volumes(&blob)
        .into_iter()
        .next()
        .ok_or_else(|| "the decompressed DXE core image holds no volume".to_string())?;
    let inner_files = files_in(&blob, &inner)?;
    let core = inner_files
        .iter()
        .find(|file| file.file_type == TYPE_DXE_CORE)
        .copied()
        .ok_or_else(|| "the DXE core volume holds no DXE core file".to_string())?;
    let pe = sections_in(&blob, &core)?
        .into_iter()
        .find(|section| section.section_type == TYPE_PE32 || section.section_type == TYPE_PE32_PLUS)
        .ok_or_else(|| "the DXE core file holds no PE image".to_string())?;
    Ok(DxeCore {
        volume,
        file,
        section,
        blob,
        inner_base: inner.base,
        inner_length: inner.length,
        inner_header_length: inner.header_length,
        inner_files,
        core,
        pe,
    })
}

// ---------------------------------------------------------------------------
// Rewriting
// ---------------------------------------------------------------------------

/// Builds an FFS file: the header of `original` with the size and checksums
/// brought up to date for `body`, then `body`.
fn build_ffs(original: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let size = FFS_HEADER_SIZE + body.len();
    if size > 0x00ff_ffff {
        return Err(format!(
            "FFS file of {size} bytes does not fit a header's size field"
        ));
    }
    let mut header = original[..FFS_HEADER_SIZE].to_vec();
    write_u24(&mut header, 20, size);
    header[17] = if header[19] & FFS_ATTRIB_CHECKSUM != 0 {
        checksum8(body)
    } else {
        FFS_FIXED_CHECKSUM
    };
    header[23] = FFS_STATE_VALID;
    let checksum = ffs_header_checksum(&header);
    header[16] = checksum;
    let mut file = header;
    file.extend_from_slice(body);
    Ok(file)
}

/// A section header and its payload.
fn build_section(section_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let size = SECTION_HEADER_SIZE + payload.len();
    if size > 0x00ff_ffff {
        return Err(format!("section of {size} bytes does not fit a size field"));
    }
    let mut section = vec![0u8; SECTION_HEADER_SIZE];
    write_u24(&mut section, 0, size);
    section[3] = section_type;
    section.extend_from_slice(payload);
    Ok(section)
}

/// A guided section carrying an LZMA stream.
fn build_lzma_section(payload: &[u8]) -> Result<Vec<u8>> {
    let size = GUIDED_HEADER_SIZE + payload.len();
    if size > 0x00ff_ffff {
        return Err(format!(
            "guided section of {size} bytes does not fit a size field"
        ));
    }
    let mut section = vec![0u8; GUIDED_HEADER_SIZE];
    write_u24(&mut section, 0, size);
    section[3] = TYPE_GUID_DEFINED;
    section[4..20].copy_from_slice(&LZMA_GUID);
    write_u16(&mut section, 20, GUIDED_HEADER_SIZE as u16);
    write_u16(&mut section, 22, 0x0001); // EFI_GUIDED_SECTION_PROCESSING_REQUIRED
    section.extend_from_slice(payload);
    Ok(section)
}

/// The whole ROM with the DXE core swapped for `image`.
fn replace_dxe_core(rom: &[u8], image: &[u8]) -> Result<Vec<u8>> {
    let core = locate(rom)?;

    // The inner volume, rebuilt with the same files in the same order, the DXE
    // core file replaced. Its header is reused verbatim apart from the length,
    // so the volume keeps the name, block map, and attributes it was built
    // with.
    let mut body = Vec::new();
    body.extend_from_slice(&build_section(core.pe.section_type, image)?);
    let core_header = core.blob[core.core.offset..core.core.offset + FFS_HEADER_SIZE].to_vec();
    let rebuilt = build_ffs(&core_header, &body)?;

    let mut volume = Vec::new();
    for file in &core.inner_files {
        if file.offset == core.core.offset {
            volume.extend_from_slice(&rebuilt);
        } else {
            volume.extend_from_slice(&core.blob[file.offset..file.offset + file.size]);
        }
        while volume.len() % 8 != 0 {
            volume.push(0xff);
        }
    }
    // EDK2 rounds a volume up to whole blocks and fills the rest with erased
    // bytes, which is also how the free space past the last file is marked.
    let block = block_size(&core.blob[core.inner_base..])?;
    let inner_length = (core.inner_header_length + volume.len()).div_ceil(block) * block;
    volume.resize(inner_length - core.inner_header_length, 0xff);

    let mut header =
        core.blob[core.inner_base..core.inner_base + core.inner_header_length].to_vec();
    let stored = u16_at(&header, FV_CHECKSUM_OFFSET)?;
    if fv_header_checksum(&header)? != stored {
        return Err("the inner volume's header checksum does not follow the specification".into());
    }
    let length_offset = FV_LENGTH_OFFSET;
    header[length_offset..length_offset + 8].copy_from_slice(&(inner_length as u64).to_le_bytes());
    let checksum = fv_header_checksum(&header)?;
    write_u16(&mut header, FV_CHECKSUM_OFFSET, checksum);

    // The wrapper sections before the volume, with the FV-image section's size
    // brought up to date.
    let mut blob = core.blob[..core.inner_base].to_vec();
    let with_header = header.len() + volume.len();
    let wrapper = core.inner_base - SECTION_HEADER_SIZE;
    if blob[wrapper + 3] != TYPE_FV_IMAGE_SECTION {
        return Err("the inner volume is not wrapped in an FV-image section".into());
    }
    if with_header != core.inner_length {
        let size = SECTION_HEADER_SIZE + with_header;
        if size > 0x00ff_ffff {
            return Err("the DXE core volume no longer fits a section size field".into());
        }
        write_u24(&mut blob, wrapper, size);
    }
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&volume);

    // Back out through compression and the two outer layers.
    let compressed = compress(&blob)?;
    let section = build_lzma_section(&compressed)?;
    let file_header = rom[core.file.offset..core.file.offset + FFS_HEADER_SIZE].to_vec();
    let file = build_ffs(&file_header, &section)?;
    let end = core.file.offset + file.len();
    if end > core.volume.base + core.volume.length {
        return Err(format!(
            "the rebuilt DXE core is {} bytes and would run past the firmware volume; \
             use a smaller build or a larger firmware volume",
            file.len()
        ));
    }

    let mut patched = rom.to_vec();
    let erased_to = core.file.offset + core.file.size.max(file.len());
    patched[core.file.offset..erased_to].fill(0xff);
    patched[core.file.offset..end].copy_from_slice(&file);
    Ok(patched)
}

/// The block size of a volume, from the first block map entry. EDK2 rounds a
/// volume's length up to a whole number of blocks, and a firmware volume driver
/// is entitled to walk it in those blocks.
fn block_size(volume: &[u8]) -> Result<usize> {
    let mut offset = FV_CHECKSUM_OFFSET + 6; // past the checksum, offset, and revision
    loop {
        let blocks = u32_at(volume, offset)?;
        let length = u32_at(volume, offset + 4)?;
        if blocks == 0 && length == 0 {
            return Ok(0x1000);
        }
        if blocks != 0 {
            return Ok(length as usize);
        }
        offset += 8;
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

const SECTION_NAMES: &[(u8, &str)] = &[
    (0x01, "compression"),
    (0x02, "guided"),
    (0x13, "dependency"),
    (0x14, "version"),
    (0x15, "user interface"),
    (0x16, "compat16"),
    (0x17, "volume image"),
    (0x18, "freeform"),
    (0x19, "raw"),
    (0x10, "PE32"),
    (0x1b, "PE32+"),
];

const FILE_NAMES: &[(u8, &str)] = &[
    (0x01, "raw"),
    (0x02, "freeform"),
    (0x03, "security core"),
    (0x04, "PEI core"),
    (0x05, "DXE core"),
    (0x06, "PEIM"),
    (0x07, "driver"),
    (0x09, "application"),
    (0x0b, "volume image"),
];

fn name_of(table: &[(u8, &str)], value: u8) -> String {
    table
        .iter()
        .find(|(code, _)| *code == value)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("type {value:#04x}"))
}

fn format_guid(guid: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
        u16::from_le_bytes([guid[4], guid[5]]),
        u16::from_le_bytes([guid[6], guid[7]]),
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

fn dump(rom: &[u8]) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "image: {} bytes", rom.len()).expect("writing to a string");
    for volume in volumes(rom) {
        writeln!(
            out,
            "volume at {:#x}: {} bytes, {}-byte header, block {:#x}",
            volume.base,
            volume.length,
            volume.header_length,
            block_size(&rom[volume.base..])?
        )
        .expect("writing to a string");
        for file in files_in(rom, &volume)? {
            writeln!(
                out,
                "  file at {:#x}: {} bytes, {}, {}",
                file.offset,
                file.size,
                name_of(FILE_NAMES, file.file_type),
                format_guid(&file.name)
            )
            .expect("writing to a string");
            for section in sections_in(rom, &file)? {
                writeln!(
                    out,
                    "    section at {:#x}: {} bytes, {}",
                    section.offset,
                    section.size,
                    name_of(SECTION_NAMES, section.section_type)
                )
                .expect("writing to a string");
                if section.section_type == TYPE_GUID_DEFINED {
                    let guid: [u8; 16] = rom[section.offset + 4..section.offset + 20]
                        .try_into()
                        .expect("sixteen bytes");
                    writeln!(out, "      compression: {}", format_guid(&guid))
                        .expect("writing to a string");
                }
            }
        }
    }
    let core =
        locate(rom).map_err(|error| format!("{out}\nthe DXE core is not usable: {error}"))?;
    writeln!(
        out,
        "DXE core: {} bytes of PE image at {:#x} in a {}-byte volume, wrapped in {} bytes of LZMA",
        core.pe.size - SECTION_HEADER_SIZE,
        core.pe.offset,
        core.inner_length,
        core.section.size - GUIDED_HEADER_SIZE
    )
    .expect("writing to a string");
    Ok(out)
}
