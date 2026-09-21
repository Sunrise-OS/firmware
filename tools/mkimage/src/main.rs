//! `mkimage`: packages a RAM-linked firmware and a PI firmware volume for QEMU.
//!
//! QEMU's `-bios` starts execution at flash offset zero, not at a firmware
//! volume's contents. The first 4 KiB therefore hold a position-independent
//! reset trampoline: it copies the firmware's ELF load segments to their RAM
//! link addresses, clears their zero-init ranges, and jumps to the entry point.
//! This trampoline is only the QEMU reset/bootstrap mechanism, not the DXE
//! firmware volume. The actual PI firmware volume follows the firmware at a
//! flash block boundary, with a DXE-core FFS file containing the input PE32+
//! image. The trampoline copies that complete volume to scratch RAM for the
//! firmware to publish to the DXE core.
//!
//! The trampoline is assembled from `boot/boot.S.in` using `clang` and `mold`.
//! Its `.text` contains the literal pool and ELF zero-init table as well as
//! code, so only this section is extracted from the linked trampoline.
//!
//! Usage: `mkimage <firmware.elf> <out.bin> <dxe-core.efi>`, with the toolchain
//! binaries found on `PATH` or specified by `CC` and `MOLD`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The stub occupies the first 4 KiB of the image, so the firmware it copies
/// starts at this offset in flash. The stub is well under a kilobyte; the
/// padding leaves room for it to grow.
const STUB_RESERVE: usize = 0x1000;

/// The complete firmware volume is copied to this scratch RAM address. It is
/// bounded below so it cannot run into other RAM users.
const FV_ADDR: usize = 0x4500_0000;
const FV_MAX_SIZE: usize = 0x0100_0000;
const FV_BLOCK_SIZE: usize = 0x1000;
/// The fixed FV header (56 bytes), one block-map entry and its terminator.
const FV_HEADER_SIZE: usize = 72;
const FFS_HEADER_SIZE: usize = 24;
const SECTION_HEADER_SIZE: usize = 4;
/// EFI_FIRMWARE_FILE_SYSTEM2_GUID, in the mixed-endian on-disk representation.
const FFS2_GUID: [u8; 16] = [
    0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3,
];
/// patina::guid::DXE_CORE_ID, also in mixed-endian on-disk representation.
const DXE_CORE_GUID: [u8; 16] = [
    0x2f, 0x32, 0xc9, 0x23, 0xf2, 0x2a, 0x6a, 0x47, 0xbc, 0x4c, 0x26, 0xbc, 0x88, 0x26, 0x6c, 0x71,
];

/// `msr daifset, #0xf`: the stub's first instruction, and the check that the
/// reset vector really is at offset 0 of the image.
const STUB_FIRST_INSTRUCTION: [u8; 4] = [0xdf, 0x4f, 0x03, 0xd5];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <firmware.elf> <output.bin> <dxe-core.efi>",
            args[0]
        );
        std::process::exit(2);
    }
    let elf = PathBuf::from(&args[1]);
    let out = PathBuf::from(&args[2]);
    let core = PathBuf::from(&args[3]);
    let cc = std::env::var("CC").unwrap_or_else(|_| "clang".into());
    let mold = std::env::var("MOLD").unwrap_or_else(|_| "mold".into());

    let firmware = elf_image(&elf);
    println!(
        "mkimage: {} -> load {:#x}, entry {:#x}, {} bytes, {} zero-init range(s)",
        elf.display(),
        firmware.load_addr,
        firmware.entry,
        firmware.image.len(),
        firmware.zero_ranges.len()
    );

    let work = out.with_extension("mkimage");
    fs::create_dir_all(&work).unwrap();

    // The stub, with the firmware's numbers substituted in.
    let template =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../boot/boot.S.in"))
            .expect("boot/boot.S.in");
    let ranges = firmware
        .zero_ranges
        .iter()
        .map(|(start, end)| format!("    .quad {start:#x}, {end:#x}\n"))
        .collect::<String>();
    let core_bytes = fs::read(&core).expect("DXE core image");
    assert!(
        core_bytes.len() >= 0x40 && core_bytes[..2] == *b"MZ",
        "{} is not a PE image",
        core.display()
    );
    let nt = u32::from_le_bytes(core_bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(
        core_bytes.get(nt..nt + 4),
        Some(b"PE\0\0".as_slice()),
        "{} has no PE signature",
        core.display()
    );
    assert_eq!(
        core_bytes.get(nt + 4..nt + 6),
        Some(0xaa64u16.to_le_bytes().as_slice()),
        "{} is not an AArch64 image",
        core.display()
    );
    assert_eq!(
        core_bytes.get(nt + 24..nt + 26),
        Some(0x20bu16.to_le_bytes().as_slice()),
        "{} is not a PE32+ image",
        core.display()
    );
    assert_eq!(
        core_bytes.get(nt + 92..nt + 94),
        Some(11u16.to_le_bytes().as_slice()),
        "{} is not an EFI boot-service driver",
        core.display()
    );
    let volume = dxe_volume(&core_bytes);
    let fv_offset = (STUB_RESERVE + firmware.image.len()).div_ceil(FV_BLOCK_SIZE) * FV_BLOCK_SIZE;
    let substitutions = [
        ("@FLASH_OFFSET@", format!("{STUB_RESERVE:#x}")),
        ("@LOAD_ADDR@", format!("{:#x}", firmware.load_addr)),
        ("@FIRMWARE_SIZE@", format!("{:#x}", firmware.image.len())),
        ("@ENTRY_ADDR@", format!("{:#x}", firmware.entry)),
        (
            "@ZERO_RANGE_COUNT@",
            format!("{}", firmware.zero_ranges.len()),
        ),
        ("@ZERO_RANGES@", ranges),
        ("@FV_OFFSET@", format!("{fv_offset:#x}")),
        ("@FV_SIZE@", format!("{:#x}", volume.len())),
        ("@FV_ADDR@", format!("{FV_ADDR:#x}")),
    ];
    let mut stub_source = template;
    for (pattern, value) in substitutions {
        stub_source = stub_source.replace(pattern, &value);
    }
    let stub_s = work.join("boot.S");
    fs::write(&stub_s, stub_source).unwrap();

    let stub_o = work.join("boot.o");
    run(
        Command::new(&cc)
            .args(["--target=aarch64-unknown-none", "-c", "-x", "assembler"])
            .arg(&stub_s)
            .arg("-o")
            .arg(&stub_o),
        "clang (assembling the stub)",
    );

    let stub_elf = work.join("boot.elf");
    run(
        Command::new(&mold)
            .arg("--image-base=0")
            .arg("--entry=_start")
            .arg("-o")
            .arg(&stub_elf)
            .arg(&stub_o),
        "mold (linking the stub)",
    );

    let stub = elf_section(&stub_elf, ".text");
    assert_eq!(
        stub.get(..4),
        Some(STUB_FIRST_INSTRUCTION.as_slice()),
        "the linked stub does not start with its entry instruction"
    );

    assert!(
        stub.len() <= STUB_RESERVE,
        "the reset trampoline exceeds its flash reservation"
    );
    let mut image = stub;
    image.resize(STUB_RESERVE, 0);
    image.extend_from_slice(&firmware.image);
    image.resize(fv_offset, 0xff);
    image.extend_from_slice(&volume);
    fs::write(&out, &image).unwrap();
    println!(
        "mkimage: wrote {} ({} bytes: {} stub + {} firmware + {} padding + {} DXE firmware volume)",
        out.display(),
        image.len(),
        STUB_RESERVE,
        firmware.image.len(),
        fv_offset - STUB_RESERVE - firmware.image.len(),
        volume.len()
    );
}

/// PI firmware volume with one aligned DXE_CORE FFS file and PE32 section.
/// Unused bytes are erased (0xff), matching the FV erase-polarity attribute.
fn dxe_volume(image: &[u8]) -> Vec<u8> {
    let section_size = SECTION_HEADER_SIZE
        .checked_add(image.len())
        .expect("PE size overflow");
    let file_size = FFS_HEADER_SIZE
        .checked_add(section_size)
        .expect("FFS size overflow");
    assert!(
        file_size <= 0x00ff_ffff,
        "DXE core exceeds the FFS 24-bit file size"
    );
    let volume_size = (FV_HEADER_SIZE + file_size).div_ceil(FV_BLOCK_SIZE) * FV_BLOCK_SIZE;
    assert!(
        volume_size <= FV_MAX_SIZE,
        "DXE volume exceeds the 16 MiB scratch RAM window"
    );

    let mut volume = vec![0xff; volume_size];
    let header = &mut volume[..FV_HEADER_SIZE];
    header.fill(0);
    header[16..32].copy_from_slice(&FFS2_GUID);
    header[32..40].copy_from_slice(&(volume_size as u64).to_le_bytes());
    header[40..44].copy_from_slice(b"_FVH");
    // READ_ENABLED_CAP | READ_STATUS | MEMORY_MAPPED | ERASE_POLARITY.
    header[44..48].copy_from_slice(&0x0000_0c06u32.to_le_bytes());
    header[48..50].copy_from_slice(&(FV_HEADER_SIZE as u16).to_le_bytes());
    header[55] = 2; // PI firmware volume revision
    header[56..60].copy_from_slice(&((volume_size / FV_BLOCK_SIZE) as u32).to_le_bytes());
    header[60..64].copy_from_slice(&(FV_BLOCK_SIZE as u32).to_le_bytes());
    // [64..72] is the zero block-map terminator.
    let sum = header.chunks_exact(2).fold(0u16, |sum, word| {
        sum.wrapping_add(u16::from_le_bytes([word[0], word[1]]))
    });
    header[50..52].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());

    let file = &mut volume[FV_HEADER_SIZE..FV_HEADER_SIZE + FFS_HEADER_SIZE];
    file.fill(0);
    file[..16].copy_from_slice(&DXE_CORE_GUID);
    file[18] = 0x05; // EFI_FV_FILETYPE_DXE_CORE
    file[17] = 0xaa; // fixed checksum when FFS_ATTRIB_CHECKSUM is clear
    file[20..23].copy_from_slice(&file_size.to_le_bytes()[..3]);
    file[23] = 0xf8; // DATA_VALID for erase polarity one
    // The header checksum treats both checksum bytes and state as zero.
    let sum = file
        .iter()
        .enumerate()
        .filter(|(index, _)| !matches!(*index, 16 | 17 | 23))
        .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte));
    file[16] = 0u8.wrapping_sub(sum);

    let section = FV_HEADER_SIZE + FFS_HEADER_SIZE;
    volume[section..section + 3].copy_from_slice(&section_size.to_le_bytes()[..3]);
    volume[section + 3] = 0x10; // EFI_SECTION_PE32 (also used for PE32+)
    volume[section + SECTION_HEADER_SIZE..section + section_size].copy_from_slice(image);
    volume
}

/// The firmware as the stub will copy it: its loadable segments, laid out at
/// `segment address - load address`.
struct FirmwareImage {
    load_addr: u64,
    entry: u64,
    /// Ranges the image does not carry and the stub must zero, as (start, end)
    /// pairs.
    zero_ranges: Vec<(u64, u64)>,
    image: Vec<u8>,
}

/// Reads the firmware ELF.
///
/// The image is built from the program headers rather than from a flat
/// `objcopy` conversion, because the two disagree: mold aligns its segments, and
/// the flat conversion compacts the gaps out, which would leave the entry point
/// pointing at a hole. A loader uses the program headers, so this does too.
fn elf_image(path: &Path) -> FirmwareImage {
    let bytes = fs::read(path).expect("firmware ELF");
    assert_eq!(&bytes[0..4], b"\x7fELF", "not an ELF file");
    assert_eq!(bytes[4], 2, "not a 64-bit ELF");
    assert_eq!(bytes[5], 1, "not little-endian");
    assert_eq!(
        u16::from_le_bytes([bytes[18], bytes[19]]),
        183,
        "not AArch64"
    );

    let entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;

    // The load address is the lowest virtual address any loadable segment asks
    // for, which is what the stub copies to and what `--image-base` set.
    let mut load_addr = u64::MAX;
    for index in 0..phnum {
        let header = phoff + index * phentsize;
        let kind = u32::from_le_bytes(bytes[header..header + 4].try_into().unwrap());
        if kind != 1 {
            continue;
        }
        let vaddr = u64::from_le_bytes(bytes[header + 16..header + 24].try_into().unwrap());
        load_addr = load_addr.min(vaddr);
    }
    assert_ne!(load_addr, u64::MAX, "the firmware has no loadable segments");

    let mut image: Vec<u8> = Vec::new();
    for index in 0..phnum {
        let header = phoff + index * phentsize;
        let kind = u32::from_le_bytes(bytes[header..header + 4].try_into().unwrap());
        if kind != 1 {
            continue;
        }
        let offset =
            u64::from_le_bytes(bytes[header + 8..header + 16].try_into().unwrap()) as usize;
        let vaddr = u64::from_le_bytes(bytes[header + 16..header + 24].try_into().unwrap());
        let filesz =
            u64::from_le_bytes(bytes[header + 32..header + 40].try_into().unwrap()) as usize;
        if filesz == 0 {
            continue;
        }
        let start = (vaddr - load_addr) as usize;
        if image.len() < start + filesz {
            image.resize(start + filesz, 0);
        }
        image[start..start + filesz].copy_from_slice(&bytes[offset..offset + filesz]);
    }
    assert!(
        entry >= load_addr && ((entry - load_addr) as usize) < image.len(),
        "the entry point is not inside the loaded image"
    );

    // The ranges an ELF loader has to clear: for every loadable segment, the
    // tail between its size on disk and its size in memory. That is exactly
    // `.bss`, and it is not one range: mold places `.relro_padding` before
    // `.data`, so the zero-initialised bytes of an image are not contiguous
    // with its static data.
    let mut zero_ranges: Vec<(u64, u64)> = Vec::new();
    for index in 0..phnum {
        let header = phoff + index * phentsize;
        let kind = u32::from_le_bytes(bytes[header..header + 4].try_into().unwrap());
        if kind != 1 {
            continue;
        }
        let vaddr = u64::from_le_bytes(bytes[header + 16..header + 24].try_into().unwrap());
        let filesz = u64::from_le_bytes(bytes[header + 32..header + 40].try_into().unwrap());
        let memsz = u64::from_le_bytes(bytes[header + 40..header + 48].try_into().unwrap());
        if memsz <= filesz {
            continue;
        }
        zero_ranges.push((vaddr + filesz, vaddr + memsz));
    }
    zero_ranges.sort_unstable();
    // Merge ranges that touch or overlap, so the stub clears each byte once.
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in zero_ranges {
        match merged.last_mut() {
            Some((_, last_end)) if start <= *last_end => *last_end = (*last_end).max(end),
            _ => merged.push((start, end)),
        }
    }

    FirmwareImage {
        load_addr,
        entry,
        zero_ranges: merged,
        image,
    }
}

/// The contents of one section of an ELF file, by name.
fn elf_section(path: &Path, name: &str) -> Vec<u8> {
    let bytes = fs::read(path).expect("ELF file");
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
    let shstrndx = u16::from_le_bytes(bytes[62..64].try_into().unwrap()) as usize;

    let names_header = shoff + shstrndx * shentsize;
    let names_off = u64::from_le_bytes(
        bytes[names_header + 24..names_header + 32]
            .try_into()
            .unwrap(),
    ) as usize;

    for index in 0..shnum {
        let header = shoff + index * shentsize;
        let name_off = u32::from_le_bytes(bytes[header..header + 4].try_into().unwrap()) as usize;
        let start = names_off + name_off;
        let end = bytes[start..].iter().position(|&b| b == 0).unwrap() + start;
        if &bytes[start..end] != name.as_bytes() {
            continue;
        }
        let offset =
            u64::from_le_bytes(bytes[header + 24..header + 32].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(bytes[header + 32..header + 40].try_into().unwrap()) as usize;
        return bytes[offset..offset + size].to_vec();
    }
    panic!("no section named {name} in {}", path.display());
}

fn run(command: &mut Command, what: &str) {
    let status = command.status().unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(status.success(), "{what} failed: {status}");
}
