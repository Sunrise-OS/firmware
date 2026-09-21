//! `mkesp`: builds the ESP disk image the firmware boots from.
//!
//! The image is a GPT disk with one EFI System Partition formatted FAT32, with
//! files written into it. The layout is written out here rather than taken from
//! a library because the tool has to agree with two other pieces of this
//! repository: the firmware's GPT parser (which checks the header CRCs and the
//! ESP type GUID) and its FAT reader.
//!
//! Usage: `mkesp <input.efi> <output.img> [src=dst ...]`, where `dst` is a
//! backslash-separated path inside the ESP and every name must fit 8.3 - the
//! image carries `\EFI\BOOT\BOOTAA64.EFI`, and nothing here needs long names.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// The sector size the image, the GPT, and the FAT volume share.
const SECTOR: usize = 512;
/// Default image size. An ESP holds a boot loader and maybe a kernel; 64 MiB is
/// roomy and writes in a moment.
const DEFAULT_SIZE_MB: usize = 64;
/// GPT entries: 128 of 128 bytes, in 32 sectors starting at LBA 2.
const GPT_ENTRIES: usize = 128;
const GPT_ENTRY_SIZE: usize = 128;
/// The first LBA a partition may start at: 1 header + 32 entry sectors + 1.
const FIRST_USABLE_LBA: u64 = 34;
/// The EFI System Partition type GUID, in the mixed-endian byte order a GPT
/// entry uses.
const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x93, 0xec, 0x93,
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <input.efi> <output.img> [src=dst ...]", args[0]);
        std::process::exit(2);
    }
    let size_mb: usize = std::env::var("MKESP_SIZE_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_SIZE_MB);

    let mut disk = Disk::new(size_mb * 1024 * 1024);
    disk.write_gpt();

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let boot = fs::read(&args[1]).unwrap_or_else(|e| panic!("reading {}: {e}", args[1]));
    files.push(("EFI\\BOOT\\BOOTAA64.EFI".to_string(), boot));
    for extra in &args[3..] {
        let (source, destination) = extra
            .split_once('=')
            .unwrap_or_else(|| panic!("expected src=dst, got {extra}"));
        files.push((
            destination.to_string(),
            fs::read(source).expect("reading source"),
        ));
    }

    let volume = Fat32::build(disk.partition_sectors(), &files);
    disk.copy_partition(&volume);
    disk.write_to(Path::new(&args[2]));
    Disk::verify(&disk, &files);

    println!(
        "mkesp: wrote {} ({} MiB, GPT + FAT32 ESP, {} file(s))",
        args[2],
        size_mb,
        files.len()
    );
}

/// The disk under construction.
struct Disk {
    bytes: Vec<u8>,
    first_lba: u64,
    last_lba: u64,
}

impl Disk {
    fn new(size_bytes: usize) -> Self {
        let sectors = (size_bytes / SECTOR) as u64;
        // Room for the primary header and entries, the partition, and the
        // backup entries and header.
        assert!(
            sectors > FIRST_USABLE_LBA + 33 + 8,
            "image too small for a GPT"
        );
        Disk {
            bytes: vec![0u8; size_bytes],
            first_lba: FIRST_USABLE_LBA,
            last_lba: sectors - 34,
        }
    }

    fn sector_mut(&mut self, lba: u64) -> &mut [u8] {
        let start = lba as usize * SECTOR;
        &mut self.bytes[start..start + SECTOR]
    }

    fn partition_sectors(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }

    fn write_gpt(&mut self) {
        let last_sector = (self.bytes.len() / SECTOR) as u64 - 1;

        // A protective MBR, so a tool that only understands the old scheme
        // sees a disk it must not touch.
        {
            let mbr = self.sector_mut(0);
            mbr[0x1be] = 0x00;
            mbr[0x1bf..0x1c2].copy_from_slice(&[0x00, 0x02, 0x00]);
            mbr[0x1c2] = 0xee;
            mbr[0x1c3..0x1c6].copy_from_slice(&[0xff, 0xff, 0xff]);
            mbr[0x1c6..0x1ca].copy_from_slice(&1u32.to_le_bytes());
            mbr[0x1ca..0x1ce].copy_from_slice(&(last_sector as u32).to_le_bytes());
            mbr[0x1fe..0x200].copy_from_slice(&[0x55, 0xaa]);
        }

        // One ESP, the rest of the entry array empty.
        let mut entries = vec![0u8; GPT_ENTRIES * GPT_ENTRY_SIZE];
        {
            let entry = &mut entries[..GPT_ENTRY_SIZE];
            entry[0..16].copy_from_slice(&ESP_TYPE_GUID);
            entry[16..32].copy_from_slice(&guid(0x01));
            entry[32..40].copy_from_slice(&self.first_lba.to_le_bytes());
            entry[40..48].copy_from_slice(&self.last_lba.to_le_bytes());
            let name = "WEIR ESP".encode_utf16().collect::<Vec<_>>();
            for (index, unit) in name.iter().enumerate() {
                entry[56 + index * 2..58 + index * 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        let entries_crc = crc32(&entries);

        // Primary header at LBA 1, pointed at the entries at LBA 2; backup
        // header in the last sector, pointed at the entries copied in front of
        // it. Each header's CRC covers the whole structure with its own field
        // zeroed.
        let primary = gpt_header(
            1,
            last_sector,
            2,
            self.first_lba,
            self.last_lba,
            entries_crc,
        );
        self.sector_mut(1).copy_from_slice(&primary);
        let backup_last = last_sector - 32;
        let backup = gpt_header(
            last_sector,
            1,
            backup_last,
            self.first_lba,
            self.last_lba,
            entries_crc,
        );
        self.sector_mut(last_sector).copy_from_slice(&backup);

        for (index, chunk) in entries.chunks(SECTOR).enumerate() {
            self.sector_mut(2 + index as u64).copy_from_slice(chunk);
        }
        for (index, chunk) in entries.chunks(SECTOR).enumerate() {
            self.sector_mut(backup_last + index as u64)
                .copy_from_slice(chunk);
        }
    }

    fn copy_partition(&mut self, volume: &[u8]) {
        let start = self.first_lba as usize * SECTOR;
        self.bytes[start..start + volume.len()].copy_from_slice(volume);
    }

    fn write_to(&self, path: &Path) {
        fs::write(path, &self.bytes).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    }

    /// Re-reads what was written and checks the structures the firmware parses.
    fn verify(disk: &Disk, files: &[(String, Vec<u8>)]) {
        let gpt = &disk.bytes[SECTOR..SECTOR * 2];
        assert_eq!(&gpt[0..8], b"EFI PART", "GPT signature");
        let header_size = u32::from_le_bytes(gpt[12..16].try_into().unwrap()) as usize;
        let mut header = gpt[..header_size].to_vec();
        let stored = u32::from_le_bytes(header[16..20].try_into().unwrap());
        header[16..20].fill(0);
        assert_eq!(crc32(&header), stored, "GPT header CRC32");

        let entries = &disk.bytes[SECTOR * 2..SECTOR * 2 + GPT_ENTRIES * GPT_ENTRY_SIZE];
        let stored = u32::from_le_bytes(gpt[88..92].try_into().unwrap());
        assert_eq!(crc32(entries), stored, "GPT entry-array CRC32");
        assert_eq!(entries[0..16], ESP_TYPE_GUID, "ESP type GUID");
        assert_eq!(
            u64::from_le_bytes(entries[32..40].try_into().unwrap()),
            FIRST_USABLE_LBA,
            "partition start LBA"
        );

        // The FAT volume, read the way the firmware's reader will: boot sector
        // fields, then the root directory's entries.
        let volume = &disk.bytes[disk.first_lba as usize * SECTOR..];
        assert_eq!(&volume[82..90], b"FAT32   ", "FAT32 type string");
        assert_eq!(&volume[71..82], b"WEIR ESP   ", "FAT32 volume label");
        assert_eq!(&volume[510..512], &[0x55, 0xaa], "boot sector signature");
        let fs_info_sector = u16::from_le_bytes(volume[48..50].try_into().unwrap()) as usize;
        let info = &volume[fs_info_sector * SECTOR..(fs_info_sector + 1) * SECTOR];
        assert_eq!(&info[0..4], b"RRaA", "FSInfo lead signature");
        assert_eq!(&info[484..488], b"rrAa", "FSInfo structure signature");

        let sectors_per_cluster = volume[13] as u64;
        let reserved = u16::from_le_bytes(volume[14..16].try_into().unwrap()) as u64;
        let fat_sectors = u32::from_le_bytes(volume[36..40].try_into().unwrap()) as u64;
        let cluster_bytes = (sectors_per_cluster * SECTOR as u64) as usize;
        let data_start = ((reserved + 2 * fat_sectors) * SECTOR as u64) as usize;
        let cluster = |number: u32| {
            let offset = data_start + (number as usize - 2) * cluster_bytes;
            &volume[offset..offset + cluster_bytes]
        };

        // Walk \EFI\BOOT and check the image is there with the right size.
        let root = cluster(2);
        let efi = find_entry(root, "EFI").expect("\\EFI in the root directory");
        let boot_dir = find_entry(cluster(efi), "BOOT").expect("\\EFI\\BOOT");
        let entry = find_entry_slot(cluster(boot_dir), "BOOTAA64.EFI").expect("the boot image");
        let size = u32::from_le_bytes(entry[28..32].try_into().unwrap()) as usize;
        assert_eq!(size, files[0].1.len(), "boot image size");
        // And the first cluster really holds the file's first bytes.
        let first = ((u16::from_le_bytes(entry[20..22].try_into().unwrap()) as usize) << 16)
            | u16::from_le_bytes(entry[26..28].try_into().unwrap()) as usize;
        let offset = data_start + (first - 2) * cluster_bytes;
        assert_eq!(
            &volume[offset..offset + size],
            &files[0].1[..],
            "boot image contents"
        );
        println!(
            "mkesp: verified GPT CRCs, FAT32 boot sector, and the {} byte boot image in \\EFI\\BOOT",
            size
        );
    }
}

/// The 32-byte directory entry named `name` in a directory cluster.
fn find_entry_slot<'a>(directory: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let wanted = to_83(name);
    for slot in directory.chunks_exact(32) {
        if slot[0] == 0 {
            break;
        }
        if slot[11] & 0x0f == 0x0f {
            continue; // a long-name slot
        }
        if slot[0..11] == wanted {
            return Some(slot);
        }
    }
    None
}

/// An entry's first cluster.
fn entry_cluster(entry: &[u8]) -> u32 {
    let high = u16::from_le_bytes(entry[20..22].try_into().unwrap()) as u32;
    let low = u16::from_le_bytes(entry[26..28].try_into().unwrap()) as u32;
    (high << 16) | low
}

/// An 8.3 directory entry's first cluster, from a directory cluster's bytes.
fn find_entry(directory: &[u8], name: &str) -> Option<u32> {
    find_entry_slot(directory, name).map(entry_cluster)
}

/// A GPT header sector, with its CRC32 filled in.
fn gpt_header(
    this_lba: u64,
    backup_lba: u64,
    entries_lba: u64,
    first_usable: u64,
    last_usable: u64,
    entries_crc: u32,
) -> [u8; SECTOR] {
    let mut header = [0u8; SECTOR];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[24..32].copy_from_slice(&this_lba.to_le_bytes());
    header[32..40].copy_from_slice(&backup_lba.to_le_bytes());
    header[40..48].copy_from_slice(&first_usable.to_le_bytes());
    header[48..56].copy_from_slice(&last_usable.to_le_bytes());
    header[56..72].copy_from_slice(&guid(0x10));
    header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    header[80..84].copy_from_slice(&(GPT_ENTRIES as u32).to_le_bytes());
    header[84..88].copy_from_slice(&(GPT_ENTRY_SIZE as u32).to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32(&header[..92]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    header
}

/// A stable GUID, so regenerating the image does not churn the identifiers.
fn guid(tag: u8) -> [u8; 16] {
    [
        0x57, 0x11, tag, 0x00, 0x57, 0x45, 0x49, 0x52, 0x80, 0x00, 0x57, 0x45, 0x49, 0x52, 0x00,
        tag,
    ]
}

/// A FAT32 volume, built in memory.
///
/// Directly, rather than through a library: the only client is this tool, the
/// layout is fixed, and the other end of it is the firmware's own reader.
struct Fat32 {
    volume: Vec<u8>,
    sectors_per_cluster: u64,
    reserved_sectors: u64,
    fat_sectors: u64,
    cluster_count: u64,
    /// One entry per cluster, starting at cluster 2.
    fat: Vec<u32>,
    next_cluster: u32,
    /// How many 32-byte slots of each directory cluster are in use.
    slots: HashMap<u32, usize>,
}

impl Fat32 {
    fn build(partition_sectors: u64, files: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut volume = Fat32 {
            volume: vec![0u8; (partition_sectors * SECTOR as u64) as usize],
            sectors_per_cluster: 8, // 4 KiB clusters
            reserved_sectors: 32,
            fat_sectors: 0,
            cluster_count: 0,
            fat: Vec::new(),
            next_cluster: 2,
            slots: HashMap::new(),
        };

        // The cluster count depends on the FAT size and the FAT size on the
        // cluster count; two passes settle both, as the specification says.
        let mut fat_sectors = 0u64;
        for _ in 0..2 {
            let data_sectors = partition_sectors - volume.reserved_sectors - 2 * fat_sectors;
            volume.cluster_count = data_sectors / volume.sectors_per_cluster;
            fat_sectors = ((volume.cluster_count + 2) * 4).div_ceil(SECTOR as u64);
        }
        volume.fat_sectors = fat_sectors;
        volume.fat = vec![0u32; (volume.cluster_count + 2) as usize];
        volume.fat[0] = 0x0fff_fff8;
        volume.fat[1] = 0x0fff_ffff;

        // The root directory is cluster 2, and it has no dot entries.
        volume.fat[2] = 0x0fff_ffff;
        volume.next_cluster = 3;
        volume.slots.insert(2, 0);

        for (path, contents) in files {
            volume.add_file(path, contents);
        }
        volume.finish();
        volume.volume
    }

    fn cluster_size(&self) -> usize {
        (self.sectors_per_cluster * SECTOR as u64) as usize
    }

    /// Where a cluster's bytes start in the volume.
    fn cluster_offset(&self, cluster: u32) -> usize {
        let data_start = self.reserved_sectors + 2 * self.fat_sectors;
        ((data_start + (cluster as u64 - 2) * self.sectors_per_cluster) * SECTOR as u64) as usize
    }

    fn allocate(&mut self, clusters: u64) -> u32 {
        let first = self.next_cluster;
        for index in 0..clusters {
            let cluster = first + index as u32;
            assert!(
                cluster as u64 + 1 < self.cluster_count + 2,
                "the image is full"
            );
            let next = if index + 1 == clusters {
                0x0fff_ffff
            } else {
                cluster + 1
            };
            self.fat[cluster as usize] = next;
        }
        self.next_cluster += clusters as u32;
        first
    }

    /// Adds `contents` at `path`, creating the directories on the way.
    fn add_file(&mut self, path: &str, contents: &[u8]) {
        let components: Vec<&str> = path.split(['\\', '/']).filter(|c| !c.is_empty()).collect();
        // With no directory components the parent is the root, cluster 2.
        assert!(!components.is_empty(), "a file needs a name: {path}");

        let mut parent = 2u32;
        for name in &components[..components.len() - 1] {
            parent = self.ensure_directory(parent, name);
        }

        let name = components[components.len() - 1];
        let clusters = contents.len().div_ceil(self.cluster_size()).max(1) as u64;
        let first = self.allocate(clusters);
        let size = contents.len() as u32;
        self.write_chain(first, contents);
        let entry = short_entry(name, first, size, 0x20);
        self.add_entry(parent, entry);
    }

    /// Finds or creates `name` inside `parent`, returning its first cluster.
    fn ensure_directory(&mut self, parent: u32, name: &str) -> u32 {
        if let Some(found) = self.find_child(parent, name) {
            return found;
        }
        let cluster = self.allocate(1);
        // A subdirectory starts with itself and its parent, which is what
        // makes `..` work for any reader.
        let mut dot = [0u8; 32];
        dot[0..11].copy_from_slice(b".          ");
        dot[11] = 0x10;
        dot[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        dot[26..28].copy_from_slice(&((cluster & 0xffff) as u16).to_le_bytes());
        let mut dotdot = [0u8; 32];
        dotdot[0..11].copy_from_slice(b"..         ");
        dotdot[11] = 0x10;
        dotdot[20..22].copy_from_slice(&((parent >> 16) as u16).to_le_bytes());
        dotdot[26..28].copy_from_slice(&((parent & 0xffff) as u16).to_le_bytes());
        self.add_entry(cluster, dot);
        self.add_entry(cluster, dotdot);
        let entry = short_entry(name, cluster, 0, 0x10);
        self.add_entry(parent, entry);
        cluster
    }

    /// The first cluster of a child of `parent`, if the name is already there.
    fn find_child(&self, parent: u32, name: &str) -> Option<u32> {
        let wanted = to_83(name);
        let offset = self.cluster_offset(parent);
        let directory = &self.volume[offset..offset + self.cluster_size()];
        for slot in directory.chunks_exact(32) {
            if slot[0] == 0 || slot[0] == 0xe5 {
                break;
            }
            if slot[11] & 0x0f == 0x0f {
                continue;
            }
            if slot[0..11] == wanted {
                let high = u16::from_le_bytes(slot[20..22].try_into().unwrap()) as u32;
                let low = u16::from_le_bytes(slot[26..28].try_into().unwrap()) as u32;
                return Some((high << 16) | low);
            }
        }
        None
    }

    /// Writes `contents` across the chain starting at `first`.
    fn write_chain(&mut self, first: u32, contents: &[u8]) {
        let cluster_size = self.cluster_size();
        let mut cluster = first;
        let mut written = 0;
        while written < contents.len() {
            let take = cluster_size.min(contents.len() - written);
            let offset = self.cluster_offset(cluster);
            self.volume[offset..offset + take].copy_from_slice(&contents[written..written + take]);
            written += take;
            cluster = self.fat[cluster as usize];
            if cluster >= 0x0fff_fff8 {
                break;
            }
        }
    }

    /// Appends a 32-byte entry to a directory cluster.
    fn add_entry(&mut self, directory: u32, entry: [u8; 32]) {
        let slot = {
            let next = self.slots.entry(directory).or_insert(0);
            let slot = *next;
            *next += 1;
            slot
        };
        let offset = self.cluster_offset(directory) + slot * 32;
        self.volume[offset..offset + 32].copy_from_slice(&entry);
    }

    /// Writes the boot sector, the FSInfo sectors, and both FAT copies.
    fn finish(&mut self) {
        let mut boot = [0u8; SECTOR];
        boot[0..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"WEIRESP ");
        boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        boot[13] = self.sectors_per_cluster as u8;
        boot[14..16].copy_from_slice(&(self.reserved_sectors as u16).to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xf8;
        boot[24..26].copy_from_slice(&32u16.to_le_bytes());
        boot[26..28].copy_from_slice(&64u16.to_le_bytes());
        boot[28..32].copy_from_slice(&(FIRST_USABLE_LBA as u32).to_le_bytes());
        boot[32..36].copy_from_slice(&((self.volume.len() / SECTOR) as u32).to_le_bytes());
        boot[36..40].copy_from_slice(&(self.fat_sectors as u32).to_le_bytes());
        // FAT32's extended BPB, at the offsets the specification gives:
        // ExtFlags 40, FSVer 42, RootClus 44, FSInfo 48, BkBootSec 50, and the
        // drive number at 64. Being four bytes out here puts every field the
        // reader wants one field late, which is exactly the bug this comment
        // exists to prevent.
        boot[40..42].copy_from_slice(&0u16.to_le_bytes()); // ext flags: mirror all FATs
        boot[42..44].copy_from_slice(&0u16.to_le_bytes()); // version 0.0
        boot[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        boot[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
        boot[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector
        boot[64] = 0x80; // drive number
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&0x5745_4952u32.to_le_bytes());
        boot[71..82].copy_from_slice(b"WEIR ESP   ");
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        self.volume[..SECTOR].copy_from_slice(&boot);
        self.volume[SECTOR * 6..SECTOR * 7].copy_from_slice(&boot);

        let mut fsinfo = [0u8; SECTOR];
        fsinfo[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        fsinfo[488..492].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        fsinfo[492..496].copy_from_slice(&u32::MAX.to_le_bytes());
        fsinfo[510..512].copy_from_slice(&[0x55, 0xaa]);
        self.volume[SECTOR..SECTOR * 2].copy_from_slice(&fsinfo);
        self.volume[SECTOR * 7..SECTOR * 8].copy_from_slice(&fsinfo);

        let mut fat_bytes = vec![0u8; self.fat_sectors as usize * SECTOR];
        for (index, value) in self.fat.iter().enumerate() {
            fat_bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let first_fat = self.reserved_sectors as usize * SECTOR;
        self.volume[first_fat..first_fat + fat_bytes.len()].copy_from_slice(&fat_bytes);
        let second_fat = first_fat + fat_bytes.len();
        self.volume[second_fat..second_fat + fat_bytes.len()].copy_from_slice(&fat_bytes);
    }
}

/// A directory entry for an 8.3 name.
fn short_entry(name: &str, first_cluster: u32, size: u32, attributes: u8) -> [u8; 32] {
    let mut entry = [0u8; 32];
    entry[0..11].copy_from_slice(&to_83(name));
    entry[11] = attributes;
    entry[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
    entry[26..28].copy_from_slice(&((first_cluster & 0xffff) as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    entry
}

/// An 8.3 name, space-padded and upper case, as FAT stores it.
fn to_83(name: &str) -> [u8; 11] {
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) => (stem, extension),
        None => (name, ""),
    };
    assert!(
        !stem.is_empty() && stem.len() <= 8 && extension.len() <= 3,
        "{name} is not a valid 8.3 name"
    );
    let mut out = [b' '; 11];
    for (index, byte) in stem.bytes().enumerate() {
        out[index] = byte.to_ascii_uppercase();
    }
    for (index, byte) in extension.bytes().enumerate() {
        out[8 + index] = byte.to_ascii_uppercase();
    }
    out
}

/// CRC-32 as GPT and FAT use it: reflected polynomial 0xEDB88320.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
