//! Mounts an image this tool produced, with the reader the firmware uses.

use std::io::Cursor;

use hadris_fat::sync::{FatVolume, FatVolumeBuilder, FatVolumeReadExt, Read};

#[test]
fn the_image_mounts_and_holds_the_boot_image() {
    let path = std::env::var("MKESP_IMAGE").unwrap_or_else(|_| "/tmp/esp-test.img".into());
    let image = match std::fs::read(&path) {
        Ok(image) => image,
        Err(_) => return, // no image built in this environment
    };
    let first_lba = 34usize;
    let last_lba = 131038usize;
    let partition = &image[first_lba * 512..(last_lba + 1) * 512];

    let volume: FatVolume<_> = FatVolumeBuilder::new(Cursor::new(partition))
        .open()
        .expect("the volume mounts");
    let root = volume.root_dir();
    let names: Vec<String> = root
        .entries()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.as_entry().map(|entry| entry.name().to_string()))
        .collect();
    assert!(
        names.iter().any(|name| name.eq_ignore_ascii_case("EFI")),
        "names: {names:?}"
    );

    let efi = root
        .entries()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.as_entry().cloned())
        .find(|entry| entry.name().eq_ignore_ascii_case("EFI"))
        .expect("EFI directory");
    let boot = root_for(&efi, &volume);
    let image_entry = boot
        .entries()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.as_entry().cloned())
        .find(|entry| entry.name().eq_ignore_ascii_case("BOOTAA64.EFI"))
        .expect("the boot image");
    let mut reader = volume.read_file(&image_entry).expect("a reader");
    let mut buffer = vec![0u8; image_entry.len() as usize];
    reader.read_exact(&mut buffer).expect("the image reads");
    assert_eq!(&buffer[0..2], b"MZ", "a PE image starts with MZ");
}

fn root_for<'a>(
    entry: &hadris_fat::sync::FileEntry,
    volume: &'a FatVolume<Cursor<&[u8]>>,
) -> hadris_fat::sync::FatDir<'a, Cursor<&[u8]>> {
    volume.open_dir_entry(entry).expect("a directory")
}
