# Tinted-Boot

UEFI firmware for QEMU's AArch64 `virt` machine, with Patina as the DXE core
and no TianoCore in the boot chain:

- **`firmware/`** brings up the machine before DXE: translation, console,
  device tree, HOB list, and loading the DXE core from a PI firmware volume.
- **`platform/`** supplies Patina's DXE core and the machine-specific components,
  built as an AArch64 EFI boot-service-driver PE image.

`tools/mkimage` puts a reset trampoline, the RAM-linked firmware, and a genuine
FFS2 firmware volume in one flash image. The volume contains a DXE_CORE FFS file
with a PE32 section. QEMU's `-bios` executes at offset zero rather than locating
an FV, so the trampoline copies the firmware and the FV to RAM. The firmware
parses the FV with Patina's FFS reader, loads the PE, and publishes an FV HOB:
Patina installs the FV/FVB protocols and dispatches its files from that volume.

There is no EDK2, PEI, or secure world. The machine starts at QEMU's reset
exception level and drops to EL1 for DXE.

```
.                      # this repository
  firmware/            # reset-stage machine bring-up and DXE handoff
  platform/            # Patina platform for QEMU virt
  testapp/             # EFI application that exercises services
  tools/mkimage        # packs reset code, firmware, and PI firmware volume
  tools/mkesp          # builds a GPT + FAT ESP disk image
  tools/rompatch       # puts a DXE core image into an EDK2 firmware ROM
  third_party/patina   # Patina, as a pinned submodule
  scripts/             # run-armvirt.sh, prepare-patina.sh
  docs/                # see the repository's own docs/ for the whole firmware
```

## Building and running

```
scripts/run-armvirt.sh            # build an ESP carrying testapp, and boot it
scripts/run-armvirt.sh esp.img    # boot \EFI\BOOT\BOOTAA64.EFI from your own ESP
```

The platform adds what Patina leaves to a platform: the timer, metronome and
watchdog architectural protocols, a PL011 text console in `ConIn`/`ConOut`, and
the storage stack - PCI enumeration, virtio-blk, GPT and FAT - published as
Block I/O and Simple File System with `PciRoot/Pci/HD` device paths. BDS boots
the removable-media path `\EFI\BOOT\BOOTAA64.EFI` from the first volume that
has it, through Patina's `LoadImage`; there are no variable services yet, so
there is no `BootOrder`.

The script builds the firmware and the DXE core, packs them, and starts QEMU.
The steps on their own:

```
cargo build --release -p tinted-uefi-firmware --target aarch64-unknown-none
cargo build --release -p tinted-boot-platform --target aarch64-unknown-uefi --features edk2
cargo run --release -p mkimage -- \
    target/aarch64-unknown-none/release/tinted-boot-aarch64 \
    target/tinted-boot-aarch64.bin \
    target/aarch64-unknown-uefi/release/tinted-armvirt-dxe-core.efi
```

Three things about that are deliberate:

- **The toolchain is pinned to Rust 1.95.0.** Patina 23 is written against the
  variadic-argument interface as it stood while `c_variadic` was unstable, and
  1.99 stabilized the feature with the method renamed. `rust-toolchain.toml`
  pins 1.95.0, and `.cargo/config.toml` sets the flags and `RUSTC_BOOTSTRAP=1`
  that Patina's own build script verifies — Patina's supported arrangement, on
  stable rather than nightly.
- **Patina is a submodule, not a vendored copy.** `third_party/patina` is pinned
  to the commit that published the crates this firmware uses, every Patina crate
  resolves into it by path, and the one rename the newer interface needs is a
  patch file that `scripts/prepare-patina.sh` applies. See
  `third_party/README.md`.
- **The machine is started with GICv3.** The platform describes a GICv3 to the
  core and to the operating system, which is what `-machine virt,gic-version=3`
  gives the machine.

## Running under an EDK2 firmware instead

For comparison, or to run the platform where a vendor firmware is the only
option, the same DXE core image can be put into an EDK2 firmware ROM:

```
cargo build --release -p tinted-boot-platform --target aarch64-unknown-uefi --features edk2
cargo run --release -p rompatch -- \
    --rom QEMU_EFI.fd \
    --pe target/aarch64-unknown-uefi/release/tinted-armvirt-dxe-core.efi \
    --out patched.fd
```

`rompatch` rewrites the firmware volume's DXE core image in place, so it needs
none of EDK2's BaseTools. `--dump` prints the ROM's structure, and `--extract`
writes out the DXE core the ROM currently carries.

[patina]: https://github.com/OpenDevicePartnership/patina
