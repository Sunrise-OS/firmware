#!/bin/sh
# Build the firmware and its DXE core, pack them into one flash image, and boot
# QEMU's AArch64 virt machine with it.
#
#   scripts/run-armvirt.sh [esp.img]
#
# The disk attaches as virtio-blk, and BDS boots \EFI\BOOT\BOOTAA64.EFI from it.
# Without an argument, an ESP carrying `testapp` is built into target/esp.img.
#
# Two images are built: the RAM-linked firmware brings up translation, console
# and the device tree; the platform crate is Patina's DXE core as an EFI PE.
# `mkimage` places that PE in a PI firmware volume. QEMU resets at flash offset
# zero, so a small trampoline copies both the firmware and FV into RAM; the
# firmware loads the core from the FV and passes its FV HOB to Patina.
# No EDK2 or secure world is involved.
set -e

here=$(cd "$(dirname "$0")/.." && pwd)

esp=${1:-}

"$here/scripts/prepare-patina.sh"
cd "$here"
cargo build --release -p tinted-uefi-firmware --target aarch64-unknown-none
cargo build --release -p tinted-boot-platform --target aarch64-unknown-uefi --features edk2
cargo run --release -q -p mkimage -- \
    target/aarch64-unknown-none/release/tinted-boot-aarch64 \
    target/tinted-boot-aarch64.bin \
    target/aarch64-unknown-uefi/release/tinted-armvirt-dxe-core.efi

if [ -z "$esp" ]; then
    cargo build --release -p tinted-boot-testapp --target aarch64-unknown-uefi
    cargo run --release -q -p mkesp -- \
        target/aarch64-unknown-uefi/release/bootaa64.efi target/esp.img
    esp=target/esp.img
fi
set -- \
    -drive "file=$esp,if=none,id=esp,format=raw" \
    -device virtio-blk-pci,drive=esp

# The machine is started with GICv3 because the platform describes a GICv3 to the
# core and to the operating system: distributor, redistributors per core. Its
# boot stages do not touch the interrupt controller, so this is the one place
# that decides.
#
# HVF runs the guest on the host's own cores, so it takes the host's CPU model
# and rejects any other; TCG is a model of a machine and is given the model this
# platform's addresses and tables are written for, so a run is the same wherever
# it happens. The firmware itself runs the same either way - the acceleration is
# what changes, and with it whether the core's undefined behaviour is reported
# (HVF) or quietly tolerated (TCG).
case "${ACCEL:-tcg}" in
    hvf) cpu=host ;;
    *) cpu=cortex-a57 ;;
esac
#
# The host QEMU links against dylibs in /usr/local/lib but carries no rpath, so
# the loader has to be told where they are.
DYLD_FALLBACK_LIBRARY_PATH=${DYLD_FALLBACK_LIBRARY_PATH:-/usr/local/lib} \
exec "${QEMU:-qemu-system-aarch64}" \
    -machine virt,acpi=off,gic-version=3 \
    -cpu "$cpu" \
    -smp 4 \
    -m 4G \
    -accel "${ACCEL:-tcg}" \
    -device virtio-gpu-rutabaga-pci,gfxstream-vulkan=on,blob=on,hostmem=256M \
    -display none \
    -no-reboot \
    -serial mon:stdio \
    -bios target/tinted-boot-aarch64.bin \
    "$@"
