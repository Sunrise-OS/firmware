//! PCIe: enumerating QEMU `virt`'s host bridge and giving its devices addresses.
//!
//! The GPEX host bridge exposes an ECAM in high memory: a function's 4 KiB of
//! configuration space is at `ECAM + (bus << 20 | slot << 15 | func << 12)`.
//! QEMU leaves every BAR unassigned - placing them is what PCI firmware is for -
//! so enumeration also assigns each memory BAR a window in the 32-bit MMIO
//! aperture, which the reset stage describes to Patina as device memory.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

/// The ECAM of QEMU `virt`'s high PCIe window.
const ECAM_BASE: usize = 0x40_1000_0000;
/// The 32-bit MMIO aperture: 0x1000_0000..0x3eff_0000.
const MMIO32_BASE: u64 = 0x1000_0000;
const MMIO32_END: u64 = 0x3eff_0000;
/// The I/O port aperture, as offsets into the PIO window.
const IO_BASE: u64 = 0x1000;
const IO_END: u64 = 0x1_0000;

/// Vendor ID an empty slot reads as.
const NO_DEVICE: u16 = 0xffff;
/// Header type 1: a PCI-to-PCI bridge.
const HEADER_TYPE_BRIDGE: u8 = 0x01;
/// The vendor ID virtio devices carry.
const VIRTIO_VENDOR: u16 = 0x1af4;

static MMIO_NEXT: AtomicU64 = AtomicU64::new(MMIO32_BASE);
static IO_NEXT: AtomicU64 = AtomicU64::new(IO_BASE);
static DEVICES: Once<Vec<PciDevice>> = Once::new();

/// One function on the bus.
#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
}

impl PciDevice {
    pub fn read32(&self, offset: u16) -> u32 {
        read32(self.bus, self.slot, self.func, offset)
    }

    pub fn write32(&self, offset: u16, value: u32) {
        write32(self.bus, self.slot, self.func, offset, value)
    }

    /// Enables memory decoding and bus mastering, so the BARs answer and the
    /// device may DMA.
    pub fn enable(&self) {
        let command = self.read32(0x04);
        let wanted = command | 0b110;
        if wanted != command {
            self.write32(0x04, wanted);
        }
    }

    pub fn is_virtio(&self) -> bool {
        self.vendor_id == VIRTIO_VENDOR
    }

    /// The identifier virtio-drivers' PCI transport takes.
    pub fn function(&self) -> virtio_drivers::transport::pci::bus::DeviceFunction {
        virtio_drivers::transport::pci::bus::DeviceFunction {
            bus: self.bus,
            device: self.slot,
            function: self.func,
        }
    }
}

fn ecam(bus: u8, slot: u8, func: u8, offset: u16) -> usize {
    ECAM_BASE
        | (bus as usize) << 20
        | (slot as usize) << 15
        | (func as usize) << 12
        | (offset as usize & 0xffc)
}

/// Reads a 32-bit configuration register.
pub fn read32(bus: u8, slot: u8, func: u8, offset: u16) -> u32 {
    // SAFETY: the ECAM is described to Patina as uncached device memory, and a
    // 32-bit access is the width configuration space requires.
    unsafe { core::ptr::read_volatile(ecam(bus, slot, func, offset) as *const u32) }
}

/// Writes a 32-bit configuration register.
pub fn write32(bus: u8, slot: u8, func: u8, offset: u16, value: u32) {
    // SAFETY: as `read32`.
    unsafe { core::ptr::write_volatile(ecam(bus, slot, func, offset) as *mut u32, value) }
}

fn read16(bus: u8, slot: u8, func: u8, offset: u16) -> u16 {
    (read32(bus, slot, func, offset & !2) >> ((offset & 2) * 8)) as u16
}

/// Every function on the bus, with bridges followed and BARs assigned.
/// Returns the single PCI enumeration shared by all platform drivers.
pub fn devices() -> &'static [PciDevice] {
    DEVICES.call_once(discover).as_slice()
}

/// Enumerates every function on the bus, with bridges followed and BARs assigned.
fn discover() -> Vec<PciDevice> {
    let mut found = Vec::new();
    scan_bus(0, &mut found, 0);
    for device in &found {
        assign_bars(device);
    }
    found
}

fn scan_bus(bus: u8, found: &mut Vec<PciDevice>, depth: usize) {
    if depth > 4 {
        return;
    }
    let first = found.len();
    for slot in 0..32u8 {
        if read16(bus, slot, 0, 0x00) == NO_DEVICE {
            continue;
        }
        push_function(bus, slot, 0, found);
        // The extra functions exist only when the multifunction bit is set.
        if (read32(bus, slot, 0, 0x0c) >> 16) & 0x80 == 0 {
            continue;
        }
        for func in 1..8u8 {
            if read16(bus, slot, func, 0x00) != NO_DEVICE {
                push_function(bus, slot, func, found);
            }
        }
    }
    // A bridge's bus registers name the bus behind it. Collected first, because
    // the recursive scan borrows `found`.
    let mut further = Vec::new();
    for device in &found[first..] {
        let header_type = (device.read32(0x0c) >> 16) as u8;
        if header_type & 0x7f == HEADER_TYPE_BRIDGE {
            let secondary = (device.read32(0x18) >> 8) as u8;
            if secondary > bus {
                further.push(secondary);
            }
        }
    }
    for secondary in further {
        scan_bus(secondary, found, depth + 1);
    }
}

fn push_function(bus: u8, slot: u8, func: u8, found: &mut Vec<PciDevice>) {
    let id = read32(bus, slot, func, 0x00);
    found.push(PciDevice {
        bus,
        slot,
        func,
        vendor_id: id as u16,
    });
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Takes an aligned window from an aperture, or `None` when it is exhausted.
fn take(cursor: &AtomicU64, end: u64, size: u64) -> Option<u64> {
    let base = align_up(cursor.load(Ordering::Acquire), size);
    let next = base.checked_add(size)?;
    if next > end {
        return None;
    }
    cursor.store(next, Ordering::Release);
    Some(base)
}

/// Sizes and places every BAR a function implements.
///
/// The size comes from the standard probe (write all ones, read back the bits
/// the device leaves writable). Decoding is off while the registers move, so the
/// device never decodes a half-written address. Every memory BAR goes in the
/// 32-bit aperture - a 64-bit BAR may live below 4 GiB, and the 64-bit aperture
/// is not described to Patina.
fn assign_bars(device: &PciDevice) {
    // Bridges have two BARs and a different layout; nothing behind QEMU's
    // default topology needs them assigned.
    if (device.read32(0x0c) >> 16) as u8 & 0x7f != 0 {
        return;
    }
    let command = device.read32(0x04);
    device.write32(0x04, command & !0b11);

    let mut index = 0u16;
    while index < 6 {
        let offset = 0x10 + index * 4;
        let original = device.read32(offset);
        let is_io = original & 0x1 != 0;
        let kind = (original >> 1) & 0x3;
        let is_64 = !is_io && kind == 0x2;

        device.write32(offset, 0xffff_ffff);
        let low = device.read32(offset);
        let mut high = 0u32;
        if is_64 {
            device.write32(offset + 4, 0xffff_ffff);
            high = device.read32(offset + 4);
        }
        let step = if is_64 { 2 } else { 1 };

        let size = if is_io {
            (!(low as u64 & 0xffff_fffc)).wrapping_add(1) & 0xffff
        } else {
            let mask = (high as u64) << 32 | (low & !0xf) as u64;
            let mask = if is_64 {
                mask
            } else {
                mask | 0xffff_ffff_0000_0000
            };
            if low & !0xf == 0 && high == 0 {
                0
            } else {
                (!mask).wrapping_add(1)
            }
        };
        if size == 0 {
            device.write32(offset, 0);
            index += step;
            continue;
        }

        let assigned = if is_io {
            take(&IO_NEXT, IO_END, size.max(4))
        } else {
            take(&MMIO_NEXT, MMIO32_END, size.max(16))
        };
        let Some(assigned) = assigned else {
            log::error!(
                "pci: {:02x}:{:02x}.{} bar{index}: no room for {size:#x} bytes",
                device.bus,
                device.slot,
                device.func
            );
            device.write32(offset, 0);
            index += step;
            continue;
        };
        device.write32(offset, (assigned as u32 & !0xf) | (original & 0xf));
        if is_64 {
            device.write32(offset + 4, (assigned >> 32) as u32);
        }
        log::info!(
            "pci: {:02x}:{:02x}.{} bar{index} {:#x} + {size:#x}",
            device.bus,
            device.slot,
            device.func,
            assigned
        );
        index += step;
    }
    device.write32(0x04, command | 0b11);
}
