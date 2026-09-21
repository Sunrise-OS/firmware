//! PCIe: enumerating the bus, and the configuration-space access a driver needs.
//!
//! QEMU's `virt` machine has one PCIe host bridge (the GPEX at 00:00.0) with an
//! ECAM in high memory: configuration space is a flat, memory-mapped window
//! where a function's 4 KiB block starts at `ecam + (bus << 20 | slot << 15 |
//! func << 12)`. Reading a device's vendor ID is therefore a memory read, and
//! enumeration is walking that window.
//!
//! The firmware does not assign BARs: QEMU's devices come out of reset with
//! usable addresses, which is how a machine boots with no firmware in front of
//! this one. It does enable the device's memory decoding and bus mastering, since
//! a driver that talks to a BAR needs both.

use alloc::vec::Vec;

use crate::platform;

/// Vendor ID read from an empty slot: every bit set.
const NO_DEVICE: u16 = 0xffff;
/// Header type 1: a PCI-to-PCI bridge, whose bus registers say what to scan next.
const HEADER_TYPE_BRIDGE: u8 = 0x01;

/// A base address register, as the device asked for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bar {
    /// Not implemented by the device.
    None,
    /// A 32-bit memory window, already assigned.
    Mem32 {
        address: u64,
        size: u64,
        prefetchable: bool,
    },
    /// A 64-bit memory window, already assigned.
    Mem64 {
        address: u64,
        size: u64,
        prefetchable: bool,
    },
    /// An I/O port window.
    Io { port: u64, size: u64 },
}

/// One function on the bus.
#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

impl PciDevice {
    /// The identifier the virtio driver's PCI transport takes.
    pub fn function(&self) -> virtio_drivers::transport::pci::bus::DeviceFunction {
        virtio_drivers::transport::pci::bus::DeviceFunction {
            bus: self.bus,
            device: self.slot,
            function: self.func,
        }
    }

    pub fn read32(&self, offset: u16) -> u32 {
        read32(self.bus, self.slot, self.func, offset)
    }

    pub fn write32(&self, offset: u16, value: u32) {
        write32(self.bus, self.slot, self.func, offset, value)
    }

    /// Enables memory decoding and bus mastering, so the device's BARs answer
    /// and it may DMA.
    pub fn enable(&self) {
        let command = self.read32(0x04);
        let wanted = command | 0b110; // memory space | bus master
        if wanted != command {
            self.write32(0x04, wanted);
        }
    }

    /// Reads BAR `index`, whether it is a 32-bit or a 64-bit window, and how
    /// large the device says it is.
    ///
    /// The size comes from the standard probe: write all ones, read back the
    /// address bits the device leaves writable, and restore the assigned
    /// address. That is the only way a BAR reports its own size, and it has to
    /// put the register back the way it found it.
    pub fn bar(&self, index: usize) -> Bar {
        let offset = 0x10 + (index as u16) * 4;
        let original = self.read32(offset);
        if original == 0 {
            return Bar::None;
        }

        self.write32(offset, 0xffff_ffff);
        let probed = self.read32(offset);
        self.write32(offset, original);

        if original & 0x1 != 0 {
            // An I/O window: the low two bits are control, the rest is the port.
            let mask = probed & !0x3;
            if mask == 0 {
                return Bar::None;
            }
            return Bar::Io {
                port: (original & !0x3) as u64,
                size: (!mask + 1) as u64,
            };
        }

        let kind = (original >> 1) & 0x3;
        let prefetchable = original & 0x8 != 0;
        match kind {
            0x1 => {
                // A 32-bit memory window.
                let mask = probed & !0xf;
                Bar::Mem32 {
                    address: (original & !0xf) as u64,
                    size: (!mask + 1) as u64,
                    prefetchable,
                }
            }
            0x2 => {
                // A 64-bit memory window: the high half is the next register.
                let high_offset = offset + 4;
                let original_high = self.read32(high_offset);
                self.write32(high_offset, 0xffff_ffff);
                let probed_high = self.read32(high_offset);
                self.write32(high_offset, original_high);

                let address = ((original_high as u64) << 32) | ((original & !0xf) as u64);
                let mask = ((probed_high as u64) << 32) | ((probed & !0xf) as u64);
                let size = if mask == 0 { 0 } else { !mask + 1 };
                Bar::Mem64 {
                    address,
                    size,
                    prefetchable,
                }
            }
            _ => Bar::None,
        }
    }

    /// A human-readable `bus:slot.function`.
    pub fn address(&self) -> (u8, u8, u8) {
        (self.bus, self.slot, self.func)
    }
}

/// Where the next memory and I/O window goes.
///
/// QEMU assigns no BARs: it leaves every device's base address registers zero
/// and lets firmware place them, which is what a PCI firmware is for. These
/// cursors are that allocator, and they stay inside the windows this firmware
/// maps.
///
/// Every memory BAR - 64-bit ones included - is placed in the 32-bit window.
/// QEMU's 64-bit window is at 512 GiB, above the 39-bit virtual address range
/// this firmware's page tables cover, and a 64-bit BAR is free to live in 32-bit
/// space so long as its address fits, which for a virtio device's few pages it
/// comfortably does.
static MMIO_NEXT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(platform::PCIE_MMIO32_BASE as u64);
static IO_NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x3eff_0000);

/// Assigns addresses to every BAR a function implements.
///
/// Each BAR is probed for the size it wants - write all ones and read back the
/// bits the device leaves writable - then given an aligned window in the right
/// region: I/O ports below 4 GiB, 32-bit memory in the 32-bit window, 64-bit
/// memory in the 64-bit one. Decoding is turned off while the registers move, so
/// a device never decodes a half-written address.
pub fn assign_bars(device: &PciDevice) {
    let command = device.read32(0x04);
    device.write32(0x04, command & !0b11);

    let mut index = 0usize;
    while index < 6 {
        let offset = 0x10 + (index as u16) * 4;
        let original = device.read32(offset);
        if original == 0 {
            index += 1;
            continue;
        }

        let is_io = original & 0x1 != 0;
        let kind = (original >> 1) & 0x3;
        let is_64 = !is_io && kind == 0x2;
        let prefetchable = original & 0x8 != 0;

        // Probe the size.
        device.write32(offset, 0xffff_ffff);
        let low_probe = device.read32(offset);
        let mut high_probe = 0u32;
        if is_64 {
            device.write32(offset + 4, 0xffff_ffff);
            high_probe = device.read32(offset + 4);
        }

        let (size, address) = if is_io {
            // I/O BARs address 16 bits of port space; the upper half reads as
            // zero through the mask.
            let mask = (low_probe & 0xffff_fffc) as u64;
            let size = (!mask).wrapping_add(1) & 0xffff;
            (size, None)
        } else {
            let mask = ((high_probe as u64) << 32) | ((low_probe & !0xf) as u64);
            let size = if mask == 0 {
                0
            } else {
                (!mask).wrapping_add(1)
            };
            (size, Some(is_64))
        };

        if size == 0 {
            // A BAR that reports no size is not implemented.
            device.write32(offset, 0);
            index += if is_64 { 2 } else { 1 };
            continue;
        }

        let assigned = if is_io {
            let cursor = IO_NEXT.load(core::sync::atomic::Ordering::Acquire);
            let base = align_up(cursor, size.max(4));
            IO_NEXT.store(base + size, core::sync::atomic::Ordering::Release);
            base
        } else {
            let cursor = MMIO_NEXT.load(core::sync::atomic::Ordering::Acquire);
            let base = align_up(cursor, size.max(16));
            MMIO_NEXT.store(base + size, core::sync::atomic::Ordering::Release);
            base
        };

        let flags = if is_io {
            0x1
        } else {
            ((kind as u32) << 1) | u32::from(prefetchable) << 3
        };
        device.write32(offset, (assigned as u32 & !0xf) | flags);
        if is_64 {
            device.write32(offset + 4, (assigned >> 32) as u32);
        }

        let (bus, slot, func) = device.address();
        crate::println!(
            "[pci] {bus:02x}:{slot:02x}.{func} bar{index} {:#x} + {:#x}",
            assigned,
            size
        );
        index += if is_64 { 2 } else { 1 };
    }

    device.write32(0x04, command | 0b11);
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// The ECAM address of a function register.
fn ecam(bus: u8, slot: u8, func: u8, offset: u16) -> usize {
    platform::PCIE_ECAM_BASE
        | ((bus as usize) << 20)
        | ((slot as usize) << 15)
        | ((func as usize) << 12)
        | (offset as usize & 0xffc)
}

/// Reads a 32-bit configuration register.
pub fn read32(bus: u8, slot: u8, func: u8, offset: u16) -> u32 {
    // SAFETY: the ECAM window is mapped as device memory at a known address, and
    // a 32-bit access is the width configuration space requires.
    unsafe { core::ptr::read_volatile(ecam(bus, slot, func, offset) as *const u32) }
}

/// Writes a 32-bit configuration register.
pub fn write32(bus: u8, slot: u8, func: u8, offset: u16, value: u32) {
    // SAFETY: as `read32`.
    unsafe { core::ptr::write_volatile(ecam(bus, slot, func, offset) as *mut u32, value) }
}

/// Reads a 16-bit configuration register.
pub fn read16(bus: u8, slot: u8, func: u8, offset: u16) -> u16 {
    let word = read32(bus, slot, func, offset & !2);
    let shift = (offset & 2) * 8;
    (word >> shift) as u16
}

/// Every function on the bus, with bridges followed.
///
/// A bridge's bus registers name the bus behind it, so the walk is recursive:
/// scan a bus, and for each bridge found, scan the bus it leads to. `depth`
/// bounds the recursion so a device with a nonsense bus number cannot loop.
pub fn discover() -> Vec<PciDevice> {
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
    for slot in 0..32u8 {
        // Function 0 decides whether the slot answers at all; the extra
        // functions only exist when the multifunction bit is set.
        let vendor = read16(bus, slot, 0, 0x00);
        if vendor == NO_DEVICE {
            continue;
        }
        push_function(bus, slot, 0, found);

        let header_type = read32(bus, slot, 0, 0x0c) >> 16;
        if header_type & 0x80 == 0 {
            continue;
        }
        for func in 1..8u8 {
            let vendor = read16(bus, slot, func, 0x00);
            if vendor != NO_DEVICE {
                push_function(bus, slot, func, found);
            }
        }
    }

    // Follow bridges. Collected first, because `scan_bus` borrows `found`.
    let mut further: Vec<u8> = Vec::new();
    for device in found.iter() {
        if device.bus != bus || device.func != 0 {
            continue;
        }
        let header_type = (read32(device.bus, device.slot, device.func, 0x0c) >> 16) as u8;
        if header_type & 0x7f != HEADER_TYPE_BRIDGE {
            continue;
        }
        let bus_numbers = read32(device.bus, device.slot, device.func, 0x18);
        let secondary = (bus_numbers >> 8) as u8;
        if secondary > bus {
            further.push(secondary);
        }
    }
    for secondary in further {
        scan_bus(secondary, found, depth + 1);
    }
}

fn push_function(bus: u8, slot: u8, func: u8, found: &mut Vec<PciDevice>) {
    let id = read32(bus, slot, func, 0x00);
    let class = read32(bus, slot, func, 0x08);
    found.push(PciDevice {
        bus,
        slot,
        func,
        vendor_id: id as u16,
        device_id: (id >> 16) as u16,
        class: (class >> 24) as u8,
        subclass: (class >> 16) as u8,
        prog_if: (class >> 8) as u8,
    });
}

/// Every function whose class is "display controller" or whose vendor is the
/// one virtio devices carry. Used by the driver probes to log what is there.
pub fn is_virtio(device: &PciDevice) -> bool {
    device.vendor_id == 0x1af4
}
