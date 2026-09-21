//! The virtio PCI transport, over this machine's ECAM.
//!
//! virtio-drivers does the transport work; what it needs from the platform is
//! configuration-space access and a HAL. The configuration access is four lines
//! here because the firmware already has ECAM reads and writes.

use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::{ConfigurationAccess, DeviceFunction, PciRoot};

use super::hal::PlatformHal;
use crate::drivers::pci::{self, PciDevice};

/// The machine's PCI configuration space, as virtio-drivers sees it.
pub struct EcamAccess;

impl ConfigurationAccess for EcamAccess {
    fn read_word(&self, function: DeviceFunction, offset: u8) -> u32 {
        pci::read32(
            function.bus,
            function.device,
            function.function,
            offset as u16,
        )
    }

    fn write_word(&mut self, function: DeviceFunction, offset: u8, data: u32) {
        pci::write32(
            function.bus,
            function.device,
            function.function,
            offset as u16,
            data,
        );
    }

    unsafe fn unsafe_clone(&self) -> Self {
        EcamAccess
    }
}

/// Opens `device` as a virtio device.
///
/// Returns `None` for anything that is not a virtio function this crate can
/// drive: a non-virtio device, or one whose capabilities the transport cannot
/// find. Both are ordinary outcomes while enumerating a bus, so they are
/// reported rather than fatal.
pub fn open(device: &PciDevice) -> Option<PciTransport> {
    // Memory decoding and bus mastering first: the transport reads the device's
    // capability list out of its BARs, and a device that is not decoding memory
    // does not answer.
    device.enable();
    let mut root = PciRoot::new(EcamAccess);
    match PciTransport::new::<PlatformHal, EcamAccess>(&mut root, device.function()) {
        Ok(transport) => Some(transport),
        Err(error) => {
            let (bus, slot, func) = device.address();
            crate::println!("[pci] {bus:02x}:{slot:02x}.{func}: {error}");
            None
        }
    }
}
