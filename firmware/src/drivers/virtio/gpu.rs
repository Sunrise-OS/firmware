//! virtio-gpu: scan-out for the graphics output protocol.
//!
//! The machine's one GPU is a virtio-gpu PCI device. This module wraps the
//! virtio-drivers controller in the surface the protocol layer wants: the
//! resolution, the pixel buffer to draw into, and a flush that pushes what was
//! drawn to the scanout. The framebuffer is a DMA buffer the device keeps
//! scanning out of, so it is set up once, here, and the pointer handed out for
//! the rest of the boot - the same lifetime the reference firmware gives its
//! pixel memory.

use virtio_drivers::device::gpu::VirtIOGpu;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::{DeviceType, Transport};

use crate::drivers::pci::PciDevice;
use crate::drivers::virtio::hal::PlatformHal;
use crate::drivers::virtio::pci::open;

/// Red Hat's vendor ID, which every virtio PCI device carries. Checked before
/// opening: the transport is only for virtio functions.
const VIRTIO_VENDOR_ID: u16 = 0x1af4;

/// The controller: the virtio-gpu driver over the platform HAL and the PCI
/// transport.
type Gpu = VirtIOGpu<PlatformHal, PciTransport>;

/// The display: the controller, the geometry it reports, and the pixel buffer
/// it owns. The buffer lives inside the controller's DMA allocation, which
/// stays valid exactly as long as this struct does - which is why the
/// protocol layer keeps one in static storage rather than handing the
/// framebuffer out on its own.
pub struct Display {
    gpu: Gpu,
    width: u32,
    height: u32,
    /// The pixel buffer, captured when the framebuffer was set up in `open`.
    /// Raw parts rather than a slice because the slice borrows `self`, and the
    /// protocol layer needs the pointer while owning the `Display` itself.
    pixels: (*mut u8, usize),
}

impl Display {
    /// Opens `device` when it is the machine's virtio-gpu, and sets up its
    /// framebuffer; anything else, a device that fails to start, or a machine
    /// with no display yields `None`.
    pub fn open(device: &PciDevice) -> Option<Display> {
        if device.vendor_id != VIRTIO_VENDOR_ID {
            return None;
        }
        let transport = open(device)?;
        // The device type comes from the transport rather than a table of PCI
        // device IDs here: the crate knows that mapping, transitional and modern
        // numbering included, and this is the one place it stays correct.
        if transport.device_type() != DeviceType::GPU {
            return None;
        }
        let mut gpu = Gpu::new(transport).ok()?;
        let (width, height) = gpu.resolution().ok()?;
        // Set up here rather than lazily in `framebuffer()`: a device that
        // cannot allocate a scanout is one that must not be published as a
        // display at all, and this way that failure ends the option instead of
        // surfacing after the protocol has advertised the buffer.
        let pixels = gpu.setup_framebuffer().ok()?;
        let pixels = (pixels.as_mut_ptr(), pixels.len());
        Some(Display {
            gpu,
            width,
            height,
            pixels,
        })
    }

    /// The resolution the device reports for its scanout.
    pub fn resolution(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// The pixel buffer: XRGB8888, `width * 4` bytes per scan line, as long as
    /// this `Display` lives.
    pub fn framebuffer(&mut self) -> &mut [u8] {
        let (pointer, length) = self.pixels;
        // SAFETY: `pointer` and `length` come from `setup_framebuffer`, whose
        // buffer is owned by `self.gpu`'s DMA allocation and is not freed or
        // resized after `open`; `&mut self` guarantees no aliasing slice.
        unsafe { core::slice::from_raw_parts_mut(pointer, length) }
    }

    /// Pushes what was drawn into the framebuffer to the scanout. Writes into
    /// the buffer only reach the host screen once they are transferred, so a
    /// drawing loop calls this after it paints.
    pub fn flush(&mut self) {
        // A failed transfer means the device rejected the update; there is no
        // caller to report it to and retrying here would spin, so the screen
        // simply keeps the last frame the device accepted.
        let _ = self.gpu.flush();
    }
}
