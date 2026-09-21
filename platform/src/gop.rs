//! Virtio-gpu scanout and EFI Graphics Output Protocol.

use core::ffi::c_void;

use patina::component::{component, params::Handle};
use patina::error::Result;
use patina::standard::efi::{self, protocols::graphics_output as gop};
use patina::uefi::boot_services::{BootServices, StandardBootServices};
use virtio_drivers::device::gpu::VirtIOGpu;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::pci::bus::PciRoot;
use virtio_drivers::transport::{DeviceType, Transport};

use crate::storage::{
    pci,
    virtio::{EcamAccess, PlatformHal},
};

type Device = VirtIOGpu<PlatformHal, PciTransport>;

struct Display {
    _gpu: Device,
    width: u32,
    height: u32,
    pixels: (*mut u8, usize),
}

impl Display {
    fn open(device: &pci::PciDevice) -> Option<Self> {
        if !device.is_virtio() {
            return None;
        }
        device.enable();
        let mut root = PciRoot::new(EcamAccess);
        let transport =
            PciTransport::new::<PlatformHal, EcamAccess>(&mut root, device.function()).ok()?;
        if transport.device_type() != DeviceType::GPU {
            return None;
        }
        let mut gpu = Device::new(transport).ok()?;
        let (width, height) = gpu.resolution().ok()?;
        let (pixels, pixel_len) = {
            let fb = gpu.setup_framebuffer().ok()?;
            (fb.as_mut_ptr(), fb.len())
        };
        Some(Self {
            _gpu: gpu,
            width,
            height,
            pixels: (pixels, pixel_len),
        })
    }
}

#[repr(C)]
struct Registry {
    protocol: gop::Protocol,
    mode: gop::Mode,
    info: gop::ModeInformation,
    display: Display,
}

static GOP_GUID: efi::Guid = gop::PROTOCOL_GUID;

pub struct Gop;

#[component]
impl Gop {
    fn entry_point(self, boot_services: StandardBootServices, image: Handle) -> Result<()> {
        crate::tables::init(&boot_services, *image);
        let Some(device) = pci::devices()
            .iter()
            .find_map(|device| Display::open(device))
        else {
            log::info!("gop: no virtio GPU found");
            return Ok(());
        };
        let (width, height) = (device.width, device.height);
        let (base, size) = device.pixels;
        let registry = crate::publish::firmware_lifetime(Registry {
            protocol: gop::Protocol {
                query_mode,
                set_mode,
                blt,
                mode: core::ptr::null_mut(),
            },
            mode: gop::Mode {
                max_mode: 1,
                mode: 0,
                info: core::ptr::null_mut(),
                size_of_info: core::mem::size_of::<gop::ModeInformation>(),
                frame_buffer_base: base as u64,
                frame_buffer_size: size,
            },
            info: gop::ModeInformation {
                version: 0,
                horizontal_resolution: width,
                vertical_resolution: height,
                pixel_format: gop::PIXEL_BLUE_GREEN_RED_RESERVED_8_BIT_PER_COLOR,
                pixel_information: gop::PixelBitmask {
                    red_mask: 0,
                    green_mask: 0,
                    blue_mask: 0,
                    reserved_mask: 0,
                },
                pixels_per_scan_line: width,
            },
            display: device,
        });
        // SAFETY: the published allocation is firmware-lifetime.
        let registry = unsafe { &mut *registry.as_ptr() };
        registry.mode.info = &mut registry.info;
        registry.protocol.mode = &mut registry.mode;
        // SAFETY: the registry is firmware-lifetime and its protocol is first.
        unsafe {
            boot_services.install_protocol_interface_unchecked(
                None,
                &GOP_GUID,
                &mut registry.protocol as *mut _ as *mut c_void,
            )?;
        }
        let base_addr = base as usize;
        log::info!("gop: virtio GPU {width}x{height}, framebuffer {base_addr:#x} ({size} bytes)");
        Ok(())
    }
}

unsafe extern "efiapi" fn query_mode(
    this: *mut gop::Protocol,
    mode: u32,
    size: *mut usize,
    info: *mut *mut gop::ModeInformation,
) -> efi::Status {
    if mode != 0 || size.is_null() || info.is_null() {
        return if mode != 0 {
            efi::Status::UNSUPPORTED
        } else {
            efi::Status::INVALID_PARAMETER
        };
    }
    unsafe {
        let registry = this as *mut Registry;
        *size = core::mem::size_of::<gop::ModeInformation>();
        *info = &mut (*registry).info;
    }
    efi::Status::SUCCESS
}

unsafe extern "efiapi" fn set_mode(_this: *mut gop::Protocol, mode: u32) -> efi::Status {
    if mode == 0 {
        efi::Status::SUCCESS
    } else {
        efi::Status::UNSUPPORTED
    }
}

unsafe extern "efiapi" fn blt(
    _this: *mut gop::Protocol,
    _buffer: *mut gop::BltPixel,
    _operation: gop::BltOperation,
    _sx: usize,
    _sy: usize,
    _dx: usize,
    _dy: usize,
    _width: usize,
    _height: usize,
    _delta: usize,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}
