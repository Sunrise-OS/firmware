//! `EFI_GRAPHICS_OUTPUT_PROTOCOL`, over the machine's display.
//!
//! The protocol is three structures that point at each other - protocol, mode,
//! mode info - and one framebuffer. All four live in a single static registry
//! written once during bring-up: the framebuffer is the display's own DMA
//! memory, whose address the device scans out of for the rest of the boot, so
//! the owner has to be the program itself rather than an allocation something
//! might reclaim. Applications draw straight into `Mode->FrameBufferBase` and
//! the pixels reach the screen through the device; `Blt` answers unsupported,
//! which is what the reference firmware does - blitting here would be a pixel
//! path nothing on this platform exercises.
//!
//! A machine with no display gets no protocol: an application that locates a
//! GOP stops looking for a framebuffer, so publishing one that scans out
//! nothing would be worse than publishing none, and the boot continues either
//! way.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use r_efi::base::Status;
use r_efi::protocols::graphics_output::{
    BltOperation, BltPixel, Mode, ModeInformation, PIXEL_BLUE_GREEN_RED_RESERVED_8_BIT_PER_COLOR,
    PixelBitmask, Protocol,
};

use crate::drivers::virtio::gpu::Display;
use crate::uefi::{self, handles};

/// The registry: protocol, mode, mode info, and the display that owns the
/// framebuffer. `repr(C)` with the protocol first, so the registry's address
/// is the protocol's address - that is the pointer installed on the handle,
/// and `mode`/`info` are found by field, never by casting the protocol back.
#[repr(C)]
struct Registry {
    protocol: Protocol,
    mode: Mode,
    info: ModeInformation,
    display: Display,
}

/// The one registry, filled in by `install` before any EFI caller can reach
/// the protocol pointer that aims into it.
static mut REGISTRY: MaybeUninit<Registry> = MaybeUninit::uninit();

/// Installs `EFI_GRAPHICS_OUTPUT_PROTOCOL` on a fresh handle over the
/// machine's display. `NOT_FOUND` (and a line on the console) when the machine
/// has no display - a valid outcome: the boot continues without a framebuffer
/// to find.
pub fn install() -> Status {
    let mut display = match find_display() {
        Some(display) => display,
        None => {
            crate::println!("[gop] no display");
            return Status::NOT_FOUND;
        }
    };

    let (width, height) = display.resolution();
    // Take the framebuffer's address while the display is still ours to borrow;
    // after the write below it belongs to the registry. The buffer was set up
    // when the display opened, so this cannot fail or move it.
    let (frame_buffer_base, frame_buffer_size) = {
        let pixels = display.framebuffer();
        (pixels.as_ptr() as u64, pixels.len())
    };

    // SAFETY: single-threaded bring-up; the registry is static storage and
    // this is its one write, before the protocol pointer into it is installed
    // on any handle. The three self-pointers are fixed up in the same block.
    unsafe {
        (*core::ptr::addr_of_mut!(REGISTRY)).write(Registry {
            protocol: Protocol {
                query_mode,
                set_mode,
                blt,
                mode: core::ptr::null_mut(),
            },
            mode: Mode {
                max_mode: 1,
                mode: 0,
                info: core::ptr::null_mut(),
                size_of_info: core::mem::size_of::<ModeInformation>(),
                frame_buffer_base,
                frame_buffer_size,
            },
            info: ModeInformation {
                // The reference firmware's value: zero, the only version
                // defined.
                version: 0,
                horizontal_resolution: width,
                vertical_resolution: height,
                // XRGB8888 as the device lays the bytes out: blue at the
                // lowest address, which is the enum's BlueGreenRed form (1).
                // The reference firmware argues the swap at length - the
                // RedGreenRed naming would advertise red and blue exchanged
                // and every app that trusts the enum would paint wrong.
                pixel_format: PIXEL_BLUE_GREEN_RED_RESERVED_8_BIT_PER_COLOR,
                pixel_information: PixelBitmask {
                    red_mask: 0,
                    green_mask: 0,
                    blue_mask: 0,
                    reserved_mask: 0,
                },
                // No padding: a line is exactly the visible width.
                pixels_per_scan_line: width,
            },
            display,
        });
        // Close the chain protocol -> mode -> info, each field inside the
        // registry that outlives every image.
        let registry = core::ptr::addr_of_mut!(REGISTRY).cast::<Registry>();
        (*registry).mode.info = core::ptr::addr_of_mut!((*registry).info);
        (*registry).protocol.mode = core::ptr::addr_of_mut!((*registry).mode);
    }

    // SAFETY: `repr(C)` puts `protocol` at offset 0 of the registry, and
    // `MaybeUninit` is transparent over it, so the registry's address is the
    // protocol's; the registry is static and outlives every handle.
    let _ = handles::install_new(
        &uefi::GRAPHICS_OUTPUT_PROTOCOL_GUID,
        core::ptr::addr_of_mut!(REGISTRY).cast::<c_void>(),
    );
    crate::println!(
        "[gop] virtio-gpu {width}x{height} XRGB8888, framebuffer @ {frame_buffer_base:#x} ({} KiB)",
        frame_buffer_size / 1024
    );
    Status::SUCCESS
}

/// The machine's display: the first PCI device that opens as the virtio GPU.
fn find_display() -> Option<Display> {
    crate::drivers::pci::discover()
        .iter()
        .find_map(Display::open)
}

/// `QueryMode`: mode 0 is the one mode, and its info lives in the registry.
unsafe extern "efiapi" fn query_mode(
    _this: *mut Protocol,
    mode_number: u32,
    size_of_info: *mut usize,
    info: *mut *mut ModeInformation,
) -> Status {
    if size_of_info.is_null() || info.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if mode_number != 0 {
        return Status::UNSUPPORTED;
    }
    // SAFETY: the protocol this arrived through points into the registry, so
    // `install` ran and wrote it; the out-pointers were checked non-null
    // above. Handing out the address of a static is valid for as long as any
    // caller can hold the protocol.
    unsafe {
        *size_of_info = core::mem::size_of::<ModeInformation>();
        *info =
            core::ptr::addr_of_mut!((*core::ptr::addr_of_mut!(REGISTRY).cast::<Registry>()).info);
    }
    Status::SUCCESS
}

/// `SetMode`: mode 0 is the mode the display was opened in and is already the
/// scanout, so accepting it is the whole change. Any other mode does not
/// exist.
unsafe extern "efiapi" fn set_mode(_this: *mut Protocol, mode_number: u32) -> Status {
    if mode_number != 0 {
        return Status::UNSUPPORTED;
    }
    Status::SUCCESS
}

/// `Blt`: unsupported. Applications draw into `Mode->FrameBufferBase`
/// themselves, as the reference firmware's applications do.
unsafe extern "efiapi" fn blt(
    _this: *mut Protocol,
    _buffer: *mut BltPixel,
    _operation: BltOperation,
    _source_x: usize,
    _source_y: usize,
    _destination_x: usize,
    _destination_y: usize,
    _width: usize,
    _height: usize,
    _delta: usize,
) -> Status {
    Status::UNSUPPORTED
}
