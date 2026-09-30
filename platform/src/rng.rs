//! Host-backed virtio entropy, exposed through EFI_RNG_PROTOCOL.
//! No software/deterministic fallback: the host is the trust boundary.

use crate::storage::{
    pci,
    virtio::{EcamAccess, PlatformHal},
};
use core::{ffi::c_void, ptr::NonNull};
use patina::component::{component, params::Handle};
use patina::error::Result;
use patina::standard::efi::{self, protocols::rng};
use patina::uefi::boot_services::{BootServices, StandardBootServices};
use spin::Mutex;
use virtio_drivers::device::common::Feature;
use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::pci::{PciTransport, bus::PciRoot};
use virtio_drivers::transport::{DeviceType, Transport};

const CHUNK: usize = 256;
const QUEUE_SIZE: usize = 8;
static RNG_GUID: efi::Guid = rng::PROTOCOL_GUID;

struct Source {
    transport: PciTransport,
    queue: VirtQueue<PlatformHal, QUEUE_SIZE>,
    // Firmware-lifetime DMA target. On timeout it must NOT be freed or reused:
    // the host may still complete the outstanding DMA request.
    buffer: NonNull<[u8; CHUNK]>,
    failed: bool,
}

impl Source {
    fn open(device: &pci::PciDevice) -> Option<Self> {
        // PciTransport::drop resets its device. Filter IDs BEFORE opening a
        // transport so probing cannot reset an already-live disk or GPU.
        let id = (device.read32(0) >> 16) as u16;
        if !device.is_virtio() || !matches!(id, 0x1005 | 0x1044) {
            return None;
        }
        device.enable();
        let mut root = PciRoot::new(EcamAccess);
        let mut transport =
            PciTransport::new::<PlatformHal, EcamAccess>(&mut root, device.function()).ok()?;
        if transport.device_type() != DeviceType::EntropySource {
            return None;
        }
        // Single direct descriptor; no indirect/event-index support needed.
        transport.begin_init(Feature::VERSION_1);
        let queue = VirtQueue::new(&mut transport, 0, false, false).ok()?;
        transport.finish_init();
        Some(Self {
            transport,
            queue,
            buffer: crate::publish::firmware_lifetime([0; CHUNK]),
            failed: false,
        })
    }

    fn fill(&mut self, output: &mut [u8]) -> efi::Status {
        if self.failed {
            return efi::Status::DEVICE_ERROR;
        }
        let services = crate::tables::boot_services();
        if services.is_null() {
            return efi::Status::NOT_READY;
        }
        for chunk in output.chunks_mut(CHUNK) {
            let mut done = 0;
            // One deadline covers short completions as well as a stalled host.
            let start = ticks();
            let timeout = frequency().saturating_mul(2);
            while done < chunk.len() {
                // SAFETY: the allocation is permanent, and no request is active
                // on entry; the mutex serializes access to this source.
                let buffer = unsafe { &mut (&mut *self.buffer.as_ptr())[..chunk.len() - done] };
                let token = match unsafe { self.queue.add(&[], &mut [buffer]) } {
                    Ok(token) => token,
                    Err(_) => {
                        self.failed = true;
                        return efi::Status::DEVICE_ERROR;
                    }
                };
                if self.queue.should_notify() {
                    self.transport.notify(0);
                }
                while !self.queue.can_pop() {
                    if ticks().wrapping_sub(start) >= timeout {
                        self.failed = true;
                        return efi::Status::TIMEOUT;
                    }
                    core::hint::spin_loop();
                }
                // SAFETY: same permanent buffer and token as submitted above.
                let count = match unsafe { self.queue.pop_used(token, &[], &mut [buffer]) } {
                    Ok(count) if count > 0 && count as usize <= buffer.len() => count as usize,
                    _ => {
                        self.failed = true;
                        return efi::Status::DEVICE_ERROR;
                    }
                };
                chunk[done..done + count].copy_from_slice(&buffer[..count]);
                buffer.fill(0);
                done += count;
                if done < chunk.len() && ticks().wrapping_sub(start) >= timeout {
                    self.failed = true;
                    return efi::Status::TIMEOUT;
                }
            }
        }
        efi::Status::SUCCESS
    }
}

fn ticks() -> u64 {
    let value;
    // SAFETY: the physical counter is accessible in the firmware execution level.
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) value, options(nomem, nostack));
    }
    value
}
fn frequency() -> u64 {
    let value;
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) value, options(nomem, nostack));
    }
    value
}

#[repr(C)]
struct Registry {
    protocol: rng::Protocol,
    source: Mutex<Source>,
}

pub struct Rng;
#[component]
impl Rng {
    fn entry_point(self, boot_services: StandardBootServices, image: Handle) -> Result<()> {
        crate::tables::init(&boot_services, *image);
        let Some(source) = pci::devices().iter().find_map(Source::open) else {
            log::warn!("rng: no virtio entropy device; EFI RNG unavailable");
            return Ok(());
        };
        let registry = crate::publish::firmware_lifetime(Registry {
            protocol: rng::Protocol { get_info, get_rng },
            source: Mutex::new(source),
        });
        // SAFETY: protocol is the first field of a permanent allocation.
        unsafe {
            boot_services.install_protocol_interface_unchecked(
                None,
                &RNG_GUID,
                registry.as_ptr() as *mut c_void,
            )?;
        }
        log::info!("rng: host-backed virtio entropy published as EFI RNG");
        Ok(())
    }
}

unsafe extern "efiapi" fn get_info(
    this: *mut rng::Protocol,
    size: *mut usize,
    algorithms: *mut rng::Algorithm,
) -> efi::Status {
    if this.is_null() || size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let needed = core::mem::size_of::<rng::Algorithm>();
    unsafe {
        if *size < needed {
            *size = needed;
            return efi::Status::BUFFER_TOO_SMALL;
        }
        if algorithms.is_null() {
            return efi::Status::INVALID_PARAMETER;
        }
        *size = needed;
        *algorithms = rng::ALGORITHM_RAW;
    }
    efi::Status::SUCCESS
}

unsafe extern "efiapi" fn get_rng(
    this: *mut rng::Protocol,
    algorithm: *mut rng::Algorithm,
    size: usize,
    output: *mut u8,
) -> efi::Status {
    if this.is_null() || output.is_null() || size == 0 || size > isize::MAX as usize {
        return efi::Status::INVALID_PARAMETER;
    }
    if !algorithm.is_null() && unsafe { *algorithm != rng::ALGORITHM_RAW } {
        return efi::Status::UNSUPPORTED;
    }
    let registry = unsafe { &*(this as *const Registry) };
    let Some(mut source) = registry.source.try_lock() else {
        return efi::Status::NOT_READY;
    };
    let output = unsafe { core::slice::from_raw_parts_mut(output, size) };
    let status = source.fill(output);
    if status != efi::Status::SUCCESS {
        output.fill(0);
    }
    status
}
