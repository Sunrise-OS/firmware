//! The EDK2 DXE core image.
//!
//! A firmware built from TianoCore loads this in its DXE phase: EDK2's SEC and
//! PEI have brought the machine up and built the HOB list, and the entry point
//! below hands both to the platform. This is the image `rust/tools/rompatch`
//! puts into a QEMU firmware ROM, and it is the only part of this crate that
//! knows about an EFI entry point.
//!
//! The other host of the same platform is `rust/firmware`, this repository's own
//! firmware, which needs no EFI entry point because it calls [`start`] directly
//! from its own bring-up.
//!
//! [`start`]: tinted_boot_platform::start

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

use patina_stacktrace::StackTrace;

/// The DXE core's entry point.
///
/// # Safety
///
/// Called once by the PEI phase's handoff with a HOB list that outlives the DXE
/// phase, which is what the UEFI DXE handoff guarantees.
#[unsafe(export_name = "efi_main")]
unsafe extern "efiapi" fn entry(physical_hob_list: *const c_void) -> ! {
    // SAFETY: the HOB list is the boot stage's handoff, and this is the only
    // caller of the platform's entry point.
    unsafe { tinted_boot_platform::start(physical_hob_list) }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("{info}");
    if let Err(error) = unsafe { StackTrace::dump() } {
        log::error!("no stack trace: {error}");
    }
    // A firmware that keeps running after a panic does damage rather than report
    // a fault, and there is nothing sensible to return to.
    loop {
        // SAFETY: `wfi` waits for an interrupt; they are masked here, so this
        // parks the processor.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) }
    }
}
