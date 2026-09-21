//! Patina platform for QEMU's AArch64 `virt` machine.
//!
//! Patina is the DXE phase of a UEFI firmware: it provides the boot and runtime
//! services, the protocol database, events and TPLs, the dispatcher, the CPU and
//! paging support, and the ACPI and SMBIOS services. A platform supplies what is
//! specific to a machine, and that is what this crate is: the machine's
//! addresses, its identity in the tables an operating system reads, and
//! eventually its drivers.
//!
//! The `Core` this crate defines is entered through [`start`], which takes the
//! HOB list of the handoff and never returns. Two hosts call it:
//!
//! * `bin/edk2-dxe-core.rs`, the DXE core PE image embedded in an EDK2 FV.
//!   EDK2's SEC and PEI phases brought the machine up and built the HOB list.
//! * `firmware/`, this repository's own reset stage, which brings the machine
//!   up, loads this DXE core from its FV, and publishes that FV through a HOB
//!   rather than depending on TianoCore's PEI.
//!
//! Both paths end in the same call, with the same contract: the machine is in
//! its final state, the HOB list describes the memory the core may use, and
//! nothing else is running.

#![no_std]

extern crate alloc;

mod arch;
mod boot;
mod console;
mod gop;
mod publish;
pub mod smbios;
mod storage;
mod tables;

use core::ffi::c_void;

use patina::{debug::log::Format, peripheral::serial::uart::UartPl011};
use patina_adv_logger::component::AdvancedLoggerComponent;
use patina_adv_logger::logger::{AdvancedLogger, TargetFilter};
use patina_dxe_core::*;
use patina_ffs_extractors::CompositeSectionExtractor;

/// The machine's first PL011 serial port: the console the boot stages before
/// this one also use.
const UART0_BASE: usize = 0x0900_0000;
/// The GICv3 distributor, and the redistributor region after it. The machine is
/// started with `gic-version=3`, which both the platform and its boot stages
/// assume.
const GIC_DIST_BASE: u64 = 0x0800_0000;
const GIC_REDIST_BASE: u64 = 0x080a_0000;

/// The revision this platform's ACPI tables carry.
const OEM_REVISION: u32 = 1;

/// Which targets the logger stays quiet about, and the level for everything
/// else. The suppressed ones are crate-internal traces that say nothing useful
/// at an information level.
static LOGGER: AdvancedLogger<UartPl011> = AdvancedLogger::new(
    Format::Standard,
    &[
        TargetFilter {
            target: "goblin",
            log_level: log::LevelFilter::Off,
            hw_filter_override: None,
        },
        TargetFilter {
            target: "allocations",
            log_level: log::LevelFilter::Off,
            hw_filter_override: None,
        },
        TargetFilter {
            target: "efi_memory_map",
            log_level: log::LevelFilter::Off,
            hw_filter_override: None,
        },
    ],
    log::LevelFilter::Info,
    // SAFETY: 0x0900_0000 is the PL011 the machine has, and the firmware owns
    // it: nothing else in the DXE phase writes to it.
    unsafe { UartPl011::new(UART0_BASE) },
);

/// The platform.
///
/// It is one type because every trait Patina needs a platform to implement
/// describes the same machine, and separate types would only be a place for its
/// addresses to drift apart.
pub struct TintedBoot;

impl MemoryInfo for TintedBoot {}

impl CpuInfo for TintedBoot {
    fn gic_bases() -> GicBases {
        // SAFETY: the addresses are the GICv3 this machine's device tree
        // describes, and this is the only user of the interrupt controller in
        // the DXE phase.
        unsafe { GicBases::new(GIC_DIST_BASE, GIC_REDIST_BASE) }
    }
}

impl ComponentInfo for TintedBoot {
    fn components(mut add: Add<Component>) {
        // Order matters: the logger first, so every component after it can
        // report what it does.
        add.component(AdvancedLoggerComponent::<UartPl011>::new(&LOGGER));
        // The architectural protocols Patina leaves to the platform (timer,
        // metronome, watchdog) and the console applications write to.
        add.component(arch::ArchProtocols);
        add.component(console::Console);
        // Disks, partitions, and FAT volumes, which BDS boots from.
        add.component(storage::Storage);
        // Virtio-gpu scanout and EFI Graphics Output Protocol.
        add.component(gop::Gop);
        // SMBIOS: the provider owns the table, the platform owns the records.
        add.component(patina_smbios::component::SmbiosProvider::new(
            smbios::VERSION_MAJOR,
            smbios::VERSION_MINOR,
        ));
        add.component(smbios::TintedSmbios::new());
        // ACPI: the manager installs tables into the XSDT and publishes the
        // RSDP; this platform has no table producer yet.
        add.component(patina_acpi::component::AcpiComponent::new(
            *b"TINT  ",
            *b"TINTACPI",
            OEM_REVISION,
            u32::from_le_bytes(*b"TINT"),
            u32::from_le_bytes(*b"0.1\0"),
        ));
        // Last: the core calls BDS once every other driver has run, and the
        // call does not return.
        add.component(boot::Boot);
    }

    fn configs(_add: Add<Config>) {}
}

impl PlatformInfo for TintedBoot {
    type CpuInfo = Self;
    type MemoryInfo = Self;
    type ComponentInfo = Self;
    type Extractor = CompositeSectionExtractor;
}

static CORE: Core<TintedBoot> = Core::new(CompositeSectionExtractor::new());

/// Starts the DXE core. Never returns: the core ends by handing the machine to
/// the boot loader or the operating system.
///
/// # Safety
///
/// Called once, with a HOB list that outlives the DXE phase and describes the
/// memory the core may use, on a machine that is in its final state.
pub unsafe fn start(physical_hob_list: *const c_void) -> ! {
    log::set_logger(&LOGGER).expect("the logger is set once");
    log::set_max_level(log::LevelFilter::Trace);
    // SAFETY: the HOB list is the caller's handoff; the logger reads it once
    // here and this is the only initialisation of it.
    //
    // The logger takes its memory-log buffer from a GUID HOB that a PEI phase
    // publishes. A host firmware that builds the HOB list itself does not
    // publish one yet, and the logger works without it: entries then go to the
    // hardware port alone, which is the console.
    if let Err(error) = unsafe { LOGGER.init(physical_hob_list) } {
        log::warn!("no memory log: {error:?}");
    }

    log::info!("Tinted platform for QEMU AArch64 virt");
    CORE.entry_point(physical_hob_list)
}
