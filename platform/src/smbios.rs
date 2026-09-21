//! The SMBIOS records this platform publishes.
//!
//! The records are `patina_smbios`' typed structures rather than bytes this
//! repository lays out itself: the field offsets, the string pool, the two
//! entry points, and the checksums are the crate's, which is a large part of
//! the reason to run on Patina at all. What is here is the content, for this
//! machine.
//!
//! Two things the DXE phase cannot see are left as "unknown" rather than
//! guessed: the number of application processors, and the installed memory.
//! The DXE phase is entered on the boot processor with the PEI memory map, and
//! the fields that describe either carry zero, which the specification defines
//! as unknown.

use alloc::string::String;
use alloc::vec;

use patina::component::{component, service::Service};
use patina::error::Result;
use patina_smbios::service::{SMBIOS_HANDLE_PI_RESERVED, Smbios, SmbiosExt, SmbiosTableHeader};
use patina_smbios::smbios_record::{
    SmbiosRecordStructure, Type0PlatformFirmwareInformation, Type1SystemInformation,
    Type2BaseboardInformation, Type3SystemEnclosure, Type4ProcessorInformation,
};
use patina_smbios::smbios_types::{
    BiosCharacteristics, BiosCharacteristicsExt1, BiosCharacteristicsExt2, BoardType, BootUpState,
    ExtendedBiosRomSize, FeatureFlags, PowerSupplyState, ProcessorCharacteristics,
    ProcessorFamilyData, ProcessorInformationStatus, ProcessorTypeData, ProcessorUpgrade,
    ProcessorVoltage, SecurityStatus, ThermalState, WakeUpType,
};

/// The SMBIOS revision the table claims. 3.7 is what the records below need:
/// the fields they fill exist by then, and nothing here uses a later one.
pub(crate) const VERSION_MAJOR: u8 = 3;
pub(crate) const VERSION_MINOR: u8 = 7;

/// The firmware vendor: this repository.
const VENDOR: &str = "Tinted Software";
/// The firmware revision, the SMBIOS view of it.
const FIRMWARE_VERSION: &str = "Tinted Boot 0.1";
/// A date for the firmware image. SMBIOS wants one; the firmware does not carry
/// a build date, so this is the release date of this revision.
const FIRMWARE_DATE: &str = "01/01/2026";
/// The machines this platform targets are QEMU's, and the system's vendor is
/// QEMU rather than the firmware.
const SYSTEM_VENDOR: &str = "QEMU";
/// The machine's product name, as QEMU describes it.
const SYSTEM_PRODUCT: &str = "QEMU AArch64 Virtual Machine";
/// The machine's board: QEMU's `virt` machine, which is a board in the SMBIOS
/// sense even when it is emulated.
const BOARD_PRODUCT: &str = "QEMU virt";
/// Recognisable, fixed system UUID. A machine with no serial number of its own
/// still has to report something the OS can key on.
const SYSTEM_UUID: [u8; 16] = [
    0x57, 0x65, 0x69, 0x72, 0x00, 0x01, 0x40, 0x00, 0x80, 0x00, 0x51, 0x45, 0x4d, 0x55, 0x00, 0x02,
];

/// The platform's SMBIOS provider.
#[derive(Default)]
pub struct TintedSmbios;

#[component]
impl TintedSmbios {
    /// The component has no state; the records depend on nothing but the
    /// machine's identity.
    pub fn new() -> Self {
        Self
    }

    fn entry_point(self, smbios: Service<dyn Smbios>) -> Result<()> {
        let (major, minor) = smbios.version();
        log::info!("SMBIOS {major}.{minor}");

        required_record(&smbios, &bios_information())?;
        required_record(&smbios, &system_information())?;

        // The chassis comes before the board: the board's record names the
        // chassis it sits in, and the specification's own answer for a board
        // that has no enclosure to name is 0xFFFF.
        let enclosure = enclosure_information();
        let chassis_handle = match smbios.add_record(None, &enclosure) {
            Ok(handle) => handle,
            Err(error) => {
                log::warn!("SMBIOS type 3: {error:?}");
                0xffff
            }
        };
        required_record(&smbios, &baseboard_information(chassis_handle))?;
        required_record(&smbios, &processor_information())?;

        let (table, entry_point) = smbios.publish_table().map_err(|error| {
            log::error!("SMBIOS table: {error:?}");
            error
        })?;
        log::info!("SMBIOS table at {table:#x}, entry point at {entry_point:#x}");
        Ok(())
    }
}

/// Adds a record the specification requires, reporting which one failed so a
/// missing table points at the record that caused it.
fn required_record<T: SmbiosRecordStructure>(
    smbios: &Service<dyn Smbios>,
    record: &T,
) -> Result<()> {
    let handle = smbios.add_record(None, record).map_err(|error| {
        log::error!("SMBIOS type {}: {error:?}", T::RECORD_TYPE);
        error
    })?;
    log::debug!("SMBIOS type {} at handle {handle:#06x}", T::RECORD_TYPE);
    Ok(())
}

/// Type 0: what the firmware is.
fn bios_information() -> Type0PlatformFirmwareInformation {
    Type0PlatformFirmwareInformation {
        header: SmbiosTableHeader::new(0, 0, SMBIOS_HANDLE_PI_RESERVED),
        vendor: 1,
        firmware_version: 2,
        // The firmware is not in a ROM at a segment address on this machine.
        bios_starting_address_segment: 0x0000,
        firmware_release_date: 3,
        // Which of this record's capability lists applies: 0xFF asks for the
        // extended ROM size field, which carries the real answer on UEFI.
        firmware_rom_size: 0xff,
        characteristics: BiosCharacteristics::new(),
        characteristics_ext1: BiosCharacteristicsExt1::new().with_acpi_supported(true),
        characteristics_ext2: BiosCharacteristicsExt2::new().with_uefi_spec_supported(true),
        system_bios_major_release: 0,
        system_bios_minor_release: 1,
        // There is no embedded controller in the firmware's view of the machine.
        embedded_controller_major_release: 0xff,
        embedded_controller_minor_release: 0xff,
        extended_bios_rom_size: ExtendedBiosRomSize::new(),
        string_pool: vec![
            String::from(VENDOR),
            String::from(FIRMWARE_VERSION),
            String::from(FIRMWARE_DATE),
        ],
    }
}

/// Type 1: what the machine is.
fn system_information() -> Type1SystemInformation {
    Type1SystemInformation {
        header: SmbiosTableHeader::new(1, 0, SMBIOS_HANDLE_PI_RESERVED),
        manufacturer: 1,
        product_name: 2,
        version: 3,
        serial_number: 4,
        uuid: SYSTEM_UUID,
        wake_up_type: WakeUpType::PowerSwitch,
        sku_number: 5,
        family: 6,
        string_pool: vec![
            String::from(SYSTEM_VENDOR),
            String::from(SYSTEM_PRODUCT),
            String::from("1.0"),
            String::from("0"),
            String::from("0"),
            String::from("QEMU"),
        ],
    }
}

/// Type 3: the enclosure the board sits in. An emulated machine has none, so
/// this describes the machine's own case in the terms an operating system
/// expects to find something in.
fn enclosure_information() -> Type3SystemEnclosure {
    Type3SystemEnclosure {
        header: SmbiosTableHeader::new(3, 0, SMBIOS_HANDLE_PI_RESERVED),
        manufacturer: 1,
        // 0x03 is "Desktop" in the specification's chassis type list.
        enclosure_type: 0x03,
        version: 2,
        serial_number: 3,
        asset_tag_number: 4,
        bootup_state: BootUpState::Safe,
        power_supply_state: PowerSupplyState::Safe,
        thermal_state: ThermalState::Safe,
        security_status: SecurityStatus::Unknown,
        oem_defined: 0,
        height: 0,
        number_of_power_cords: 0,
        contained_element_count: 0,
        contained_element_record_length: 0,
        string_pool: vec![
            String::from(SYSTEM_VENDOR),
            String::from("QEMU virt"),
            String::from("0"),
            String::from("0"),
        ],
    }
}

/// Type 2: the board inside it.
fn baseboard_information(chassis_handle: u16) -> Type2BaseboardInformation {
    Type2BaseboardInformation {
        header: SmbiosTableHeader::new(2, 0, SMBIOS_HANDLE_PI_RESERVED),
        manufacturer: 1,
        product: 2,
        version: 3,
        serial_number: 4,
        asset_tag: 5,
        feature_flags: FeatureFlags::new()
            .with_hosting_board(true)
            .with_replaceable_board(true),
        location_in_chassis: 6,
        chassis_handle,
        board_type: BoardType::Motherboard,
        contained_object_handles: 0,
        string_pool: vec![
            String::from(SYSTEM_VENDOR),
            String::from(BOARD_PRODUCT),
            String::from("1.0"),
            String::from("0"),
            String::from("0"),
            String::from("Onboard"),
        ],
    }
}

/// Type 4: the processor the firmware runs on.
///
/// The identification is the architecture's: the processor ID field carries the
/// MIDR, read here rather than assumed, and the version string repeats it
/// because naming the part would mean carrying a table of implementer and part
/// numbers. The counts are zero, which the specification reads as unknown: the
/// DXE phase is entered on the boot processor and does not enumerate the
/// others, so it has no honest number to give.
fn processor_information() -> Type4ProcessorInformation {
    let midr = read_midr();
    Type4ProcessorInformation {
        header: SmbiosTableHeader::new(4, 0, SMBIOS_HANDLE_PI_RESERVED),
        socket_designation: 1,
        processor_type: ProcessorTypeData::CentralProcessor,
        // 0xFE asks the reader to use the field below.
        processor_family: 0xfe,
        processor_manufacturer: 2,
        processor_id: processor_identification(midr),
        processor_version: 3,
        voltage: ProcessorVoltage::new().with_processor_voltage_indicate_legacy(true),
        external_clock: 0,
        max_speed: 0,
        current_speed: 0,
        status: ProcessorInformationStatus::new()
            .with_cpu_status(1)
            .with_cpu_socket_populated(true),
        processor_upgrade: ProcessorUpgrade::NoUpgrade,
        l1_cache_handle: 0xffff,
        l2_cache_handle: 0xffff,
        l3_cache_handle: 0xffff,
        serial_number: 4,
        asset_tag: 5,
        part_number: 6,
        core_count: 0,
        core_enabled: 0,
        thread_count: 0,
        processor_characteristics: ProcessorCharacteristics::new().with_capable_64bit(true),
        processor_family2: ProcessorFamilyData::ARMv8,
        core_count2: 0,
        core_enabled2: 0,
        thread_count2: 0,
        string_pool: vec![
            String::from("CPU0"),
            String::from("ARM"),
            String::from("AArch64"),
            String::from("0"),
            String::from("0"),
            String::from("0"),
            String::from("0"),
        ],
    }
}

/// The architecture defines the processor ID field as the MIDR, which is four
/// bytes, in the low half of the eight the field has.
fn processor_identification(midr: u64) -> [u8; 8] {
    let mut id = [0u8; 8];
    id[..4].copy_from_slice(&(midr as u32).to_le_bytes());
    id
}

/// Reads `MIDR_EL1`, the register that identifies the part.
fn read_midr() -> u64 {
    let midr: u64;
    // SAFETY: `MIDR_EL1` is a read-only identification register, readable at
    // EL1, and reading it has no side effects.
    unsafe { core::arch::asm!("mrs {}, MIDR_EL1", out(reg) midr, options(nomem, nostack)) };
    midr
}
