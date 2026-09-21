//! The UEFI console: simple text input and output over the PL011.
//!
//! Patina builds the system table with no console, so without this an
//! application's `ConOut->OutputString` is a call through a null pointer. This
//! installs both protocols on one handle and points `ConIn`, `ConOut` and
//! `StdErr` at them. The UART is the one Patina's logger also writes to; both
//! are byte-at-a-time polled writes on one core, so they interleave by line at
//! worst.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, Ordering},
};

use patina::component::{component, params::Handle};
use patina::error::{EfiError, Result};
use patina::standard::efi::{
    self, Boolean, Char16, Event, Guid,
    protocols::{simple_text_input, simple_text_output},
};
use patina::uefi::boot_services::{BootServices, StandardBootServices};

use crate::tables;

const UART_BASE: usize = 0x0900_0000;
const UART_DR: usize = 0x00;
const UART_FR: usize = 0x18;
const FR_RXFE: u32 = 1 << 4;
const FR_TXFF: u32 = 1 << 5;

const COLUMNS: i32 = 80;
const ROWS: i32 = 25;

static OUTPUT_GUID: Guid = simple_text_output::PROTOCOL_GUID;
static INPUT_GUID: Guid = simple_text_input::PROTOCOL_GUID;

static WAIT_FOR_KEY: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

fn uart_read(offset: usize) -> u32 {
    // SAFETY: the PL011 register file is device memory at a fixed address that
    // this firmware maps; registers are 32 bits wide.
    unsafe { core::ptr::read_volatile((UART_BASE + offset) as *const u32) }
}

fn uart_write_byte(byte: u8) {
    while uart_read(UART_FR) & FR_TXFF != 0 {
        core::hint::spin_loop();
    }
    // SAFETY: as `uart_read`.
    unsafe { core::ptr::write_volatile((UART_BASE + UART_DR) as *mut u32, byte as u32) };
}

fn uart_write(bytes: &[u8]) {
    for byte in bytes {
        uart_write_byte(*byte);
    }
}

fn uart_has_input() -> bool {
    uart_read(UART_FR) & FR_RXFE == 0
}

fn uart_try_read() -> Option<u8> {
    if !uart_has_input() {
        return None;
    }
    Some(uart_read(UART_DR) as u8)
}

/// Writes a small decimal number, for escape sequences.
fn uart_decimal(mut value: u32) {
    let mut digits = [0u8; 10];
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        uart_write_byte(digits[count]);
    }
}

static mut MODE: simple_text_output::Mode = simple_text_output::Mode {
    max_mode: 1,
    mode: 0,
    attribute: 0x07,
    cursor_column: 0,
    cursor_row: 0,
    cursor_visible: Boolean::TRUE,
};

fn mode() -> *mut simple_text_output::Mode {
    core::ptr::addr_of_mut!(MODE)
}

extern "efiapi" fn output_reset(
    this: *mut simple_text_output::Protocol,
    _extended: Boolean,
) -> efi::Status {
    clear_screen(this)
}

extern "efiapi" fn output_string(
    _this: *mut simple_text_output::Protocol,
    string: *mut Char16,
) -> efi::Status {
    if string.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let mode = mode();
    // SAFETY: MODE is this driver's static; the console is single-threaded.
    let (mut column, mut row) = unsafe { ((*mode).cursor_column, (*mode).cursor_row) };
    let mut index = 0usize;
    loop {
        // SAFETY: the caller passes a NUL-terminated UCS-2 string.
        let unit = unsafe { string.add(index).read_unaligned() };
        if unit == 0 {
            break;
        }
        index += 1;
        let character = unit as u32;
        match character {
            0x0d => {
                column = 0;
                uart_write_byte(b'\r');
            }
            0x0a => {
                row += 1;
                uart_write_byte(b'\n');
            }
            0x08 => {
                if column > 0 {
                    column -= 1;
                    uart_write(b"\x08 \x08");
                }
            }
            0x09 => {
                let stop = (column / 8 + 1) * 8;
                while column < stop && column < COLUMNS {
                    uart_write_byte(b' ');
                    column += 1;
                }
            }
            character if character < 0x20 || character == 0x7f => {}
            character => {
                // UCS-2 to UTF-8; surrogates are not characters UCS-2 has.
                if character < 0x80 {
                    uart_write_byte(character as u8);
                } else if character < 0x800 {
                    uart_write(&[
                        0xc0 | (character >> 6) as u8,
                        0x80 | (character & 0x3f) as u8,
                    ]);
                } else {
                    uart_write(&[
                        0xe0 | (character >> 12) as u8,
                        0x80 | ((character >> 6) & 0x3f) as u8,
                        0x80 | (character & 0x3f) as u8,
                    ]);
                }
                column += 1;
            }
        }
        if column >= COLUMNS {
            column = 0;
            row += 1;
        }
        row = row.min(ROWS - 1);
    }
    // SAFETY: as above.
    unsafe {
        (*mode).cursor_column = column;
        (*mode).cursor_row = row;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn test_string(
    _this: *mut simple_text_output::Protocol,
    _string: *mut Char16,
) -> efi::Status {
    efi::Status::SUCCESS
}

extern "efiapi" fn query_mode(
    _this: *mut simple_text_output::Protocol,
    mode_number: usize,
    columns: *mut usize,
    rows: *mut usize,
) -> efi::Status {
    if mode_number != 0 {
        return efi::Status::UNSUPPORTED;
    }
    if columns.is_null() || rows.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller passed writable out-parameters.
    unsafe {
        columns.write_unaligned(COLUMNS as usize);
        rows.write_unaligned(ROWS as usize);
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn set_mode(
    this: *mut simple_text_output::Protocol,
    mode_number: usize,
) -> efi::Status {
    if mode_number != 0 {
        return efi::Status::UNSUPPORTED;
    }
    clear_screen(this)
}

extern "efiapi" fn set_attribute(
    _this: *mut simple_text_output::Protocol,
    attribute: usize,
) -> efi::Status {
    // SAFETY: MODE is this driver's static.
    unsafe { (*mode()).attribute = attribute as i32 };
    // EFI colours are IRGB with red and blue swapped relative to ANSI.
    const ANSI: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];
    let foreground = attribute & 0x0f;
    let background = (attribute >> 4) & 0x07;
    uart_write(b"\x1b[0;");
    if foreground & 0x08 != 0 {
        uart_write(b"1;");
    }
    uart_decimal(30 + ANSI[foreground & 0x07] as u32);
    uart_write_byte(b';');
    uart_decimal(40 + ANSI[background] as u32);
    uart_write_byte(b'm');
    efi::Status::SUCCESS
}

extern "efiapi" fn clear_screen(_this: *mut simple_text_output::Protocol) -> efi::Status {
    uart_write(b"\x1b[2J\x1b[H");
    // SAFETY: MODE is this driver's static.
    unsafe {
        (*mode()).cursor_column = 0;
        (*mode()).cursor_row = 0;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn set_cursor_position(
    _this: *mut simple_text_output::Protocol,
    column: usize,
    row: usize,
) -> efi::Status {
    if column >= COLUMNS as usize || row >= ROWS as usize {
        return efi::Status::UNSUPPORTED;
    }
    uart_write(b"\x1b[");
    uart_decimal(row as u32 + 1);
    uart_write_byte(b';');
    uart_decimal(column as u32 + 1);
    uart_write_byte(b'H');
    // SAFETY: MODE is this driver's static.
    unsafe {
        (*mode()).cursor_column = column as i32;
        (*mode()).cursor_row = row as i32;
    }
    efi::Status::SUCCESS
}

extern "efiapi" fn enable_cursor(
    _this: *mut simple_text_output::Protocol,
    visible: Boolean,
) -> efi::Status {
    uart_write(if visible.into() {
        b"\x1b[?25h"
    } else {
        b"\x1b[?25l"
    });
    // SAFETY: MODE is this driver's static.
    unsafe { (*mode()).cursor_visible = visible };
    efi::Status::SUCCESS
}

static mut OUTPUT: simple_text_output::Protocol = simple_text_output::Protocol {
    reset: output_reset,
    output_string,
    test_string,
    query_mode,
    set_mode,
    set_attribute,
    clear_screen,
    set_cursor_position,
    enable_cursor,
    mode: core::ptr::addr_of_mut!(MODE),
};

extern "efiapi" fn input_reset(
    _this: *mut simple_text_input::Protocol,
    _extended: Boolean,
) -> efi::Status {
    while uart_try_read().is_some() {}
    efi::Status::SUCCESS
}

/// Decodes one key from the UART: printable ASCII, the control keys UEFI names,
/// and the ANSI escape sequences terminals send for cursor and editing keys.
fn read_key() -> Option<simple_text_input::InputKey> {
    let key = |scan_code: u16, unicode_char: Char16| {
        Some(simple_text_input::InputKey {
            scan_code,
            unicode_char,
        })
    };
    match uart_try_read()? {
        b'\r' | b'\n' => key(0, b'\r' as Char16),
        0x08 | 0x7f => key(0, 0x08),
        b'\t' => key(0, b'\t' as Char16),
        0x1b => {
            let Some(first) = uart_try_read() else {
                return key(0x17, 0);
            }; // Escape
            if first != b'[' && first != b'O' {
                return key(0x17, 0);
            }
            let second = uart_try_read()?;
            let scan = match second {
                b'A' => 0x01,
                b'B' => 0x02,
                b'C' => 0x03,
                b'D' => 0x04,
                b'H' => 0x05,
                b'F' => 0x06,
                b'0'..=b'9' => {
                    // `ESC [ n ~`: consume through the terminator.
                    while let Some(byte) = uart_try_read() {
                        if byte == b'~' {
                            break;
                        }
                    }
                    match second {
                        b'1' => 0x05,
                        b'2' => 0x07,
                        b'3' => 0x08,
                        b'4' => 0x06,
                        b'5' => 0x09,
                        b'6' => 0x0a,
                        _ => 0,
                    }
                }
                _ => 0,
            };
            key(scan, 0)
        }
        byte if (0x20..0x7f).contains(&byte) => key(0, byte as Char16),
        _ => key(0, 0),
    }
}

extern "efiapi" fn read_key_stroke(
    _this: *mut simple_text_input::Protocol,
    key: *mut simple_text_input::InputKey,
) -> efi::Status {
    if key.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    match read_key() {
        Some(pressed) => {
            // SAFETY: the caller passed a writable key buffer.
            unsafe { key.write_unaligned(pressed) };
            efi::Status::SUCCESS
        }
        None => efi::Status::NOT_READY,
    }
}

/// `WaitForKey`'s notify function: the core calls it while an application
/// waits on or checks the event, and it signals once a byte is waiting.
extern "efiapi" fn wait_for_key_notify(event: Event, _context: *mut c_void) {
    if !uart_has_input() {
        return;
    }
    let services = tables::boot_services();
    if !services.is_null() {
        // SAFETY: boot services are live while the core dispatches notifies.
        unsafe { ((*services).signal_event)(event) };
    }
}

static mut INPUT: simple_text_input::Protocol = simple_text_input::Protocol {
    reset: input_reset,
    read_key_stroke,
    wait_for_key: core::ptr::null_mut(),
};

/// Installs the console and publishes it in the system table.
pub struct Console;

#[component]
impl Console {
    fn entry_point(self, boot_services: StandardBootServices, image: Handle) -> Result<()> {
        let table = tables::init(&boot_services, *image).ok_or(EfiError::NotFound)?;
        let services = tables::boot_services();
        if services.is_null() {
            return Err(EfiError::NotReady);
        }

        let mut event: Event = core::ptr::null_mut();
        // SAFETY: boot services are live, and the notify function is a static
        // function of the notify type.
        let status = unsafe {
            ((*services).create_event)(
                efi::EVT_NOTIFY_WAIT,
                efi::TPL_NOTIFY,
                Some(wait_for_key_notify),
                core::ptr::null_mut(),
                &mut event,
            )
        };
        if status != efi::Status::SUCCESS {
            log::error!("console: WaitForKey event: {status:?}");
            return Err(EfiError::OutOfResources);
        }
        WAIT_FOR_KEY.store(event, Ordering::Release);

        // SAFETY: the interfaces are statics of the structures their GUIDs name
        // and outlive boot services; the system table is Patina's live table,
        // and the fields changed are the console's.
        unsafe {
            (*core::ptr::addr_of_mut!(INPUT)).wait_for_key = event;
            let output = core::ptr::addr_of_mut!(OUTPUT);
            let input = core::ptr::addr_of_mut!(INPUT);
            let handle = boot_services.install_protocol_interface_unchecked(
                None,
                &OUTPUT_GUID,
                output as *mut c_void,
            )?;
            boot_services.install_protocol_interface_unchecked(
                Some(handle),
                &INPUT_GUID,
                input as *mut c_void,
            )?;

            (*table).console_out_handle = handle;
            (*table).con_out = output;
            (*table).standard_error_handle = handle;
            (*table).std_err = output;
            (*table).console_in_handle = handle;
            (*table).con_in = input;
            tables::rechecksum(table);
        }
        log::info!("console: PL011 text console published in the system table");
        Ok(())
    }
}
