//! The console protocols: `EFI_SIMPLE_TEXT_OUTPUT` and
//! `EFI_SIMPLE_TEXT_INPUT`, both over the PL011.
//!
//! Text output is what a boot loader's messages, and this firmware's own log,
//! come out as: UTF-16 in, bytes on the serial line, with carriage return and
//! line feed handled the way a terminal expects. Text input decodes the ANSI
//! escape sequences a terminal sends for the cursor keys into the specification's
//! scan codes.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use r_efi::base::{Boolean, Char16, Event, Status};
use r_efi::protocols::simple_text_input;
use r_efi::protocols::simple_text_output;

use crate::console;
use crate::uefi::events;

/// The screen the firmware reports: the serial console has no modes, but the
/// protocol wants one, and 80x25 is the one an application can rely on being
/// told about.
const MAX_MODE: i32 = 1;
const COLUMNS: i32 = 80;
const ROWS: i32 = 25;

/// Attribute bits: background in the high nibble, foreground in the low.
const ATTR_LIGHT_GREY: i32 = 0x07;

static mut OUTPUT_PROTOCOL: MaybeUninit<simple_text_output::Protocol> = MaybeUninit::uninit();
static mut OUTPUT_MODE: MaybeUninit<simple_text_output::Mode> = MaybeUninit::uninit();
static mut INPUT_PROTOCOL: MaybeUninit<simple_text_input::Protocol> = MaybeUninit::uninit();
static mut WAIT_FOR_KEY: MaybeUninit<Event> = MaybeUninit::uninit();

/// Builds the console protocols. Called once from `init`.
pub fn init() {
    // SAFETY: single-threaded bring-up; the protocol structs are static.
    unsafe {
        (*core::ptr::addr_of_mut!(OUTPUT_MODE)).write(simple_text_output::Mode {
            max_mode: MAX_MODE,
            mode: 0,
            attribute: ATTR_LIGHT_GREY,
            cursor_column: 0,
            cursor_row: 0,
            cursor_visible: Boolean::TRUE,
        });
        (*core::ptr::addr_of_mut!(OUTPUT_PROTOCOL)).write(simple_text_output::Protocol {
            reset: output_reset,
            output_string,
            test_string,
            query_mode,
            set_mode,
            set_attribute,
            clear_screen,
            set_cursor_position,
            enable_cursor,
            mode: core::ptr::addr_of_mut!(OUTPUT_MODE) as *mut simple_text_output::Mode,
        });
        let wait_for_key = events::create_polled(has_pending_key)
            .expect("console: out of events for the key-wait handle");
        (*core::ptr::addr_of_mut!(WAIT_FOR_KEY)).write(wait_for_key);
        (*core::ptr::addr_of_mut!(INPUT_PROTOCOL)).write(simple_text_input::Protocol {
            reset: input_reset,
            read_key_stroke,
            wait_for_key,
        });
    }
}

/// The text-output protocol for the system table.
pub fn output_protocol_ptr() -> *mut simple_text_output::Protocol {
    // SAFETY: `init` wrote it; the address never changes.
    unsafe { core::ptr::addr_of_mut!(OUTPUT_PROTOCOL) as *mut simple_text_output::Protocol }
}

/// The text-input protocol for the system table.
pub fn input_protocol_ptr() -> *mut simple_text_input::Protocol {
    // SAFETY: `init` wrote it; the address never changes.
    unsafe { core::ptr::addr_of_mut!(INPUT_PROTOCOL) as *mut simple_text_input::Protocol }
}

unsafe extern "efiapi" fn output_reset(
    this: *mut simple_text_output::Protocol,
    _extended: Boolean,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the system table's protocol is the one `init` built.
    unsafe {
        let mode = (*this).mode;
        if !mode.is_null() {
            (*mode).cursor_column = 0;
            (*mode).cursor_row = 0;
        }
    }
    Status::SUCCESS
}

/// `OutputString`: UTF-16 in, bytes out.
unsafe extern "efiapi" fn output_string(
    this: *mut simple_text_output::Protocol,
    string: *mut Char16,
) -> Status {
    if this.is_null() || string.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller promises a NUL-terminated UTF-16 string.
    let mut units = 0usize;
    while unsafe { *string.add(units) } != 0 {
        units += 1;
        if units > 1 << 20 {
            return Status::INVALID_PARAMETER;
        }
    }
    // SAFETY: the string length was validated above.
    let units = unsafe { core::slice::from_raw_parts(string, units) };
    let mut buffer = [0u8; 4];
    let mut writer = console::UartWriter;
    let mut column = current_column(this);
    let mut row = current_row(this);
    for unit in units {
        let character = *unit as u32;
        let bytes: &[u8] = if character == b'\r' as u32 {
            column = 0;
            b"\r"
        } else if character == b'\n' as u32 {
            row += 1;
            b"\n"
        } else if character == b'\t' as u32 {
            let stop = (column / 8 + 1) * 8;
            while column < stop && column < COLUMNS {
                writer.write_byte(b' ');
                column += 1;
            }
            b""
        } else if character == 0x08 {
            column = (column - 1).max(0);
            b"\x08 \x08"
        } else if character < 0x20 || character == 0x7f {
            // Control characters other than the ones handled above are dropped
            // rather than printed as escapes: a boot loader's messages are what
            // an application writes, and it usually means what it wrote.
            b""
        } else if character < 0x80 {
            buffer[..1].copy_from_slice(&[character as u8]);
            &buffer[..1]
        } else if character < 0x800 {
            buffer[0] = 0xc0 | (character >> 6) as u8;
            buffer[1] = 0x80 | (character & 0x3f) as u8;
            &buffer[..2]
        } else {
            buffer[0] = 0xe0 | (character >> 12) as u8;
            buffer[1] = 0x80 | ((character >> 6) & 0x3f) as u8;
            buffer[2] = 0x80 | (character & 0x3f) as u8;
            &buffer[..3]
        };
        for byte in bytes {
            writer.write_byte(*byte);
        }
        if column >= COLUMNS {
            column = 0;
            row += 1;
        }
        if row >= ROWS {
            row = ROWS - 1;
        }
    }
    // SAFETY: the protocol is the one `init` built.
    unsafe {
        let mode = (*this).mode;
        if !mode.is_null() {
            (*mode).cursor_column = column;
            (*mode).cursor_row = row;
        }
    }
    Status::SUCCESS
}

fn current_column(this: *mut simple_text_output::Protocol) -> i32 {
    // SAFETY: the pointer is the system table's protocol.
    unsafe {
        let mode = (*this).mode;
        if mode.is_null() {
            0
        } else {
            (*mode).cursor_column
        }
    }
}

fn current_row(this: *mut simple_text_output::Protocol) -> i32 {
    // SAFETY: as `current_column`.
    unsafe {
        let mode = (*this).mode;
        if mode.is_null() {
            0
        } else {
            (*mode).cursor_row
        }
    }
}

unsafe extern "efiapi" fn test_string(
    _this: *mut simple_text_output::Protocol,
    string: *mut Char16,
) -> Status {
    if string.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // Everything the firmware can print is printable: walk to the terminator and
    // accept anything that decodes.
    for index in 0..(1 << 20) {
        // SAFETY: the caller promises a NUL-terminated string.
        let unit = unsafe { *string.add(index) };
        if unit == 0 {
            return Status::SUCCESS;
        }
    }
    Status::UNSUPPORTED
}

unsafe extern "efiapi" fn query_mode(
    _this: *mut simple_text_output::Protocol,
    mode_number: usize,
    columns: *mut usize,
    rows: *mut usize,
) -> Status {
    if columns.is_null() || rows.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if mode_number != 0 {
        return Status::UNSUPPORTED;
    }
    // SAFETY: the out-parameters are writable.
    unsafe {
        *columns = COLUMNS as usize;
        *rows = ROWS as usize;
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn set_mode(
    _this: *mut simple_text_output::Protocol,
    mode_number: usize,
) -> Status {
    if mode_number == 0 {
        Status::SUCCESS
    } else {
        Status::UNSUPPORTED
    }
}

unsafe extern "efiapi" fn set_attribute(
    this: *mut simple_text_output::Protocol,
    attribute: usize,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // The serial console has no colours to set; record the attribute an
    // application asked for so `Mode->Attribute` reads back what it expects.
    // SAFETY: the protocol is the one `init` built.
    unsafe {
        let mode = (*this).mode;
        if !mode.is_null() {
            (*mode).attribute = attribute as i32;
        }
    }
    Status::SUCCESS
}

/// `ClearScreen`: the serial console has no screen to clear, so this moves the
/// cursor home and says it succeeded - which is what an application means when
/// it asks.
unsafe extern "efiapi" fn clear_screen(this: *mut simple_text_output::Protocol) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }
    console::write(b"\x1b[2J\x1b[H");
    // SAFETY: the protocol is the one `init` built.
    unsafe {
        let mode = (*this).mode;
        if !mode.is_null() {
            (*mode).cursor_column = 0;
            (*mode).cursor_row = 0;
        }
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn set_cursor_position(
    this: *mut simple_text_output::Protocol,
    column: usize,
    row: usize,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the protocol is the one `init` built.
    unsafe {
        let mode = (*this).mode;
        if !mode.is_null() {
            (*mode).cursor_column = column as i32;
            (*mode).cursor_row = row as i32;
        }
    }
    Status::SUCCESS
}

unsafe extern "efiapi" fn enable_cursor(
    this: *mut simple_text_output::Protocol,
    visible: Boolean,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the protocol is the one `init` built.
    unsafe {
        let mode = (*this).mode;
        if !mode.is_null() {
            (*mode).cursor_visible = visible;
        }
    }
    Status::SUCCESS
}

// Text input.

unsafe extern "efiapi" fn input_reset(
    this: *mut simple_text_input::Protocol,
    _extended: Boolean,
) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // Drain whatever the terminal has already sent: a reset means "start from
    // here", not "play back the typing that happened before I started".
    while console::UART.try_read_byte().is_some() {}
    Status::SUCCESS
}

/// Whether the serial line has a byte waiting. The key-wait event polls this.
fn has_pending_key() -> bool {
    console::UART.has_input()
}

/// A key, decoded from the terminal's escape sequences.
struct Key {
    scan_code: u16,
    unicode: Char16,
}

/// Reads and decodes one key, if one is waiting.
fn read_key() -> Option<Key> {
    let byte = console::UART.try_read_byte()?;
    match byte {
        b'\r' | b'\n' => Some(Key {
            scan_code: 0,
            unicode: '\r' as Char16,
        }),
        0x08 | 0x7f => Some(Key {
            scan_code: 0,
            unicode: 0x08,
        }),
        b'\t' => Some(Key {
            scan_code: 0,
            unicode: '\t' as Char16,
        }),
        0x1b => read_escape(),
        byte if byte >= 0x20 && byte < 0x7f => Some(Key {
            scan_code: 0,
            unicode: byte as Char16,
        }),
        _ => Some(Key {
            scan_code: 0,
            unicode: 0,
        }),
    }
}

/// Decodes what follows an ESC. CSI sequences arrive as `ESC [ A`, and the
/// application cursor keys the specification defines map onto the arrows.
fn read_escape() -> Option<Key> {
    let first = console::UART.try_read_byte()?;
    if first != b'[' && first != b'O' {
        // A bare ESC: report it as such rather than as a key the terminal never
        // sent.
        return Some(Key {
            scan_code: 0,
            unicode: 0x1b,
        });
    }
    let second = console::UART.try_read_byte()?;
    let scan_code = match second {
        b'A' => 0x01, // up
        b'B' => 0x02, // down
        b'C' => 0x03, // right
        b'D' => 0x04, // left
        b'H' => 0x05, // home
        b'F' => 0x06, // end
        b'0'..=b'9' => {
            // A numeric parameter (`ESC [ 3 ~`): consume through the terminator
            // so the next read starts at a clean boundary.
            // Consume through the sequence's terminator, so the next read
            // starts at a clean boundary; stop if the terminal stops sending.
            let mut terminator = console::UART.try_read_byte();
            while let Some(byte) = terminator {
                if byte == b'~' {
                    break;
                }
                terminator = console::UART.try_read_byte();
            }
            match second {
                b'3' => 0x08, // delete
                b'5' => 0x0a, // page up
                b'6' => 0x18, // page down
                b'1' => 0x05, // home
                b'4' => 0x06, // end
                _ => 0,
            }
        }
        _ => 0,
    };
    Some(Key {
        scan_code,
        unicode: 0,
    })
}

unsafe extern "efiapi" fn read_key_stroke(
    _this: *mut simple_text_input::Protocol,
    key: *mut simple_text_input::InputKey,
) -> Status {
    if key.is_null() {
        return Status::INVALID_PARAMETER;
    }
    match read_key() {
        Some(decoded) => {
            // SAFETY: the out-parameter is writable.
            unsafe {
                *key = simple_text_input::InputKey {
                    scan_code: decoded.scan_code,
                    unicode_char: decoded.unicode,
                };
            }
            Status::SUCCESS
        }
        None => Status::NOT_READY,
    }
}
