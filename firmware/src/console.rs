//! The console: a PL011 UART, and the bytes that reach it.
//!
//! This is both the firmware's own log and the backing for
//! `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`. It is deliberately dumb: byte-at-a-time
//! polls of the flag register. QEMU's PL011 accepts a byte whenever the
//! transmit FIFO has room, and the FIFO is what makes printing during bring-up
//! reliable.

use core::fmt;
use spin::Mutex;

use crate::platform;

/// PL011 register offsets.
const DR: usize = 0x00;
const FR: usize = 0x18;
const IBRD: usize = 0x24;
const FBRD: usize = 0x28;
const LCR_H: usize = 0x2c;
const CR: usize = 0x30;
const ICR: usize = 0x44;

/// `FR` bits.
const FR_TXFF: u32 = 1 << 5;
const FR_RXFE: u32 = 1 << 4;

/// The console UART.
pub static UART: Pl011 = Pl011::new(platform::UART0_BASE);

static LOCK: Mutex<()> = Mutex::new(());
static READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    #[inline]
    fn reg(&self, offset: usize) -> *mut u32 {
        (self.base + offset) as *mut u32
    }

    #[inline]
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: the register file is mapped Device memory, and a 32-bit
        // volatile access is the width every PL011 register has.
        unsafe { core::ptr::read_volatile(self.reg(offset)) }
    }

    #[inline]
    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile(self.reg(offset), value) }
    }

    /// Programs the UART for 8N1 at 115200. QEMU ignores the baud divisors;
    /// they are set because a real PL011 would need them.
    pub fn init(&self) {
        self.write(CR, 0);
        self.write(ICR, 0x7ff);
        self.write(IBRD, 13); // 24 MHz / (16 * 115200)
        self.write(FBRD, 1);
        self.write(LCR_H, 0x70); // 8 bits, FIFOs enabled
        self.write(CR, 0x301); // UARTEN | TXE | RXE
    }

    pub fn write_byte(&self, byte: u8) {
        while self.read(FR) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        self.write(DR, byte as u32);
    }

    /// A byte if one is waiting, nothing otherwise.
    pub fn try_read_byte(&self) -> Option<u8> {
        if self.read(FR) & FR_RXFE != 0 {
            return None;
        }
        Some(self.read(DR) as u8)
    }

    /// Whether a byte is waiting, without consuming it.
    pub fn has_input(&self) -> bool {
        self.read(FR) & FR_RXFE == 0
    }
}

/// `Write` on a shared reference, so the one global UART can be formatted
/// through without being borrowed mutably.
impl fmt::Write for &Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Programs the console. Until this returns, output still works - QEMU's PL011
/// resets with the transmitter enabled - but nothing is synchronised.
pub fn init() {
    UART.init();
    READY.store(true, core::sync::atomic::Ordering::Release);
}

/// Whether the console has been initialised. The panic path checks this: before
/// it, formatting is not safe, because the MMU may not be on.
pub fn ready() -> bool {
    READY.load(core::sync::atomic::Ordering::Acquire)
}

/// Writes a string without formatting or locking. Safe before the MMU is on:
/// every access is a single aligned 32-bit MMIO write.
pub fn emergency_write(s: &str) {
    for byte in s.bytes() {
        UART.write_byte(byte);
    }
}

/// Writes `value` as hexadecimal, without formatting or locking.
pub fn emergency_hex(value: u64) {
    emergency_write("0x");
    for shift in (0..64).step_by(4).rev() {
        let nibble = ((value >> shift) & 0xf) as u8;
        UART.write_byte(if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        });
    }
}

/// The sink behind `print!`/`println!`.
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    let _guard = LOCK.lock();
    let _ = (&UART).write_fmt(args);
}

/// A `Write`-style handle on the UART that needs no formatting, for code that
/// runs before the console is initialised or from an interrupt.
pub struct UartWriter;

impl UartWriter {
    #[inline]
    pub fn write_byte(&self, byte: u8) {
        UART.write_byte(byte);
    }
}

/// Writes raw bytes straight to the UART, without locking or formatting.
pub fn write(bytes: &[u8]) {
    for byte in bytes {
        UART.write_byte(*byte);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::console::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\r\n"));
    ($($arg:tt)*) => ($crate::console::_print(format_args!("{}\r\n", format_args!($($arg)*))));
}
