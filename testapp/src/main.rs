//! AArch64 UEFI application the firmware boots from the ESP.
//!
//! It exercises the published UEFI 2.70 environment end to end: text output,
//! system-table headers, configuration tables, memory services, pool and page
//! allocation, protocol discovery, variables, time, and timer events. Every
//! result is printed through the console so a serial log doubles as the test
//! report.

#![no_std]
#![no_main]

use r_efi::base::{Event, Guid, Handle, PhysicalAddress, Status};
use r_efi::protocols::simple_file_system::PROTOCOL_GUID as SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
use r_efi::protocols::simple_text_output::Protocol as TextOut;
use r_efi::system::{self, BootServices, MemoryDescriptor, RuntimeServices, SystemTable, Time};

/// Scratch buffer for one output line. Lines are formatted into UTF-16 here
/// and handed to OutputString; 256 units cover the longest line we emit
/// (GUID rows, status lines) with room for the terminating NUL.
const LINE_CAP: usize = 256;

struct Console {
    out: *mut TextOut,
    buf: [u16; LINE_CAP],
    len: usize,
}

impl Console {
    fn new(out: *mut TextOut) -> Self {
        Console {
            out,
            buf: [0; LINE_CAP],
            len: 0,
        }
    }

    /// Push one UCS-2 code unit, dropping it when the line is full. The slot
    /// after the last unit stays reserved for the terminator, so a full line
    /// still forms a valid C string instead of overflowing.
    fn raw(&mut self, c: u16) {
        if self.len + 1 < LINE_CAP {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }

    /// Push one character. Non-ASCII input degrades to '?': everything we
    /// format ourselves is ASCII; raw UCS-2 goes through `raw`/`wstr`.
    fn chr(&mut self, c: char) {
        let unit = c as u32;
        self.raw(if unit < 0x80 {
            unit as u16
        } else {
            u16::from(b'?')
        });
    }

    fn str(&mut self, s: &str) {
        for c in s.chars() {
            self.chr(c);
        }
    }

    fn dec(&mut self, mut v: u64) {
        if v == 0 {
            self.chr('0');
            return;
        }
        // Digits are collected backwards, so buffer size bounds the value:
        // 20 digits cover the full u64 range.
        let mut digits = [0u8; 20];
        let mut n = 0;
        while v > 0 && n < digits.len() {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.chr(digits[n] as char);
        }
    }

    /// Exactly `digits` hex digits, zero-padded, no `0x` prefix (callers add
    /// prefixes where they want them, and GUIDs need bare digit runs).
    fn hex(&mut self, v: u64, digits: usize) {
        for i in (0..digits).rev() {
            let nibble = ((v >> (i * 4)) & 0xf) as u32;
            self.chr(char::from_digit(nibble, 16).unwrap_or('?'));
        }
    }

    fn status(&mut self, s: Status) {
        // Status codes carry meaning in the high bits (error flag), so the
        // full width matters; the symbolic name is appended when r-efi knows it.
        self.hex(s.as_usize() as u64, 16);
        if let Some(text) = s.description() {
            self.str(" (");
            self.str(text);
            self.chr(')');
        }
    }

    /// Microsoft-wire-format GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
    fn guid(&mut self, g: &Guid) {
        let (time_low, time_mid, time_hi, seq_hi, seq_lo, node) = g.as_fields();
        self.hex(time_low as u64, 8);
        self.chr('-');
        self.hex(time_mid as u64, 4);
        self.chr('-');
        self.hex(time_hi as u64, 4);
        self.chr('-');
        self.hex(u64::from(seq_hi), 2);
        self.hex(u64::from(seq_lo), 2);
        self.chr('-');
        for byte in node {
            self.hex(u64::from(*byte), 2);
        }
    }

    fn nl(&mut self) {
        // The firmware console tracks cursor rows and columns; a bare LF
        // would leave the column unanchored, so line ends are CRLF.
        self.chr('\r');
        self.chr('\n');
    }

    /// Append a firmware-owned UCS-2 string (the vendor name). The string is
    /// NUL-terminated per the UEFI specification; the loop is additionally
    /// capped by our own line buffer, so it terminates either way.
    fn wstr(&mut self, s: *const u16) {
        if s.is_null() {
            self.str("(null)");
            return;
        }
        let mut p = s;
        while self.len + 1 < LINE_CAP {
            // SAFETY: `p` walks a firmware-provided NUL-terminated UCS-2
            // buffer, checked against NUL before each further advance.
            let unit = unsafe { core::ptr::read(p) };
            if unit == 0 {
                break;
            }
            self.raw(unit);
            p = p.wrapping_add(1);
        }
    }

    fn flush(&mut self) {
        if self.out.is_null() {
            self.len = 0;
            return;
        }
        self.buf[self.len] = 0;
        // SAFETY: `out` is the firmware's SimpleTextOutput instance, valid
        // for the life of the system table, and `buf` is a NUL-terminated
        // UCS-2 buffer as OutputString requires.
        let _ = unsafe { ((*self.out).output_string)(self.out, self.buf.as_mut_ptr()) };
        // A console write failure has no actionable response here; the run
        // continues so later probes still report.
        self.len = 0;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "efiapi" fn efi_main(
    image_handle: Handle,
    system_table: *mut SystemTable,
) -> Status {
    if system_table.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the firmware hands the entry point a valid system table that
    // outlives this call; the null guard above covers the impossible case.
    let st = unsafe { &*system_table };
    let mut con = Console::new(st.con_out);

    con.str("tinted-testapp: entry");
    con.nl();
    con.flush();
    con.str("image handle: ");
    con.hex(image_handle as u64, 16);
    con.nl();
    con.flush();

    // --- System table header -------------------------------------------------
    let revision = st.hdr.revision;
    con.str("UEFI revision: ");
    con.dec(u64::from(revision >> 16));
    con.chr('.');
    let minor = revision & 0xffff;
    if minor < 10 {
        con.chr('0');
    }
    con.dec(u64::from(minor));
    con.str(", HeaderSize: ");
    con.dec(u64::from(st.hdr.header_size));
    con.str(", Crc32: ");
    con.hex(u64::from(st.hdr.crc32), 8);
    con.nl();
    con.flush();

    // --- Firmware vendor (already UTF-16; print units verbatim) -------------
    con.str("firmware vendor: ");
    con.wstr(st.firmware_vendor);
    con.str(", revision: ");
    con.dec(u64::from(st.firmware_revision));
    con.nl();
    con.flush();

    // --- Configuration tables ------------------------------------------------
    con.str("configuration tables: ");
    con.dec(st.number_of_table_entries as u64);
    con.nl();
    con.flush();
    if !st.configuration_table.is_null() {
        for i in 0..st.number_of_table_entries {
            // SAFETY: the firmware publishes an array of
            // `number_of_table_entries` ConfigurationTable records at
            // `configuration_table`; the null guard selects the index range.
            let table = unsafe { &*st.configuration_table.add(i) };
            con.str("  [");
            con.dec(i as u64);
            con.str("] ");
            con.guid(&table.vendor_guid);
            con.str(" -> ");
            con.hex(table.vendor_table as u64, 16);
            con.nl();
            con.flush();
        }
    }

    if st.boot_services.is_null() || st.runtime_services.is_null() {
        con.str("boot/runtime services missing; stopping probes");
        con.nl();
        con.flush();
        return Status::UNSUPPORTED;
    }
    // SAFETY: UEFI publishes non-null boot and runtime service tables for
    // as long as the system table is valid, which is asserted above.
    let bs: &BootServices = unsafe { &*st.boot_services };
    let rt: &RuntimeServices = unsafe { &*st.runtime_services };

    // --- Memory map ----------------------------------------------------------
    // A u64-element buffer so the descriptor array is naturally aligned, and
    // exactly 64 KiB as the probe intends.
    let mut map_buf = [0u64; 8192];
    let mut map_size = core::mem::size_of_val(&map_buf);
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_version: u32 = 0;
    // SAFETY: every out-parameter is a valid local, and `map_buf` is
    // `map_size` bytes of writable, aligned memory.
    let status = unsafe {
        (bs.get_memory_map)(
            &mut map_size,
            map_buf.as_mut_ptr() as *mut MemoryDescriptor,
            &mut map_key,
            &mut desc_size,
            &mut desc_version,
        )
    };
    con.str("GetMemoryMap: ");
    con.status(status);
    con.nl();
    con.flush();
    if status == Status::SUCCESS && desc_size > 0 {
        let count = map_size / desc_size;
        con.str("  descriptors: ");
        con.dec(count as u64);
        con.str(", descriptor size: ");
        con.dec(desc_size as u64);
        con.str(", map key: ");
        con.hex(map_key as u64, 16);
        con.nl();
        con.flush();
        let base = map_buf.as_ptr() as *const u8;
        for i in 0..count.min(6) {
            // SAFETY: GetMemoryMap filled `map_size` bytes as
            // `desc_size`-strided descriptors inside `map_buf`, so the first
            // min(count, 6) slots hold valid records.
            let desc = unsafe { &*(base.add(i * desc_size) as *const MemoryDescriptor) };
            con.str("  desc[");
            con.dec(i as u64);
            con.str("] type=");
            con.dec(u64::from(desc.r#type));
            con.str(" start=");
            con.hex(desc.physical_start, 16);
            con.str(" pages=");
            con.dec(desc.number_of_pages);
            con.str(" attr=");
            con.hex(desc.attribute, 16);
            con.nl();
            con.flush();
        }
    }

    // --- Pool allocation -----------------------------------------------------
    let mut pool: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: out-pointer to a valid local; the firmware writes the block
    // address there on success.
    let status = unsafe { (bs.allocate_pool)(system::LOADER_DATA, 4096, &mut pool) };
    con.str("AllocatePool(4 KiB): ");
    con.status(status);
    con.nl();
    con.flush();
    if status == Status::SUCCESS {
        // SAFETY: `pool` was returned by a successful AllocatePool above and
        // is passed back exactly once.
        let free = unsafe { (bs.free_pool)(pool) };
        con.str("FreePool: ");
        con.status(free);
        con.nl();
        con.flush();
    } else {
        con.str("FreePool: skipped (allocate failed)");
        con.nl();
        con.flush();
    }

    // --- Page allocation -----------------------------------------------------
    let mut page: PhysicalAddress = 0;
    // SAFETY: out-pointer to a valid local for the returned address.
    let status = unsafe {
        (bs.allocate_pages)(
            system::ALLOCATE_ANY_PAGES,
            system::LOADER_DATA,
            1,
            &mut page,
        )
    };
    con.str("AllocatePages(1 page): ");
    con.status(status);
    con.nl();
    con.flush();
    if status == Status::SUCCESS {
        con.str("  page address: ");
        con.hex(page, 16);
        con.nl();
        con.flush();
        // SAFETY: address and page count round out the successful
        // AllocatePages call above; freeing once pairs the allocation.
        let free = unsafe { (bs.free_pages)(page, 1) };
        con.str("FreePages: ");
        con.status(free);
        con.nl();
        con.flush();
    } else {
        con.str("FreePages: skipped (allocate failed)");
        con.nl();
        con.flush();
    }

    // --- Filesystem volumes --------------------------------------------------
    let mut sfs_guid = SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    let mut count: usize = 0;
    let mut handles: *mut Handle = core::ptr::null_mut();
    // SAFETY: all out-pointers are valid locals; a null search key is the
    // documented form for BY_PROTOCOL.
    let status = unsafe {
        (bs.locate_handle_buffer)(
            system::BY_PROTOCOL,
            &mut sfs_guid,
            core::ptr::null_mut(),
            &mut count,
            &mut handles,
        )
    };
    con.str("LocateHandleBuffer(SIMPLE_FILE_SYSTEM): ");
    con.status(status);
    con.nl();
    con.flush();
    if status == Status::SUCCESS {
        con.str("  volumes: ");
        con.dec(count as u64);
        con.nl();
        con.flush();
        // SAFETY: the buffer came from the successful LocateHandleBuffer and
        // the spec mandates releasing it with FreePool.
        let free = unsafe { (bs.free_pool)(handles as *mut core::ffi::c_void) };
        con.str("FreePool(handles): ");
        con.status(free);
        con.nl();
        con.flush();
    } else if status == Status::NOT_FOUND {
        // NOT_FOUND is how LocateHandleBuffer reports "no such protocol".
        con.str("  volumes: 0");
        con.nl();
        con.flush();
    }

    // --- The volume this image was loaded from ---------------------------------
    // SAFETY: the boot services table is live and the image handle is ours.
    unsafe { probe_own_volume(&mut con, bs, image_handle) };

    // --- BootOrder variable --------------------------------------------------
    let mut name = [
        u16::from(b'B'),
        u16::from(b'o'),
        u16::from(b'o'),
        u16::from(b't'),
        u16::from(b'O'),
        u16::from(b'r'),
        u16::from(b'd'),
        u16::from(b'e'),
        u16::from(b'r'),
        0,
    ];
    let mut var_guid = system::GLOBAL_VARIABLE;
    let mut var_size: usize = 0;
    // SAFETY: name is NUL-terminated, the GUID and size are valid locals,
    // and a null data pointer with size 0 is the documented size probe.
    let status = unsafe {
        (rt.get_variable)(
            name.as_mut_ptr(),
            &mut var_guid,
            core::ptr::null_mut(),
            &mut var_size,
            core::ptr::null_mut(),
        )
    };
    con.str("GetVariable(BootOrder): ");
    if status == Status::BUFFER_TOO_SMALL || status == Status::SUCCESS {
        con.str("size=");
        con.dec(var_size as u64);
        con.str(" bytes, status=");
    }
    con.status(status);
    con.nl();
    con.flush();

    // --- Current time --------------------------------------------------------
    let mut time = Time::default();
    // SAFETY: out-pointer to a valid local; a null capabilities pointer is
    // permitted by the spec.
    let status = unsafe { (rt.get_time)(&mut time, core::ptr::null_mut()) };
    con.str("GetTime: ");
    con.status(status);
    if !status.is_error() {
        con.str(" ");
        con.dec(u64::from(time.year));
        con.chr('-');
        con.hex(u64::from(time.month), 2);
        con.chr('-');
        con.hex(u64::from(time.day), 2);
        con.chr(' ');
        con.hex(u64::from(time.hour), 2);
        con.chr(':');
        con.hex(u64::from(time.minute), 2);
        con.chr(':');
        con.hex(u64::from(time.second), 2);
    }
    con.nl();
    con.flush();

    // --- Timer: 100 ms relative, then wait -----------------------------------
    let mut event: Event = core::ptr::null_mut();
    // SAFETY: out-pointer to a valid local for the created event handle.
    let status = unsafe {
        (bs.create_event)(
            system::EVT_TIMER,
            system::TPL_CALLBACK,
            None,
            core::ptr::null_mut(),
            &mut event,
        )
    };
    con.str("CreateEvent(EVT_TIMER): ");
    con.status(status);
    con.nl();
    con.flush();
    if status == Status::SUCCESS {
        // 100 ns ticks: 100 ms = 1_000_000 ticks.
        // SAFETY: `event` is the handle just created; trigger is the spec's
        // 100 ns tick count for a relative timer.
        let status = unsafe { (bs.set_timer)(event, system::TIMER_RELATIVE, 1_000_000) };
        con.str("SetTimer(100 ms relative): ");
        con.status(status);
        con.nl();
        con.flush();
        // SAFETY: valid count of 1, out-pointers to valid locals, and the
        // event is armed by the SetTimer above.
        let mut index: usize = 0;
        let status = unsafe { (bs.wait_for_event)(1, &mut event, &mut index) };
        con.str("WaitForEvent: ");
        con.status(status);
        con.nl();
        con.flush();
        // SAFETY: `event` is the live handle created above, closed once.
        let _ = unsafe { (bs.close_event)(event) };
    } else {
        con.str("SetTimer/WaitForEvent: skipped (create failed)");
        con.nl();
        con.flush();
    }

    con.str("tinted-testapp: returning EFI_SUCCESS");
    con.nl();
    con.flush();
    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // No console guarantee exists inside a panic; park so the firmware log
    // keeps the last printed line as context.
    loop {
        core::hint::spin_loop();
    }
}

fn counter() -> (u64, u64) {
    let (count, frequency): (u64, u64);
    // SAFETY: reading the generic timer's counter and frequency has no effects.
    unsafe {
        core::arch::asm!("isb", "mrs {}, cntpct_el0", "mrs {}, cntfrq_el0", out(reg) count, out(reg) frequency);
    }
    (count, frequency)
}

/// Opens the volume the image came from through `LoadedImage.DeviceHandle` -
/// the way a boot loader finds the disk its kernel is on - lists the root, and
/// reads `\KERNEL` when the volume carries one, timing the read.
///
/// # Safety
///
/// `bs` must be the live boot services table and `image` this image's handle.
unsafe fn probe_own_volume(con: &mut Console, bs: &BootServices, image: Handle) {
    use r_efi::protocols::{file, loaded_image, simple_file_system};
    let mut loaded: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut guid = loaded_image::PROTOCOL_GUID;
    // SAFETY: valid handle, GUID and out-pointer.
    let status = unsafe { (bs.handle_protocol)(image, &mut guid, &mut loaded) };
    con.str("LoadedImage: ");
    con.status(status);
    con.nl();
    con.flush();
    if status != Status::SUCCESS {
        return;
    }
    // SAFETY: the firmware returned its loaded-image protocol for this image.
    let device = unsafe { (*(loaded as *mut loaded_image::Protocol)).device_handle };
    let mut sfs: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut guid = simple_file_system::PROTOCOL_GUID;
    // SAFETY: as above.
    let status = unsafe { (bs.handle_protocol)(device, &mut guid, &mut sfs) };
    con.str("DeviceHandle SimpleFileSystem: ");
    con.status(status);
    con.nl();
    con.flush();
    if status != Status::SUCCESS {
        return;
    }
    let sfs = sfs as *mut simple_file_system::Protocol;
    let mut root: *mut file::Protocol = core::ptr::null_mut();
    // SAFETY: the protocol came from the firmware.
    if unsafe { ((*sfs).open_volume)(sfs, &mut root) } != Status::SUCCESS {
        return;
    }

    // The root directory: one EFI_FILE_INFO per read, zero bytes at the end.
    let mut info = [0u64; 64];
    loop {
        let mut size = core::mem::size_of_val(&info);
        // SAFETY: the buffer is `size` bytes.
        let status =
            unsafe { ((*root).read)(root, &mut size, info.as_mut_ptr() as *mut core::ffi::c_void) };
        if status != Status::SUCCESS || size == 0 {
            break;
        }
        let entry = info.as_ptr() as *const file::Info;
        con.str("  \\");
        // SAFETY: the firmware wrote an EFI_FILE_INFO with a terminated name.
        unsafe {
            con.wstr((entry as *const u8).add(core::mem::size_of::<file::Info>()) as *const u16);
            con.str(if (*entry).attribute & file::DIRECTORY != 0 {
                "\\"
            } else {
                ""
            });
            con.str("  ");
            con.dec((*entry).file_size);
        }
        con.nl();
        con.flush();
    }

    let mut name = [0u16; 8];
    for (slot, byte) in name.iter_mut().zip(b"\\KERNEL") {
        *slot = u16::from(*byte);
    }
    let mut kernel: *mut file::Protocol = core::ptr::null_mut();
    // SAFETY: the name is terminated and the out-pointer is a local.
    let status =
        unsafe { ((*root).open)(root, &mut kernel, name.as_mut_ptr(), file::MODE_READ, 0) };
    if status != Status::SUCCESS {
        con.str("\\KERNEL: ");
        con.status(status);
        con.nl();
        con.flush();
        // SAFETY: the root handle is ours to close.
        unsafe { ((*root).close)(root) };
        return;
    }
    let mut size = core::mem::size_of_val(&info);
    let mut guid = file::INFO_ID;
    // SAFETY: the buffer is `size` bytes.
    unsafe {
        ((*kernel).get_info)(
            kernel,
            &mut guid,
            &mut size,
            info.as_mut_ptr() as *mut core::ffi::c_void,
        )
    };
    // SAFETY: GetInfo filled an EFI_FILE_INFO.
    let length = unsafe { (*(info.as_ptr() as *const file::Info)).file_size } as usize;
    let mut buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: out-pointer to a local.
    if unsafe { (bs.allocate_pool)(system::LOADER_DATA, length, &mut buffer) } != Status::SUCCESS {
        return;
    }
    let (start, frequency) = counter();
    let mut read = length;
    // SAFETY: the buffer holds `length` bytes.
    let status = unsafe { ((*kernel).read)(kernel, &mut read, buffer) };
    let elapsed_ms = (counter().0 - start) * 1000 / frequency;
    // Mach-O's 64-bit magic, as the first four bytes of an XNU kernel.
    // SAFETY: at least four bytes were read when the read succeeded.
    let magic = if read >= 4 {
        unsafe { (buffer as *const u32).read_unaligned() }
    } else {
        0
    };
    con.str("\\KERNEL: ");
    con.status(status);
    con.str(", ");
    con.dec(read as u64);
    con.str(" of ");
    con.dec(length as u64);
    con.str(" bytes in ");
    con.dec(elapsed_ms);
    con.str(" ms, magic ");
    con.hex(u64::from(magic), 8);
    con.nl();
    con.flush();
    // SAFETY: each resource is released once.
    unsafe {
        (bs.free_pool)(buffer);
        ((*kernel).close)(kernel);
        ((*root).close)(root);
    }
}
