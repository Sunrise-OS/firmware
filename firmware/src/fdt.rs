//! Just enough device tree to learn the machine's shape.
//!
//! UEFI on AArch64 is entered with a device tree in `x0`, and it is the only
//! description of the machine the firmware gets: QEMU generates it from the
//! command line, so it is also the only way to see a RAM size that differs from
//! what the firmware was built expecting. The firmware parses two things from
//! it: the memory node, and `/chosen/bootargs` for the loaded image's
//! command line. Everything else it needs is in `platform`.

const MAGIC: u32 = 0xd00d_feed;
const TOKEN_BEGIN_NODE: u32 = 1;
const TOKEN_END_NODE: u32 = 2;
const TOKEN_PROP: u32 = 3;
const TOKEN_END: u32 = 9;

/// A device tree blob, read in place from wherever the boot stage left it.
pub struct Fdt {
    base: usize,
    /// Offset of the structure block, and of the strings block.
    struct_off: usize,
    strings_off: usize,
    strings_len: usize,
    pub total_size: usize,
}

impl Fdt {
    /// Wraps a blob and checks its header. Returns `None` for a null pointer or
    /// anything that is not a device tree, so a caller can fall back to the
    /// built-in platform description.
    pub fn new(address: usize) -> Option<Fdt> {
        if address == 0 {
            return None;
        }
        let fdt = Fdt {
            base: address,
            struct_off: read_u32(address + 8) as usize,
            strings_off: read_u32(address + 12) as usize,
            strings_len: read_u32(address + 32) as usize,
            total_size: read_u32(address + 4) as usize,
        };
        (read_u32(address) == MAGIC).then_some(fdt)
    }

    fn u32_at(&self, offset: usize) -> u32 {
        read_u32(self.base + self.struct_off + offset)
    }

    fn string(&self, name_off: u32) -> &str {
        let start = self.base + self.strings_off + name_off as usize;
        let mut len = 0;
        while len < self.strings_len.saturating_sub(name_off as usize) {
            // SAFETY: the strings block is inside the blob, which the boot stage
            // has already written and sized for us.
            let byte = unsafe { core::ptr::read_volatile((start + len) as *const u8) };
            if byte == 0 {
                break;
            }
            len += 1;
        }
        // SAFETY: the bytes are NUL-terminated ASCII from the blob.
        unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(start as *const u8, len))
        }
    }

    fn property_value<'a>(&'a self, value_off: usize, len: u32) -> &'a [u8] {
        // SAFETY: the structure block bounds were validated against the blob
        // header by the boot stage that wrote it.
        unsafe {
            core::slice::from_raw_parts(
                (self.base + self.struct_off + value_off) as *const u8,
                len as usize,
            )
        }
    }

    /// The first `/memory` node's base and size, taking the root node's cell
    /// sizes into account.
    pub fn memory(&self) -> Option<(u64, u64)> {
        let mut cursor = 0;
        let mut address_cells = 2usize;
        let mut size_cells = 2usize;
        let mut depth = 0usize;
        let mut in_memory = false;

        loop {
            let token = self.u32_at(cursor);
            cursor += 4;
            match token {
                TOKEN_BEGIN_NODE => {
                    let name_start = self.base + self.struct_off + cursor;
                    let mut len = 0;
                    // SAFETY: as in `string`.
                    loop {
                        let byte =
                            unsafe { core::ptr::read_volatile((name_start + len) as *const u8) };
                        if byte == 0 {
                            break;
                        }
                        len += 1;
                    }
                    let name = unsafe {
                        core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                            name_start as *const u8,
                            len,
                        ))
                    };
                    cursor += len + 1;
                    cursor = (cursor + 3) & !3;
                    depth += 1;
                    if depth == 2 && name.starts_with("memory") {
                        in_memory = true;
                    }
                }
                TOKEN_END_NODE => {
                    if in_memory {
                        return None;
                    }
                    depth = depth.saturating_sub(1);
                    in_memory = false;
                }
                TOKEN_PROP => {
                    let len = self.u32_at(cursor);
                    let name_off = self.u32_at(cursor + 4);
                    cursor += 8;
                    let name = self.string(name_off);
                    let value = self.property_value(cursor, len);
                    cursor = (cursor + len as usize + 3) & !3;

                    match (depth, in_memory, name) {
                        (1, _, "#address-cells") => address_cells = be_u32(value) as usize,
                        (1, _, "#size-cells") => size_cells = be_u32(value) as usize,
                        (2, true, "reg") => {
                            let (base, _) = read_cells(value, address_cells);
                            let (size, _) = read_cells(&value[address_cells * 4..], size_cells);
                            return Some((base, size));
                        }
                        _ => {}
                    }
                }
                TOKEN_END => return None,
                _ => return None,
            }
        }
    }

    /// `/chosen/bootargs`, the command line the boot stage passed.
    pub fn bootargs(&self) -> Option<&str> {
        let mut cursor = 0;
        let mut depth = 0usize;
        let mut in_chosen = false;
        loop {
            let token = self.u32_at(cursor);
            cursor += 4;
            match token {
                TOKEN_BEGIN_NODE => {
                    let name_start = self.base + self.struct_off + cursor;
                    let mut len = 0;
                    // SAFETY: as in `string`.
                    loop {
                        let byte =
                            unsafe { core::ptr::read_volatile((name_start + len) as *const u8) };
                        if byte == 0 {
                            break;
                        }
                        len += 1;
                    }
                    let name = unsafe {
                        core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                            name_start as *const u8,
                            len,
                        ))
                    };
                    cursor += len + 1;
                    cursor = (cursor + 3) & !3;
                    depth += 1;
                    in_chosen = depth == 2 && name == "chosen";
                }
                TOKEN_END_NODE => {
                    in_chosen = false;
                    depth = depth.saturating_sub(1);
                }
                TOKEN_PROP => {
                    let len = self.u32_at(cursor);
                    let name_off = self.u32_at(cursor + 4);
                    cursor += 8;
                    let name = self.string(name_off);
                    let value = self.property_value(cursor, len);
                    cursor = (cursor + len as usize + 3) & !3;
                    if in_chosen && name == "bootargs" {
                        let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                        return core::str::from_utf8(&value[..end]).ok();
                    }
                }
                TOKEN_END => return None,
                _ => return None,
            }
        }
    }
}

fn read_u32(address: usize) -> u32 {
    // SAFETY: the caller passes addresses inside the blob.
    u32::from_be(unsafe { core::ptr::read_volatile(address as *const u32) })
}

fn be_u32(value: &[u8]) -> u32 {
    u32::from_be_bytes([value[0], value[1], value[2], value[3]])
}

/// Reads a big-endian cell array, returning the value and how many bytes it
/// used.
fn read_cells(value: &[u8], cells: usize) -> (u64, usize) {
    let mut result = 0u64;
    for index in 0..cells {
        result = (result << 32) | be_u32(&value[index * 4..]) as u64;
    }
    (result, cells * 4)
}
