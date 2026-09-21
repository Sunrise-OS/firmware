//! AArch64 exception vectors.
//!
//! The table is 16 entries of exactly 128 bytes: four kinds of exception at each
//! of four sources, which is the layout `VBAR_EL1` requires - a slot's address
//! is its offset, so an entry that overflows 128 bytes runs into its neighbour
//! and every exception after it is dispatched to the wrong code.
//!
//! Each slot therefore only saves the integer state and jumps out; the work that
//! follows (reading the exception's own registers, dispatching) happens in
//! `exception_entry`, outside the table.
//!
//! Note on the assembler: GNU `.align n` on ELF targets is *bytes*, not 2^n, so
//! the alignments here are `.balign`.

use core::arch::global_asm;

/// The saved state of an interrupted or faulting context.
#[repr(C)]
pub struct ExceptionFrame {
    pub x: [u64; 31],
    /// Which vector: `source * 4 + kind`. See `Source`/`Kind`.
    pub vector: u64,
    pub sp_el0: u64,
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
    pub far: u64,
}

/// Where the exception came from, from the vector offset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    CurrentSp0,
    CurrentSpX,
    LowerAarch64,
    LowerAarch32,
}

/// What kind of exception it was, from the vector offset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Synchronous,
    Irq,
    Fiq,
    SError,
}

impl ExceptionFrame {
    pub fn source(&self) -> Source {
        match self.vector >> 2 {
            0 => Source::CurrentSp0,
            1 => Source::CurrentSpX,
            2 => Source::LowerAarch64,
            _ => Source::LowerAarch32,
        }
    }

    pub fn kind(&self) -> Kind {
        match self.vector & 3 {
            0 => Kind::Synchronous,
            1 => Kind::Irq,
            2 => Kind::Fiq,
            _ => Kind::SError,
        }
    }

    /// The exception class, as reported in `ESR_EL1.EC`.
    pub fn exception_class(&self) -> u64 {
        (self.esr >> 26) & 0x3f
    }
}

/// Installs the vector table in `VBAR_EL1`.
pub fn install() {
    // SAFETY: the symbol is the vector table, which `balign 2048` keeps 11-bit
    // aligned as the architecture requires, and it lives in the RAM the
    // firmware runs from.
    unsafe {
        core::arch::asm!(
            "adrp {tmp}, __vector_table",
            "add  {tmp}, {tmp}, :lo12:__vector_table",
            "msr  vbar_el1, {tmp}",
            "isb",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}

/// The handler every vector entry calls.
///
/// # Safety
///
/// Called only from `exception_entry`, with a pointer to a frame built there.
/// On a synchronous exception, an SError or an FIQ it does not return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exception_handler(frame: *mut ExceptionFrame) {
    let frame = unsafe { &*frame };
    match frame.kind() {
        // IRQs are the timer's, and are expected: hand them to the GIC, which
        // dispatches and signals end of interrupt, then resume.
        Kind::Irq => crate::arch::gic::handle_irq(),
        _ => {
            crate::println!("\r\n[trap] {:?} from {:?}", frame.kind(), frame.source());
            crate::println!(
                "[trap] esr={:#018x} elr={:#018x} far={:#018x} spsr={:#018x}",
                frame.esr,
                frame.elr,
                frame.far,
                frame.spsr
            );
            crate::println!("[trap] exception class {:#x}", frame.exception_class());
            crate::println!(
                "[trap] x0={:#x} x1={:#x} x2={:#x} x3={:#x} x29={:#x} x30={:#x}",
                frame.x[0],
                frame.x[1],
                frame.x[2],
                frame.x[3],
                frame.x[29],
                frame.x[30]
            );
            crate::arch::halt();
        }
    }
}

// The frame: 31 general registers, the vector number, the exception state, and
// the fault address - 37 slots, padded to 38 to keep SP 16-byte aligned.
//
// A slot is 76 bytes: `sub`, the 16 saves, the vector number, and the branch.
// It has to stay under 128.
global_asm!(
    r#"
.macro ventry n
    .balign 128
    sub     sp, sp, #(38 * 8)
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]
    mov     x0, #(\n)
    b       exception_entry
.endm

.section .text.vectors, "ax"
.balign 2048
.global __vector_table
__vector_table:
    // Current EL with SP0.
    ventry 0
    ventry 1
    ventry 2
    ventry 3
    // Current EL with SPx: the firmware's own exceptions.
    ventry 4
    ventry 5
    ventry 6
    ventry 7
    // Lower EL, AArch64.
    ventry 8
    ventry 9
    ventry 10
    ventry 11
    // Lower EL, AArch32.
    ventry 12
    ventry 13
    ventry 14
    ventry 15

exception_entry:
    // x0 holds the vector number; the general registers are already saved, so
    // the remaining exception state can be read with x1 as scratch.
    str     x0,       [sp, #248]
    mrs     x1, sp_el0
    str     x1,       [sp, #256]
    mrs     x1, elr_el1
    str     x1,       [sp, #264]
    mrs     x1, spsr_el1
    str     x1,       [sp, #272]
    mrs     x1, esr_el1
    str     x1,       [sp, #280]
    mrs     x1, far_el1
    str     x1,       [sp, #288]
    mov     x0, sp
    bl      exception_handler
    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    add     sp, sp, #(38 * 8)
    eret
"#
);
