//! Control Flow Guard (CFG) mitigation utilities.
//!
//! This module provides functions to check CFG status, retrieve process cookies,
//! and encode/decode pointers as required by Windows when working with VEH.

use winapi::um::winnt::{PVOID, DWORD, HANDLE};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::errhandlingapi::GetProcessMitigationPolicy;
use winapi::shared::ntdef::BOOL;

/// Process mitigation policy for CFG.
#[repr(C)]
pub struct ProcessMitigationControlFlowGuardPolicy {
    pub enable_control_flow_guard: BOOL,
    pub strict_control_flow_guard: BOOL,
}

/// Checks if Control Flow Guard (CFG) is enabled for the current process.
///
/// # Returns
/// true if CFG is enabled, false otherwise.
pub fn is_cfg_enabled() -> bool {
    let mut policy: ProcessMitigationControlFlowGuardPolicy = unsafe { std::mem::zeroed() };
    let result = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            winapi::um::winnt::PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY as u32,
            &mut policy as *mut _ as PVOID,
            std::mem::size_of_val(&policy) as u32,
        )
    };
    result != 0 && policy.enable_control_flow_guard != 0
}

/// Retrieves the process cookie for the current process.
///
/// The process cookie is a per-process secret value used to obfuscate pointers.
///
/// # Returns
/// The process cookie, or None on failure.
pub fn get_process_cookie() -> Option<DWORD> {
    use winapi::um::processthreadsapi::NtQueryInformationProcess;
    use winapi::um::winnt::PROCESSINFOCLASS;

    let mut cookie: DWORD = 0;
    let mut return_length: u32 = 0;
    
    let status = unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            PROCESSINFOCLASS::ProcessCookie,
            &mut cookie as *mut _ as PVOID,
            std::mem::size_of_val(&cookie) as u32,
            &mut return_length,
        )
    };
    
    if status >= 0 {
        Some(cookie)
    } else {
        None
    }
}

/// Encodes a pointer using the process cookie.
///
/// This mimics the behavior of Windows' EncodePointer function.
///
/// # Arguments
/// * `ptr` - The raw pointer to encode.
/// * `cookie` - The process cookie to use for encoding.
///
/// # Returns
/// The encoded pointer.
pub fn encode_pointer(ptr: PVOID, cookie: DWORD) -> PVOID {
    let raw = ptr as u64;
    let encoded = rotate_left64(raw ^ cookie as u64, 0x40 - (cookie & 0x3f));
    encoded as PVOID
}

/// Decodes a pointer using the process cookie.
///
/// This mimics the behavior of Windows' DecodePointer function.
///
/// # Arguments
/// * `encoded` - The encoded pointer to decode.
/// * `cookie` - The process cookie to use for decoding.
///
/// # Returns
/// The decoded raw pointer.
pub fn decode_pointer(encoded: PVOID, cookie: DWORD) -> PVOID {
    let encoded_val = encoded as u64;
    let rotated = rotate_right64(encoded_val, 0x40 - (cookie & 0x3f));
    (rotated ^ cookie as u64) as PVOID
}

/// Performs a left rotation on a 64-bit value.
fn rotate_left64(value: u64, shift: u32) -> u64 {
    (value << shift) | (value >> (64 - shift))
}

/// Performs a right rotation on a 64-bit value.
fn rotate_right64(value: u64, shift: u32) -> u64 {
    (value >> shift) | (value << (64 - shift))
}

/// Global reference counter for VEH entries.
/// This is required by Windows when registering vectored handlers.
static mut G_REF: DWORD = 1;

/// Returns a pointer to the global reference counter.
pub fn get_ref_counter() -> *mut DWORD {
    unsafe { &mut G_REF }
}
