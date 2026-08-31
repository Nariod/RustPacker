//! Control Flow Guard (CFG) mitigation utilities.
//!
//! This module provides functions to check CFG status, retrieve process cookies,
//! and encode/decode pointers as required by Windows when working with VEH.

use winapi::um::errhandlingapi::GetProcessMitigationPolicy;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::PVOID;
use winapi::shared::ntdef::BOOL;

/// Process mitigation policy for CFG.
#[repr(C)]
pub struct ProcessMitigationControlFlowGuardPolicy {
    pub enable_control_flow_guard: BOOL,
    pub strict_control_flow_guard: BOOL,
}

/// Cookie rotation shift calculation constant.
const COOKIE_ROTATION_SHIFT_MASK: u32 = 0x3f;

/// Checks if Control Flow Guard (CFG) is enabled for the current process.
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
pub fn get_process_cookie() -> Option<u32> {
    use winapi::um::processthreadsapi::NtQueryInformationProcess;
    use winapi::um::winnt::PROCESSINFOCLASS;

    let mut cookie: u32 = 0;
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

/// Calculates the rotation shift from a cookie value.
fn calculate_rotation_shift(cookie: u32) -> u32 {
    0x40 - (cookie & COOKIE_ROTATION_SHIFT_MASK)
}

/// Performs a left rotation on a 64-bit value.
fn rotate_left64(value: u64, shift: u32) -> u64 {
    (value << shift) | (value >> (64 - shift))
}

/// Performs a right rotation on a 64-bit value.
fn rotate_right64(value: u64, shift: u32) -> u64 {
    (value >> shift) | (value << (64 - shift))
}

/// Encodes a pointer using the process cookie.
///
/// This mimics the behavior of Windows' EncodePointer function.
pub fn encode_pointer(ptr: PVOID, cookie: u32) -> PVOID {
    let raw = ptr as u64;
    let shift = calculate_rotation_shift(cookie);
    rotate_left64(raw ^ cookie as u64, shift) as PVOID
}

/// Decodes a pointer using the process cookie.
///
/// This mimics the behavior of Windows' DecodePointer function.
pub fn decode_pointer(encoded: PVOID, cookie: u32) -> PVOID {
    let encoded_val = encoded as u64;
    let shift = calculate_rotation_shift(cookie);
    (rotate_right64(encoded_val, shift) ^ cookie as u64) as PVOID
}

/// Global reference counter for VEH entries.
/// This is required by Windows when registering vectored handlers.
static mut g_ref: u32 = 1;

/// Returns a pointer to the global reference counter.
pub fn get_ref_counter() -> *mut u32 {
    unsafe { &mut g_ref }
}
