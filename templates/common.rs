// Shared utilities injected into every generated loader via {{COMMON_MODULE}}.
// Single source of truth: the generator copies this verbatim into each project's src/.

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
