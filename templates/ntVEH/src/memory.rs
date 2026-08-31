//! Memory protection utilities for VEH manipulation.
//!
//! This module provides safe wrappers around Windows memory protection APIs
//! like VirtualProtect and heap protection functions.

use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, PVOID, DWORD};
use winapi::um::heapapi::HeapAlloc;
use winapi::ctypes::c_void;

/// Memory protection flags compatible with Windows API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryProtection {
    /// Page cannot be accessed.
    NoAccess = winapi::um::winnt::PAGE_NOACCESS,
    /// Page can be read.
    ReadOnly = winapi::um::winnt::PAGE_READONLY,
    /// Page can be read and written.
    ReadWrite = winapi::um::winnt::PAGE_READWRITE,
    /// Page can be executed and read.
    ExecuteRead = winapi::um::winnt::PAGE_EXECUTE_READ,
    /// Page can be executed, read, and written.
    ExecuteReadWrite = winapi::um::winnt::PAGE_EXECUTE_READWRITE,
    /// Page can be executed.
    Execute = winapi::um::winnt::PAGE_EXECUTE,
    /// Page can be read and executed.
    ReadExecute = winapi::um::winnt::PAGE_EXECUTE_READ,
    /// Guard page (for stack overflow detection).
    Guard = winapi::um::winnt::PAGE_GUARD,
}

impl MemoryProtection {
    /// Returns the DWORD value for the protection.
    pub fn as_dword(&self) -> DWORD {
        *self as DWORD
    }
}

/// Changes the protection of a memory region.
///
/// # Arguments
/// * `address` - Pointer to the start of the region.
/// * `size` - Size of the region in bytes.
/// * `new_protection` - Desired memory protection.
///
/// # Returns
/// The old protection of the region, or None on failure.
pub fn set_memory_protection(
    address: PVOID,
    size: usize,
    new_protection: MemoryProtection,
) -> Option<DWORD> {
    let mut old_protect: DWORD = 0;
    let result = unsafe {
        VirtualProtect(
            address,
            size,
            new_protection.as_dword(),
            &mut old_protect,
        )
    };
    if result == 0 {
        None
    } else {
        Some(old_protect)
    }
}

/// Allocates memory from the default process heap.
///
/// # Arguments
/// * `size` - Size of memory to allocate.
///
/// # Returns
/// Pointer to the allocated memory, or null on failure.
pub fn heap_alloc(size: usize) -> *mut c_void {
    unsafe { HeapAlloc(winapi::um::heapapi::GetProcessHeap(), 0, size) }
}

/// Frees memory allocated from the heap.
///
/// # Arguments
/// * `ptr` - Pointer to the memory to free.
pub unsafe fn heap_free(ptr: *mut c_void) {
    winapi::um::heapapi::HeapFree(
        winapi::um::heapapi::GetProcessHeap(),
        0,
        ptr,
    );
}

/// Queries information about a memory region.
///
/// # Arguments
/// * `address` - Pointer to query.
///
/// # Returns
/// MemoryBasicInformation structure, or None on failure.
pub fn query_memory(address: PVOID) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let result = unsafe { VirtualQuery(address, &mut mbi, std::mem::size_of_val(&mbi)) };
    if result == 0 {
        None
    } else {
        Some(mbi)
    }
}
