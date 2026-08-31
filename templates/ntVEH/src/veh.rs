//! Vectored Exception Handler (VEH) manipulation utilities.
//!
//! This module provides functions to add, remove, and manipulate VEH/VCH handlers
//! for code injection and execution hijacking purposes.

use winapi::um::winnt::{PVOID, DWORD, LIST_ENTRY, HMODULE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::synchapi::{AcquireSRWLockExclusive, ReleaseSRWLockExclusive};
use winapi::um::errhandlingapi::EXCEPTION_POINTERS;
use winapi::ctypes::c_void;
use std::ffi::CString;

use crate::memory::{set_memory_protection, MemoryProtection, heap_alloc};
use crate::cfg::{is_cfg_enabled, get_process_cookie, encode_pointer, get_ref_counter};

/// Represents a vectored handler entry in the LdrpVectorHandlerList.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VectoredHandlerEntry {
    pub entry: LIST_ENTRY,
    pub refs: PVOID,
    pub unused: PVOID,
    pub handler: PVOID,
}

/// Represents the LdrpVectorHandlerList structure in ntdll.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VectoredHandlerList {
    pub lock_veh: PVOID,
    pub first_veh: *mut VectoredHandlerEntry,
    pub last_veh: *mut VectoredHandlerEntry,
    pub lock_vch: PVOID,
    pub first_vch: *mut VectoredHandlerEntry,
    pub last_vch: *mut VectoredHandlerEntry,
}

/// Cross-process flags for PEB.
#[repr(u32)]
pub enum CrossProcessFlags {
    ProcessUsingVEH = 0x4,
    ProcessUsingVCH = 0x8,
}

impl CrossProcessFlags {
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }
}

/// Sets or clears a flag in PEB.CrossProcessFlags.
pub fn set_peb_cross_process_flag(flag: CrossProcessFlags, set: bool) -> bool {
    use winapi::um::winnt::PEB;
    use winapi::um::processthreadsapi::NtQueryInformationProcess;
    use winapi::um::winnt::PROCESSINFOCLASS;

    let mut peb: *mut PEB = std::ptr::null_mut();
    let mut return_length: u32 = 0;
    
    let status = unsafe {
        NtQueryInformationProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            PROCESSINFOCLASS::ProcessBasicInformation,
            &mut peb as *mut _ as PVOID,
            std::mem::size_of_val(&peb) as u32,
            &mut return_length,
        )
    };
    
    if status < 0 {
        return false;
    }

    unsafe {
        if set {
            (*peb).CrossProcessFlags |= flag.as_u32();
        } else {
            (*peb).CrossProcessFlags &= !flag.as_u32();
        }
    }
    true
}

/// Finds the address of LdrpVectorHandlerList by pattern matching.
/// 
/// This searches for the `lea r12, [LdrpVectorHandlerList]` instruction
/// in the RtlRemoveVectoredExceptionHandler function.
pub fn get_vectored_handler_list() -> Option<*mut VectoredHandlerList> {
    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
    if ntdll.is_null() {
        return None;
    }

    let rtl_remove_veh = unsafe {
        GetProcAddress(
            ntdll,
            b"RtlRemoveVectoredExceptionHandler\0".as_ptr() as *const i8,
        )
    };
    if rtl_remove_veh.is_null() {
        return None;
    }

    // Pattern: lea r12, [displacement] = 0x4c 0x8d 0x25
    let pattern: [u8; 3] = [0x4c, 0x8d, 0x25];
    let mut addr = rtl_remove_veh as *const u8;
    
    // Skip initial jumps (0xE9)
    while unsafe { *addr } == 0xe9 {
        let offset = unsafe { *(addr.add(1) as *const i32) };
        addr = unsafe { addr.add(5).add(offset as usize) };
    }

    // Search for pattern
    let max_search = 0x1000;
    for _ in 0..max_search {
        if unsafe { 
            *addr == pattern[0] && 
            *addr.add(1) == pattern[1] && 
            *addr.add(2) == pattern[2] 
        } {
            let displacement = unsafe { *(addr.add(3) as *const i32) };
            let list_addr = unsafe { 
                addr.add(7).add(displacement as usize) as *mut VectoredHandlerList 
            };
            return Some(list_addr);
        }
        addr = unsafe { addr.add(1) };
    }
    None
}

/// Finds the address of LdrProtectMrdata function.
pub fn get_ldr_protect_mrdata() -> Option<extern "system" fn(BOOL, PVOID) -> c_void> {
    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
    let rtl_delete_func_table = unsafe {
        GetProcAddress(ntdll, b"RtlDeleteFunctionTable\0".as_ptr() as *const i8)
    };

    // Search for 'call LdrProtectMrdata' (0xE8 followed by 4-byte offset)
    let mut addr = rtl_delete_func_table as *const u8;
    for _ in 0..0x1000 {
        if unsafe { *addr } == 0xe8 {
            let offset = unsafe { *(addr.add(1) as *const i32) };
            let target = unsafe { (addr as usize + 5).wrapping_add(offset as usize) };
            return Some(unsafe { std::mem::transmute(target as *const c_void) });
        }
        addr = unsafe { addr.add(1) };
    }
    None
}

/// Finds the address of LdrpMrdataHeap.
pub fn get_ldrp_mrdata_heap() -> Option<*mut PVOID> {
    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
    let rtl_add_func_table = unsafe {
        GetProcAddress(ntdll, b"RtlAddFunctionTable\0".as_ptr() as *const i8)
    };

    // Pattern: mov rcx, [LdrpMrdataHeap] = 0x48 0x8B 0x0D
    let pattern: [u8; 3] = [0x48, 0x8B, 0x0D];
    let mut addr = rtl_add_func_table as *const u8;
    
    for _ in 0..0x1000 {
        if unsafe { 
            *addr == pattern[0] && 
            *addr.add(1) == pattern[1] && 
            *addr.add(2) == pattern[2] 
        } {
            let displacement = unsafe { *(addr.add(3) as *const i32) };
            let heap_ptr = unsafe { (addr as usize + 7).wrapping_add(displacement as usize) as *mut PVOID };
            return Some(heap_ptr);
        }
        addr = unsafe { addr.add(1) };
    }
    None
}

/// Type for the LdrProtectMrdata function.
type LdrProtectMrdataFn = extern "system" fn(BOOL, PVOID) -> c_void;

/// Wrapper for LdrProtectMrdata to avoid CFG alignment issues.
/// Uses an indirect call via a function pointer.
pub unsafe fn call_ldr_protect_mrdata(
    protect: BOOL,
    address: PVOID,
    ldr_protect_mrdata: LdrProtectMrdataFn,
) {
    // Use a function pointer for indirect call
    let func_ptr: *mut Option<extern "system" fn(BOOL, PVOID) -> c_void> = 
        &mut Some(ldr_protect_mrdata);
    (*func_ptr).unwrap()(protect, address);
}

/// Adds a custom Vectored Exception Handler (VEH).
///
/// This is similar to AddVectoredExceptionHandler but with full control over
/// the registration process, including CFG support.
///
/// # Arguments
/// * `handler` - The exception handler function to register.
/// * `insert_first` - If true, inserts at the beginning of the list.
///
/// # Returns
/// Pointer to the new handler entry, or None on failure.
pub fn add_veh_handler(
    handler: extern "system" fn(*mut EXCEPTION_POINTERS) -> i32,
    insert_first: bool,
) -> Option<*mut VectoredHandlerEntry> {
    // 1. Resolve internal addresses
    let list_ptr = get_vectored_handler_list()?;
    let list = unsafe { &mut *list_ptr };
    
    let ldr_protect_mrdata = get_ldr_protect_mrdata()?;
    
    // 2. Check CFG status
    let cfg_enabled = is_cfg_enabled();
    let mut heap = unsafe { winapi::um::heapapi::GetProcessHeap() };
    
    if cfg_enabled {
        if let Some(mrdata_heap_ptr) = get_ldrp_mrdata_heap() {
            let mrdata_heap = unsafe { *mrdata_heap_ptr };
            if !mrdata_heap.is_null() {
                heap = mrdata_heap;
                // For now, we'll handle protection when needed
            }
        }
    }

    // 3. Acquire VEH lock
    unsafe { AcquireSRWLockExclusive(list.lock_veh as *mut _) };

    // 4. Make .mrdata writable
    let list_size = std::mem::size_of::<VectoredHandlerList>();
    let _old_protect = set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadWrite);
    
    if _old_protect.is_none() {
        unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };
        return None;
    }

    // 5. Check if list is empty
    let veh_list_start = (list_ptr as usize + std::mem::offset_of!(VectoredHandlerList, first_veh)) 
        as *mut VectoredHandlerEntry;
    let is_empty = unsafe { list.first_veh == veh_list_start };

    // 6. Allocate new entry
    let entry_size = std::mem::size_of::<VectoredHandlerEntry>();
    let new_entry = heap_alloc(entry_size) as *mut VectoredHandlerEntry;
    if new_entry.is_null() {
        set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadOnly);
        unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };
        return None;
    }

    // 7. Configure the entry
    unsafe {
        (*new_entry).refs = get_ref_counter() as PVOID;
        (*new_entry).unused = std::ptr::null_mut();
        
        if let Some(cookie) = get_process_cookie() {
            (*new_entry).handler = encode_pointer(handler as PVOID, cookie);
        } else {
            (*new_entry).handler = handler as PVOID;
        }
    }

    // 8. Insert into list
    if is_empty || insert_first {
        if is_empty {
            set_peb_cross_process_flag(CrossProcessFlags::ProcessUsingVEH, true);
            unsafe {
                (*new_entry).entry.Flink = veh_list_start as *mut LIST_ENTRY;
                (*new_entry).entry.Blink = veh_list_start as *mut LIST_ENTRY;
            }
            list.last_veh = new_entry;
        } else {
            unsafe {
                (*new_entry).entry.Flink = list.first_veh as *mut LIST_ENTRY;
                (*new_entry).entry.Blink = veh_list_start as *mut LIST_ENTRY;
                (*list.first_veh).entry.Blink = &mut (*new_entry).entry as *mut _;
            }
        }
        list.first_veh = new_entry;
    } else {
        unsafe {
            (*list.last_veh).entry.Flink = new_entry as *mut LIST_ENTRY;
            (*new_entry).entry.Blink = list.last_veh as *mut LIST_ENTRY;
            (*new_entry).entry.Flink = veh_list_start as *mut LIST_ENTRY;
        }
        list.last_veh = new_entry;
    }

    // 9. Restore protections
    set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadOnly);
    
    // 10. Release lock
    unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };

    Some(new_entry)
}

/// Overwrites the first VEH handler in the list.
///
/// This is a simpler approach than adding a new handler, but be careful
/// as it may break existing functionality (e.g., EDR hooks).
///
/// # Arguments
/// * `handler` - The new handler function to set as the first VEH.
///
/// # Returns
/// true if successful, false otherwise.
pub fn overwrite_first_veh(handler: extern "system" fn(*mut EXCEPTION_POINTERS) -> i32) -> bool {
    let list_ptr = get_vectored_handler_list().unwrap_or_else(|| std::ptr::null_mut());
    if list_ptr.is_null() {
        return false;
    }

    let list = unsafe { &mut *list_ptr };
    let veh_list_start = (list_ptr as usize + std::mem::offset_of!(VectoredHandlerList, first_veh)) 
        as *mut VectoredHandlerEntry;

    unsafe { AcquireSRWLockExclusive(list.lock_veh as *mut _) };

    if list.first_veh == veh_list_start {
        unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };
        return false;
    }

    let list_size = std::mem::size_of::<VectoredHandlerList>();
    let _old_protect = set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadWrite);
    
    if _old_protect.is_none() {
        unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };
        return false;
    }

    if let Some(cookie) = get_process_cookie() {
        unsafe {
            (*list.first_veh).handler = encode_pointer(handler as PVOID, cookie);
        }
    } else {
        unsafe {
            (*list.first_veh).handler = handler as PVOID;
        }
    }

    set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadOnly);
    unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };

    true
}

/// Triggers an exception to test VEH handlers.
/// This causes a division by zero exception.
pub fn trigger_exception() {
    unsafe {
        let zero: i32 = 0;
        let _ = 1 / zero;
    }
}
