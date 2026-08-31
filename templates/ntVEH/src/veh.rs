//! Vectored Exception Handler (VEH) manipulation utilities.
//!
//! This module provides functions to add, remove, and manipulate VEH/VCH handlers
//! for code injection and execution hijacking purposes.

use winapi::um::winnt::{BOOL, DWORD, LIST_ENTRY, PVOID};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::synchapi::{AcquireSRWLockExclusive, ReleaseSRWLockExclusive};
use winapi::um::errhandlingapi::EXCEPTION_POINTERS;

use crate::cfg::{encode_pointer, get_process_cookie, get_ref_counter};
use crate::memory::{heap_alloc, set_memory_protection, MemoryProtection};

/// Pattern bytes for `lea r12, [displacement]` instruction.
const PATTERN_LEA_R12: [u8; 3] = [0x4c, 0x8d, 0x25];

/// Pattern bytes for `mov rcx, [displacement]` instruction.
const PATTERN_MOV_RCX: [u8; 3] = [0x48, 0x8B, 0x0D];

/// JMP instruction opcode.
const OPCODE_JMP: u8 = 0xe9;

/// CALL instruction opcode.
const OPCODE_CALL: u8 = 0xe8;

/// Maximum bytes to search for patterns.
const MAX_PATTERN_SEARCH: usize = 0x1000;

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

/// Skips initial jump instructions in a function.
fn skip_initial_jumps(addr: &mut *const u8) {
    while unsafe { *addr } == OPCODE_JMP {
        let offset = unsafe { *(addr.add(1) as *const i32) };
        *addr = unsafe { addr.add(5).add(offset as usize) };
    }
}

/// Searches for a pattern in memory starting from a given address.
fn find_pattern(start_addr: *const u8, pattern: &[u8]) -> Option<*const u8> {
    let mut addr = start_addr;
    skip_initial_jumps(&mut addr);

    for _ in 0..MAX_PATTERN_SEARCH {
        if unsafe {
            *addr == pattern[0] &&
            *addr.add(1) == pattern[1] &&
            *addr.add(2) == pattern[2]
        } {
            return Some(addr);
        }
        addr = unsafe { addr.add(1) };
    }
    None
}

/// Finds the address of LdrpVectorHandlerList by pattern matching.
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

    let addr = find_pattern(rtl_remove_veh as *const u8, &PATTERN_LEA_R12)?;
    if addr.is_none() {
        return None;
    }

    let addr = addr.unwrap();
    let displacement = unsafe { *(addr.add(3) as *const i32) };
    Some(unsafe { addr.add(7).add(displacement as usize) as *mut VectoredHandlerList })
}

/// Finds the address of LdrProtectMrdata function.
pub fn get_ldr_protect_mrdata() -> Option<extern "system" fn(BOOL, PVOID) -> ()> {
    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8) };
    let rtl_delete_func_table = unsafe {
        GetProcAddress(ntdll, b"RtlDeleteFunctionTable\0".as_ptr() as *const i8)
    };

    let mut addr = rtl_delete_func_table as *const u8;
    for _ in 0..MAX_PATTERN_SEARCH {
        if unsafe { *addr } == OPCODE_CALL {
            let offset = unsafe { *(addr.add(1) as *const i32) };
            let target = unsafe { (addr as usize + 5).wrapping_add(offset as usize) };
            return Some(unsafe { std::mem::transmute(target as *const ()) });
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

    let addr = find_pattern(rtl_add_func_table as *const u8, &PATTERN_MOV_RCX)?;
    if addr.is_none() {
        return None;
    }

    let addr = addr.unwrap();
    let displacement = unsafe { *(addr.add(3) as *const i32) };
    Some(unsafe { (addr as usize + 7).wrapping_add(displacement as usize) as *mut PVOID })
}

/// Type for the LdrProtectMrdata function.
pub type LdrProtectMrdataFn = extern "system" fn(BOOL, PVOID) -> ();

/// Acquires the VEH list lock and makes .mrdata writable.
fn acquire_veh_lock_and_make_writable(list_ptr: *mut VectoredHandlerList) -> bool {
    let list = unsafe { &mut *list_ptr };
    unsafe { AcquireSRWLockExclusive(list.lock_veh as *mut _) };

    let list_size = std::mem::size_of::<VectoredHandlerList>();
    let old_protect = set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadWrite);

    if old_protect.is_none() {
        unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };
        return false;
    }
    true
}

/// Releases the VEH list lock and restores .mrdata to read-only.
fn release_veh_lock_and_restore(list_ptr: *mut VectoredHandlerList) {
    let list_size = std::mem::size_of::<VectoredHandlerList>();
    set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadOnly);
    let list = unsafe { &mut *list_ptr };
    unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };
}

/// Allocates and configures a new VEH entry.
fn allocate_and_configure_entry(
    handler: extern "system" fn(*mut EXCEPTION_POINTERS) -> i32,
    heap: *mut (),
) -> *mut VectoredHandlerEntry {
    let entry_size = std::mem::size_of::<VectoredHandlerEntry>();
    let new_entry = heap_alloc(entry_size) as *mut VectoredHandlerEntry;

    if new_entry.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        (*new_entry).refs = get_ref_counter() as PVOID;
        (*new_entry).unused = std::ptr::null_mut();

        if let Some(cookie) = get_process_cookie() {
            (*new_entry).handler = encode_pointer(handler as PVOID, cookie);
        } else {
            (*new_entry).handler = handler as PVOID;
        }
    }

    new_entry
}

/// Checks if the VEH list is empty.
fn is_veh_list_empty(list: &VectoredHandlerList) -> bool {
    let list_ptr = list as *const _ as *mut u8;
    let veh_list_start = (list_ptr as usize + std::mem::offset_of!(VectoredHandlerList, first_veh))
        as *mut VectoredHandlerEntry;
    unsafe { list.first_veh == veh_list_start }
}

/// Inserts a new entry at the beginning of the VEH list.
fn insert_entry_at_beginning(list: &mut VectoredHandlerList, new_entry: *mut VectoredHandlerEntry) {
    let list_ptr = list as *const _ as *mut u8;
    let veh_list_start = (list_ptr as usize + std::mem::offset_of!(VectoredHandlerList, first_veh))
        as *mut VectoredHandlerEntry;

    set_peb_cross_process_flag(CrossProcessFlags::ProcessUsingVEH, true);

    unsafe {
        (*new_entry).entry.Flink = veh_list_start as *mut _;
        (*new_entry).entry.Blink = veh_list_start as *mut _;
        list.last_veh = new_entry;
    }
    list.first_veh = new_entry;
}

/// Inserts a new entry at the end of the VEH list.
fn insert_entry_at_end(list: &mut VectoredHandlerList, new_entry: *mut VectoredHandlerEntry) {
    let list_ptr = list as *const _ as *mut u8;
    let veh_list_start = (list_ptr as usize + std::mem::offset_of!(VectoredHandlerList, first_veh))
        as *mut VectoredHandlerEntry;

    unsafe {
        (*list.last_veh).entry.Flink = new_entry as *mut _;
        (*new_entry).entry.Blink = list.last_veh as *mut _;
        (*new_entry).entry.Flink = veh_list_start as *mut _;
    }
    list.last_veh = new_entry;
}

/// Inserts a new entry after the first existing entry.
fn insert_entry_after_first(list: &mut VectoredHandlerList, new_entry: *mut VectoredHandlerEntry) {
    let list_ptr = list as *const _ as *mut u8;
    let veh_list_start = (list_ptr as usize + std::mem::offset_of!(VectoredHandlerList, first_veh))
        as *mut VectoredHandlerEntry;

    unsafe {
        (*new_entry).entry.Flink = list.first_veh as *mut _;
        (*new_entry).entry.Blink = veh_list_start as *mut _;
        (*list.first_veh).entry.Blink = &mut (*new_entry).entry as *mut _;
    }
    list.first_veh = new_entry;
}

/// Adds a custom Vectored Exception Handler (VEH).
pub fn add_veh_handler(
    handler: extern "system" fn(*mut EXCEPTION_POINTERS) -> i32,
    insert_first: bool,
) -> Option<*mut VectoredHandlerEntry> {
    let list_ptr = get_vectored_handler_list()?;
    let list = unsafe { &mut *list_ptr };

    let _ = get_ldr_protect_mrdata()?;

    let is_cfg_enabled = is_cfg_enabled();
    let heap = if is_cfg_enabled {
        get_ldrp_mrdata_heap().map_or(
            unsafe { winapi::um::heapapi::GetProcessHeap() },
            |mrdata_heap_ptr| unsafe { *mrdata_heap_ptr },
        )
    } else {
        unsafe { winapi::um::heapapi::GetProcessHeap() }
    };

    if !acquire_veh_lock_and_make_writable(list_ptr) {
        return None;
    }

    let is_empty = is_veh_list_empty(list);

    let new_entry = allocate_and_configure_entry(handler, heap);
    if new_entry.is_null() {
        release_veh_lock_and_restore(list_ptr);
        return None;
    }

    if is_empty || insert_first {
        if is_empty {
            insert_entry_at_beginning(list, new_entry);
        } else {
            insert_entry_after_first(list, new_entry);
        }
    } else {
        insert_entry_at_end(list, new_entry);
    }

    release_veh_lock_and_restore(list_ptr);
    Some(new_entry)
}

/// Overwrites the first VEH handler in the list.
pub fn overwrite_first_veh(handler: extern "system" fn(*mut EXCEPTION_POINTERS) -> i32) -> bool {
    let list_ptr = get_vectored_handler_list().unwrap_or_else(|| std::ptr::null_mut());
    if list_ptr.is_null() {
        return false;
    }

    let list = unsafe { &mut *list_ptr };
    let list_ptr_usize = list_ptr as usize;
    let veh_list_start = (list_ptr_usize + std::mem::offset_of!(VectoredHandlerList, first_veh))
        as *mut VectoredHandlerEntry;

    unsafe { AcquireSRWLockExclusive(list.lock_veh as *mut _) };

    if list.first_veh == veh_list_start {
        unsafe { ReleaseSRWLockExclusive(list.lock_veh as *mut _) };
        return false;
    }

    let list_size = std::mem::size_of::<VectoredHandlerList>();
    let old_protect = set_memory_protection(list_ptr as PVOID, list_size, MemoryProtection::ReadWrite);

    if old_protect.is_none() {
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
pub fn trigger_exception() {
    unsafe {
        let zero: i32 = 0;
        let _ = 1 / zero;
    }
}
