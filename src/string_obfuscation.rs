//! Advanced string obfuscation module for RustPacker
//!
//! This module provides utilities for obfuscating strings in the generated loaders
//! to evade static analysis by AV/EDR solutions.

use crate::tools::random_u8;

/// Obfuscation method for strings
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum ObfuscationMethod {
    /// Use litcrypt for compile-time string encryption
    Litcrypt,
    /// Use XOR encryption with a random key
    Xor,
    /// Use byte array with XOR
    ByteArrayXor,
}

/// Generate a random XOR key for string obfuscation
///
/// # Returns
/// A non-zero random u8 value
pub fn generate_xor_key() -> u8 {
    loop {
        let key = random_u8();
        if key != 0 {
            return key;
        }
    }
}

/// Obfuscate a string using XOR with a random key
///
/// # Arguments
/// * `input` - The string to obfuscate
///
/// # Returns
/// Tuple of (obfuscated_bytes, xor_key)
pub fn xor_obfuscate(input: &str) -> (Vec<u8>, u8) {
    let key = generate_xor_key();
    let obfuscated: Vec<u8> = input.bytes().map(|b| b ^ key).collect();
    (obfuscated, key)
}

/// Generate Rust code for XOR deobfuscation at runtime
///
/// # Arguments
/// * `var_name` - Name of the variable to create
/// * `obfuscated` - The obfuscated bytes
/// * `key` - The XOR key used for obfuscation
///
/// # Returns
/// Rust code string that deobfuscates the string at runtime
#[allow(dead_code)]
pub fn generate_xor_deobfuscation(var_name: &str, obfuscated: &[u8], key: u8) -> String {
    let bytes_lit: Vec<String> = obfuscated.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!(
        "let {} = [{}]\n    .iter()\n    .map(|b| *b ^ 0x{:02x})\n    .map(|b| b as char)\n    .collect::<String>();",
        var_name, bytes_lit.join(", "), key
    )
}

/// Generate Rust code for litcrypt obfuscation
///
/// # Arguments
/// * `var_name` - Name of the variable to create
/// * `input` - The string to obfuscate
///
/// # Returns
/// Rust code string using litcrypt
#[allow(dead_code)]
pub fn generate_litcrypt_obfuscation(var_name: &str, input: &str) -> String {
    // Check if the string can be used with litcrypt
    if can_use_litcrypt_literal(input) {
        format!("let {} = lc!(\"{}\");", var_name, input)
    } else {
        // Fallback to XOR obfuscation for complex strings
        let (obfuscated, key) = xor_obfuscate(input);
        generate_xor_deobfuscation(var_name, &obfuscated, key)
    }
}

/// Check if a string can be safely used with litcrypt
///
/// # Arguments
/// * `value` - The string to check
///
/// # Returns
/// true if the string can be used with litcrypt
pub fn can_use_litcrypt_literal(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_graphic() || c == ' ')
        && !value.contains('"')
        && !value.contains('\\')
        && !value.contains('\n')
        && !value.contains('\r')
        && !value.contains('\t')
}

/// Generate a function that deobfuscates a string at runtime
///
/// # Arguments
/// * `func_name` - Name of the deobfuscation function
/// * `input` - The string to obfuscate
///
/// # Returns
/// Rust code for the deobfuscation function
#[allow(dead_code)]
pub fn generate_deobfuscation_function(func_name: &str, input: &str) -> String {
    let (obfuscated, _key) = xor_obfuscate(input);
    let bytes_lit: Vec<String> = obfuscated.iter().map(|b| format!("0x{:02x}", b)).collect();

    format!(
        "fn {}(key: u8) -> String {{\n    let obfuscated = [{}];\n    obfuscated.iter()\n        .map(|b| *b ^ key)\n        .map(|b| b as char)\n        .collect::<String>()\n}}",
        func_name, bytes_lit.join(", ")
    )
}

/// Obfuscate a string for use in template code
///
/// # Arguments
/// * `input` - The string to obfuscate
/// * `method` - The obfuscation method to use
///
/// # Returns
/// Tuple of (obfuscated_code, deobfuscation_code, imports)
#[allow(dead_code)]
pub fn obfuscate_string(
    input: &str,
    method: ObfuscationMethod,
) -> (String, String, Option<String>) {
    match method {
        ObfuscationMethod::Litcrypt => {
            if can_use_litcrypt_literal(input) {
                (
                    format!("lc!(\"{}\")", input),
                    String::new(),
                    Some("use_litcrypt!();".to_string()),
                )
            } else {
                // Fallback to XOR
                let (obfuscated, _key) = xor_obfuscate(input);
                let deobfuscation = generate_xor_deobfuscation("s", &obfuscated, _key);
                (format!("{{ {} }}", deobfuscation), "s".to_string(), None)
            }
        }
        ObfuscationMethod::Xor => {
            let (obfuscated, key) = xor_obfuscate(input);
            let var_name = "obf_str";
            let deobfuscation = generate_xor_deobfuscation(var_name, &obfuscated, key);
            (
                format!("{{ {} }}", deobfuscation),
                var_name.to_string(),
                None,
            )
        }
        ObfuscationMethod::ByteArrayXor => {
            let (obfuscated, key) = xor_obfuscate(input);
            let bytes_lit: Vec<String> =
                obfuscated.iter().map(|b| format!("0x{:02x}", b)).collect();
            let array_lit = format!("[{}]", bytes_lit.join(", "));
            (
                format!("deobfuscate_string!({}, 0x{:02x})", array_lit, key),
                String::new(),
                Some("macro_rules! deobfuscate_string { ($arr:expr, $key:expr) => { $arr.iter().map(|b| *b ^ $key).map(|b| b as char).collect::<String>() }; }".to_string()),
            )
        }
    }
}

/// Create a macro for string deobfuscation
///
/// # Returns
/// Rust macro definition for string deobfuscation
#[allow(dead_code)]
pub fn generate_deobfuscation_macro() -> String {
    r#"
macro_rules! deobfuscate_str {
    ($name:ident, $arr:expr, $key:expr) => {
        let $name = $arr.iter()
            .map(|b| *b ^ $key)
            .map(|b| b as char)
            .collect::<String>();
    };
}
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_obfuscation_roundtrip() {
        let original = "notepad.exe";
        let (obfuscated, key) = xor_obfuscate(original);

        let deobfuscated: String = obfuscated
            .iter()
            .map(|b| *b ^ key)
            .map(|b| b as char)
            .collect();

        assert_eq!(deobfuscated, original);
    }

    #[test]
    fn test_xor_obfuscation_empty() {
        let original = "";
        let (obfuscated, _) = xor_obfuscate(original);
        assert!(obfuscated.is_empty());
    }

    #[test]
    fn test_xor_obfuscation_special_chars() {
        let original = "C:\\Windows\\System32";
        let (obfuscated, key) = xor_obfuscate(original);

        let deobfuscated: String = obfuscated
            .iter()
            .map(|b| *b ^ key)
            .map(|b| b as char)
            .collect();

        assert_eq!(deobfuscated, original);
    }

    #[test]
    fn test_can_use_litcrypt_literal() {
        assert!(can_use_litcrypt_literal("notepad.exe"));
        assert!(can_use_litcrypt_literal("explorer.exe"));
        assert!(!can_use_litcrypt_literal("path\\with\\backslash"));
        assert!(!can_use_litcrypt_literal("string\nwith\nnewlines"));
        assert!(!can_use_litcrypt_literal("string\"with\"quotes"));
    }

    #[test]
    fn test_generate_xor_deobfuscation() {
        let original = "test";
        let (obfuscated, key) = xor_obfuscate(original);
        let code = generate_xor_deobfuscation("my_var", &obfuscated, key);

        assert!(code.contains("my_var"));
        assert!(code.contains(&format!("0x{:02x}", key)));
    }

    #[test]
    fn test_generate_deobfuscation_function() {
        let original = "target.exe";
        let code = generate_deobfuscation_function("deobf_target", original);

        assert!(code.contains("fn deobf_target"));
        assert!(code.contains("String"));
    }

    #[test]
    fn test_obfuscate_string_litcrypt() {
        let (obfuscated, _, _) = obfuscate_string("notepad.exe", ObfuscationMethod::Litcrypt);
        assert!(obfuscated.contains("lc!"));
    }

    #[test]
    fn test_obfuscate_string_xor() {
        let (obfuscated, _, _) = obfuscate_string("test", ObfuscationMethod::Xor);
        assert!(obfuscated.contains("let obf_str"));
    }
}
