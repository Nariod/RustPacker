//! String obfuscation module for RustPacker
//!
//! This module provides utilities for obfuscating strings in the generated loaders
//! to evade static analysis by AV/EDR solutions.

use crate::utils::random_u8;

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
pub fn generate_xor_deobfuscation(var_name: &str, obfuscated: &[u8], key: u8) -> String {
    let bytes_lit: Vec<String> = obfuscated.iter().map(|b| format!("0x{:02x}", b)).collect();
    format!(
        "let {} = [{}]\n    .iter()\n    .map(|b| *b ^ 0x{:02x})\n    .map(|b| b as char)\n    .collect::<String>();",
        var_name, bytes_lit.join(", "), key
    )
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

/// Obfuscate a string for use in generated code
///
/// # Arguments
/// * `value` - The string to obfuscate
///
/// # Returns
/// Obfuscated string expression using litcrypt or XOR
pub fn litcrypt_string_expr(value: &str) -> String {
    if can_use_litcrypt_literal(value) {
        format!("lc!(\"{}\")", value)
    } else {
        format!("{:?}.to_string()", value)
    }
}

/// Obfuscate a string for use in template code
///
/// # Arguments
/// * `value` - The string to obfuscate
///
/// # Returns
/// Obfuscated string expression
pub fn obfuscate_string_for_template(value: &str) -> String {
    // Use XOR obfuscation for all strings in templates
    let (obfuscated, key) = xor_obfuscate(value);
    let bytes_lit: Vec<String> = obfuscated.iter().map(|b| format!("0x{:02x}", b)).collect();

    // Generate a unique variable name based on the string
    let var_name = format!("s_{}", generate_string_hash(value));

    // Return the deobfuscation code
    format!(
        "let {} = [{}]\n    .iter()\n    .map(|b| *b ^ 0x{:02x})\n    .map(|b| b as char)\n    .collect::<String>();",
        var_name, bytes_lit.join(", "), key
    )
}

/// Generate a simple hash for string variable naming
fn generate_string_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash % 10000 // Keep it reasonable
}

/// Obfuscate API function name using XOR with a key
///
/// # Arguments
/// * `name` - The API function name to obfuscate
/// * `key` - The XOR key to use
///
/// # Returns
/// Obfuscated string representation of the API name
pub fn obfuscate_api_name(name: &str, key: u8) -> String {
    let bytes: Vec<String> = name.bytes().map(|b| format!("0x{:02x}", b ^ key)).collect();
    format!("[{}]", bytes.join(", "))
}

/// Generate a non-zero random key for API obfuscation
pub fn non_zero_random_key() -> u8 {
    loop {
        let k = random_u8();
        if k != 0 {
            return k;
        }
    }
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
    fn test_litcrypt_string_expr_wraps_simple_value() {
        assert_eq!(litcrypt_string_expr("notepad.exe"), "lc!(\"notepad.exe\")");
    }

    #[test]
    fn test_litcrypt_string_expr_falls_back_for_escaped_value() {
        assert_eq!(
            litcrypt_string_expr(r#"C:\Program Files\app.exe"#),
            r#""C:\\Program Files\\app.exe".to_string()"#
        );
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
    fn test_obfuscate_string_for_template() {
        let obfuscated = obfuscate_string_for_template("notepad.exe");
        assert!(obfuscated.contains("let s_"));
        assert!(obfuscated.contains(".iter()"));
        assert!(obfuscated.contains("^ 0x"));
    }

    #[test]
    fn test_obfuscate_api_name() {
        let obfuscated = obfuscate_api_name("NtCreateThreadEx", 0x42);
        assert!(obfuscated.starts_with('['));
        assert!(obfuscated.ends_with(']'));
        assert!(obfuscated.contains("0x"));
    }

    #[test]
    fn test_non_zero_random_key() {
        let key = non_zero_random_key();
        assert_ne!(key, 0);
    }
}
