//! Encryption modules for RustPacker
//!
//! This module provides various encryption methods for shellcode.

pub mod aes;
pub mod uuid;
pub mod xor;

use std::path::Path;

/// Output of encryption process
#[derive(Debug, Clone)]
pub struct EncryptionOutput {
    pub decryption_function: String,
    pub main: String,
    pub dependencies: Option<String>,
    pub imports: Option<String>,
}

/// Encrypt shellcode using the specified method
///
/// # Arguments
/// * `input_path` - Path to the input shellcode file
/// * `export_path` - Path to save the encrypted shellcode
/// * `method` - Encryption method to use
///
/// # Returns
/// EncryptionOutput containing all necessary code for decryption
pub fn encrypt_shellcode(
    input_path: &Path,
    export_path: &Path,
    method: crate::config::Encryption,
) -> EncryptionOutput {
    match method {
        crate::config::Encryption::Xor => xor::encrypt_xor(
            input_path,
            export_path,
            crate::obfuscation::non_zero_random_key(),
        ),
        crate::config::Encryption::Aes => aes::encrypt_aes(
            input_path,
            export_path,
            &crate::utils::random_aes_key(),
            &crate::utils::random_aes_iv(),
        ),
        crate::config::Encryption::Uuid => uuid::encrypt_uuid(input_path, export_path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Encryption;
    use std::fs;

    #[test]
    fn test_encrypt_shellcode_xor() {
        let dir = std::env::temp_dir().join("rustpacker_test_encrypt_xor");
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("test.bin");
        let output = dir.join("output.xor");
        fs::write(&input, &[0xfc, 0x48, 0x83]).unwrap();

        let result = encrypt_shellcode(&input, &output, Encryption::Xor);
        assert!(!result.decryption_function.is_empty());
        assert!(!result.main.is_empty());
        assert!(output.exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
