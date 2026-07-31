//! Encryption modules for RustPacker

pub mod aes;
pub mod uuid;
pub mod xor;

use std::path::Path;

use crate::encryption::aes::encrypt_aes;
use crate::encryption::uuid::encrypt_uuid;
use crate::encryption::xor::encrypt_xor;
use crate::obfuscation::non_zero_random_key;
use crate::utils::{random_aes_iv, random_aes_key};

/// Output of encryption process
#[derive(Debug, Clone)]
pub struct EncryptionOutput {
    pub decryption_function: String,
    pub main: String,
    pub dependencies: Option<String>,
    pub imports: Option<String>,
}

/// Encrypt shellcode using the specified method
pub fn encrypt_shellcode(
    input_path: &Path,
    export_path: &Path,
    method: crate::config::Encryption,
) -> EncryptionOutput {
    match method {
        crate::config::Encryption::Xor => {
            encrypt_xor(input_path, export_path, non_zero_random_key())
        }
        crate::config::Encryption::Aes => {
            encrypt_aes(input_path, export_path, &random_aes_key(), &random_aes_iv())
        }
        crate::config::Encryption::Uuid => encrypt_uuid(input_path, export_path),
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
