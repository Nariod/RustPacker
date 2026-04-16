use crate::shellcode_reader::read_shellcode;
use crate::tools::{write_to_file, EncryptionOutput};
use std::path::Path;

fn xor_encode(shellcode: &[u8], key: u8) -> Vec<u8> {
    shellcode.iter().map(|x| x ^ key).collect()
}

pub fn encrypt_xor(input_path: &Path, export_path: &Path, key: u8) -> EncryptionOutput {
    println!("[+] XORing shellcode with key {}..", key);
    let unencrypted = read_shellcode(input_path);
    let encrypted_content = xor_encode(&unencrypted, key);
    write_to_file(&encrypted_content, export_path).expect("Failed to write XOR output");

    let decryption_function = "fn xor_decode(buf: &[u8], key: u8) -> Vec<u8> {
        buf.iter().map(|x| x ^ key).collect()
    }"
    .to_string();

    let main = format!("vec = xor_decode(&vec, {});", key);

    println!("[+] Done XORing shellcode!");
    EncryptionOutput {
        decryption_function,
        main,
        dependencies: None,
        imports: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_xor_encode_roundtrip() {
        let original: Vec<u8> = vec![0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0];
        let key: u8 = 0x42;
        let encoded = xor_encode(&original, key);
        let decoded = xor_encode(&encoded, key);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_xor_encode_with_zero_key() {
        let original: Vec<u8> = vec![0xfc, 0x48, 0x83];
        let encoded = xor_encode(&original, 0);
        assert_eq!(encoded, original);
    }

    #[test]
    fn test_xor_encode_empty() {
        let original: Vec<u8> = vec![];
        let encoded = xor_encode(&original, 0xAB);
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_encrypt_xor_returns_expected_fields() {
        let dir = std::env::temp_dir().join("rustpacker_test_xor");
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("test_shellcode.bin");
        let output = dir.join("output.xor");
        fs::write(&input, &[0xfc, 0x48, 0x83]).unwrap();

        let result = encrypt_xor(&input, &output, 0x42);

        assert!(!result.decryption_function.is_empty());
        assert!(!result.main.is_empty());
        assert!(result.dependencies.is_none());
        assert!(result.imports.is_none());
        assert!(output.exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
