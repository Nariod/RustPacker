use crate::shellcode_reader::read_shellcode;
use crate::tools::{write_to_file, EncryptionOutput};
use libaes::Cipher;
use std::path::Path;

fn aes_256_encrypt(shellcode: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let cipher = Cipher::new_256(key);
    cipher.cbc_encrypt(iv, shellcode)
}

pub fn encrypt_aes(
    input_path: &Path,
    export_path: &Path,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> EncryptionOutput {
    println!(
        "[+] AES encrypting shellcode with key {:?} and IV {:?}",
        key, iv
    );
    let unencrypted = read_shellcode(input_path);
    let encrypted_content = aes_256_encrypt(&unencrypted, key, iv);
    write_to_file(&encrypted_content, export_path).expect("Failed to write AES output");

    let decryption_function =
        "fn aes_256_decrypt(buf: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
        let cipher = Cipher::new_256(key);
        cipher.cbc_decrypt(iv, buf)
    }"
        .to_string();

    let main = format!(
        "let key: [u8;32] = {:?};
    let iv: [u8;16] = {:?};   
    vec = aes_256_decrypt(&vec, &key, &iv);
    ",
        key, iv
    );

    println!("[+] Done AES encrypting shellcode!");
    EncryptionOutput {
        decryption_function,
        main,
        dependencies: Some(r#"libaes = "0.7""#.to_string()),
        imports: Some("use libaes::Cipher;".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let original: Vec<u8> = vec![0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00,
                                     0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51];
        let key: [u8; 32] = [0x01; 32];
        let iv: [u8; 16] = [0x02; 16];

        let encrypted = aes_256_encrypt(&original, &key, &iv);
        assert_ne!(encrypted, original);

        let cipher = Cipher::new_256(&key);
        let decrypted = cipher.cbc_decrypt(&iv, &encrypted);
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_aes_returns_expected_fields() {
        let dir = std::env::temp_dir().join("rustpacker_test_aes");
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("test_shellcode.bin");
        let output = dir.join("output.aes");
        fs::write(&input, &[0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00,
                             0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51]).unwrap();

        let key: [u8; 32] = [0x01; 32];
        let iv: [u8; 16] = [0x02; 16];
        let result = encrypt_aes(&input, &output, &key, &iv);

        assert!(!result.decryption_function.is_empty());
        assert!(!result.main.is_empty());
        assert!(result.dependencies.is_some());
        assert!(result.imports.is_some());
        assert!(output.exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
