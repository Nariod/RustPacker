// module dedicated to AES encrypt a binary input and give back the path of the encrypted file

use crate::{shellcode_reader::meta_vec_from_file, tools::write_to_file};
use libaes::Cipher;
use std::{collections::HashMap, path::Path};

fn aes_256_encrypt(shellcode: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    // thanks to https://github.com/memN0ps/arsenal-rs/blob/ee385df07805515da5ffc2a9900d51d24a47f9ab/obfuscate_shellcode-rs/src/main.rs
    let cipher = Cipher::new_256(key);

    cipher.cbc_encrypt(iv, shellcode)
}

pub fn meta_aes(
    input_path: &Path,
    export_path: &Path,
    key: &[u8; 32],
    iv: &[u8; 16],
) -> HashMap<String, String> {
    println!(
        "[+] AES encrypting shellcode with key {:?} and IV {:?}",
        key, iv
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = aes_256_encrypt(&unencrypted, key, iv);
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }

    let mut result: HashMap<String, String> = HashMap::new();

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
    let dependencies = r#"libaes = "0.7""#.to_string();

    let imports = "
    use libaes::Cipher;
    "
    .to_string();

    result.insert(String::from("decryption_function"), decryption_function);
    result.insert(String::from("main"), main);
    result.insert(String::from("dependencies"), dependencies);
    result.insert(String::from("imports"), imports);

    println!("[+] Done AES encrypting shellcode!");
    result
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
    fn test_meta_aes_returns_expected_keys() {
        let dir = std::env::temp_dir().join("rustpacker_test_aes");
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("test_shellcode.bin");
        let output = dir.join("output.aes");
        fs::write(&input, &[0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00,
                             0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51]).unwrap();

        let key: [u8; 32] = [0x01; 32];
        let iv: [u8; 16] = [0x02; 16];
        let result = meta_aes(&input, &output, &key, &iv);

        assert!(result.contains_key("decryption_function"));
        assert!(result.contains_key("main"));
        assert!(result.contains_key("dependencies"));
        assert!(result.contains_key("imports"));
        assert!(output.exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
