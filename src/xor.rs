// module dedicated to xor a binary input and give back the path of the encrypted file

use crate::{shellcode_reader::meta_vec_from_file, tools::write_to_file};
use std::{collections::HashMap, path::Path};

fn xor_encode(shellcode: &[u8], key: u8) -> Vec<u8> {
    // thanks to https://github.com/memN0ps/arsenal-rs/blob/main/obfuscate_shellcode-rs/src/main.rs
    shellcode.iter().map(|x| x ^ key).collect()
}

pub fn meta_xor(input_path: &Path, export_path: &Path, key: u8) -> HashMap<String, String> {
    println!("[+] XORing shellcode with key {}..", key);
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = xor_encode(&unencrypted, key);
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }

    let mut result: HashMap<String, String> = HashMap::new();

    let decryption_function = "fn xor_decode(buf: &[u8], key: u8) -> Vec<u8> {
        buf.iter().map(|x| x ^ key).collect()
    }"
    .to_string();

    let main = format!("vec = xor_decode(&vec, {});", key);

    result.insert(String::from("decryption_function"), decryption_function);
    result.insert(String::from("main"), main);

    println!("[+] Done XORing shellcode!");
    result
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
    fn test_meta_xor_returns_expected_keys() {
        let dir = std::env::temp_dir().join("rustpacker_test_xor");
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("test_shellcode.bin");
        let output = dir.join("output.xor");
        fs::write(&input, &[0xfc, 0x48, 0x83]).unwrap();

        let result = meta_xor(&input, &output, 0x42);

        assert!(result.contains_key("decryption_function"));
        assert!(result.contains_key("main"));
        assert!(output.exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
