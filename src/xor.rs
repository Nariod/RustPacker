use std::{collections::HashMap, path::Path};
use crate::{shellcode_reader::ShellcodeReader, tools::write_to_file};

pub struct XorEncryptor;

impl XorEncryptor {
    pub fn xor_encode(shellcode: &[u8], key: u8) -> Vec<u8> {
        // thanks to https://github.com/memN0ps/arsenal-rs/blob/main/obfuscate_shellcode-rs/src/main.rs
        shellcode.iter().map(|x| x ^ key).collect()
    }

    pub fn meta_xor(
        input_path: &Path,
        export_path: &Path,
        key: u8,
    ) -> HashMap<String, String> {
        println!("[+] XORing shellcode with key {}..", key);
        let unencrypted = ShellcodeReader::meta_vec_from_file(input_path); // Replace with the appropriate function call
        let encrypted_content = XorEncryptor::xor_encode(&unencrypted, key);
        match write_to_file(&encrypted_content, export_path) {
            Ok(()) => (),
            Err(err) => panic!("{:?}", err),
        }

        let mut result: HashMap<String, String> = HashMap::new();

        let decryption_function = "fn xor_decode(buf: &Vec<u8>, key: u8) -> Vec<u8> {{
                buf.iter().map(|x| x ^ key).collect()
            }}".to_string();

        let main = format!("vec = xor_decode(&vec, {});", key);

        result.insert(String::from("decryption_function"), decryption_function);
        result.insert(String::from("main"), main);

        println!("[+] Done XORing shellcode!");
        result
    }
}
