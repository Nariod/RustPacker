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
        "fn aes_256_decrypt(buf: &Vec<u8>, key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
        let cipher = Cipher::new_256(key);    
        let decrypted = cipher.cbc_decrypt(iv, &buf);
    
        decrypted
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
