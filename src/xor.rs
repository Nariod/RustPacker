// module dedicated to xor a binary input and give back the path of the encrypted file

use std::fs::File;
use std::path::Path;
use std::path::PathBuf;


fn xor_encode(shellcode: &Vec<u8>, key: u8) -> Vec<u8> {
    // thanks to https://github.com/memN0ps/arsenal-rs/blob/main/obfuscate_shellcode-rs/src/main.rs
    shellcode.iter().map(|x| x ^ key).collect()
}

fn meta_xor(input_path: &Path, export_path: &Path, key: u8) {
    let unencrypted = include_bytes!(input_path);
    let encrypted_content = xor_encode(&unencrypted, key);
    let result = match write_to_file(&encrypted_content, export_path) {
        Ok(()) => _,
        Err(err) => panic!("{:?}", err),
    };

}