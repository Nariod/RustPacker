// Module building the end-result Rust code
use std::str;
use std::path::Path;
use crate::arg_parser::{Order, Execution};
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{PathBuf};
use random_string::generate;

fn search_and_replace(path_to_main: &Path, search: &str, replace: &str) -> Result<(), Box<dyn std::error::Error>> {
    // thanks to https://users.rust-lang.org/t/replacing-content-in-file/52690/5
    let file_content = fs::read_to_string(path_to_main)?;
    let new_content = file_content.replace(search, &replace);

    let mut file = OpenOptions::new().write(true).truncate(true).open(path_to_main)?;
    file.write(new_content.as_bytes())?;

    Ok(())
}

fn create_folder() -> Result<String, Box<dyn std::error::Error>> {
    let charset = "abcdefghijklmnopqrstuvwxyz";
    let random = generate(12, charset);
    println!("[+] Creating output folder: {}", &random);
    fs::create_dir(&random)?;

    Ok(random)
}

pub fn meta_puzzle(order: Order, shellcode: Vec<u8>) -> PathBuf {
    println!("[+] Assembling Rust code..");

    let path_to_main;
    match order.execution {
        Execution::CreateThread => path_to_main = Path::new("templates/createThread/src/main.rs"),
    }
    let search = "{{shellcode}}";
    let replace: String = format!("{:?}", &shellcode);

    let folder: String;
    match create_folder() {
        Ok(content) => folder = content,
        Err(err) => panic!("{:?}", err),
    }

    let _ = search_and_replace(path_to_main, search, &replace);
    println!("[+] Done assembling Rust code!");
    return Path::new(&folder).to_path_buf();
}