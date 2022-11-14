// Module building the end-result Rust code
use crate::arg_parser::{Encryption, Execution, Order};
use crate::tools::{absolute_path, random_u8, path_to_string};
use crate::xor::meta_xor;
use fs_extra::dir::{copy, CopyOptions};
use random_string::generate;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::str;

fn search_and_replace(
    path_to_main: &Path,
    search: &str,
    replace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // thanks to https://users.rust-lang.org/t/replacing-content-in-file/52690/5
    let file_content = fs::read_to_string(path_to_main)?;
    let new_content = file_content.replace(search, replace);

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path_to_main)?;
    file.write_all(new_content.as_bytes())?;

    Ok(())
}

fn create_root_folder(general_output_folder: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let charset = "abcdefghijklmnopqrstuvwxyz";
    let random = generate(12, charset);
    let prefix = "output_";
    let result = [prefix, &random].join("");
    println!("[+] Creating output folder: {}", &result);
    let mut result_path = general_output_folder.to_path_buf();
    result_path.push(result);
    fs::create_dir(&result_path)?;

    Ok(result_path)
}

fn copy_template(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let options = CopyOptions {
        content_only: true,
        ..Default::default()
    };
    copy(source, dest, &options)?;

    Ok(())
}

pub fn meta_puzzle(order: Order) -> PathBuf {
    println!("[+] Assembling Rust code..");
    //dbg!("{}", &order.encryption);
    let mut general_output_folder = PathBuf::new();
    general_output_folder.push("shared");

    let path_to_template = match order.execution {
        Execution::CreateThread => Path::new("templates/createThread/."),
        Execution::CreateRemoteThread => Path::new("templates/createRemoteThread/."),
        Execution::SysCreateRemoteThread => Path::new("templates/sysCRT/.")
    };

    let folder: PathBuf = match create_root_folder(&general_output_folder) {
        Ok(content) => content,
        Err(err) => panic!("{:?}", err),
    };
    match copy_template(path_to_template, &folder) {
        Ok(_) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut to_main = folder.clone();
    to_main.push("src");
    to_main.push("main.rs");

    let absolute_shellcode_path = match absolute_path(&order.shellcode_path) {
        Ok(path) => path,
        Err(err) => panic!("{:?}", err),
    };

    let absolute_shellcode_path_as_string: String = path_to_string(&absolute_shellcode_path);

    let mut to_be_replaced = HashMap::new();
    to_be_replaced.insert("{{DEPENDENCIES}}", "");
    to_be_replaced.insert("{{IMPORTS}}", "");
    to_be_replaced.insert("{{DECRYPTION_FUNCTION}}", "");
    to_be_replaced.insert("{{MAIN}}", "");
    to_be_replaced.insert("{{PATH_TO_SHELLCODE}}", &absolute_shellcode_path_as_string);

    match order.encryption {
        Some(Encryption::Xor) => {
            let key = random_u8();
            let mut path_to_xor = to_main.clone();
            path_to_xor.pop();
            path_to_xor.push("input.xor");
            let absolute_path_to_xor = match absolute_path(&path_to_xor) {
                Ok(path) => path,
                Err(err) => panic!("{:?}", err),
            };
            let absolute_path_to_xor_as_string = path_to_string(&absolute_path_to_xor);

            let xor_args: HashMap<String, String> =
                meta_xor(&order.shellcode_path, &path_to_xor, key);
            let decryption_function = match xor_args.get("decryption_function") {
                Some(content) => content,
                None => panic!("I don't even know how this happened.."),
            };
            let main = match xor_args.get("main") {
                Some(content) => content,
                None => panic!("I don't even know how this happened.."),
            };
            to_be_replaced.insert("{{DECRYPTION_FUNCTION}}", decryption_function);
            to_be_replaced.insert("{{MAIN}}", main);
            to_be_replaced.insert("{{PATH_TO_SHELLCODE}}", &absolute_path_to_xor_as_string);

            for (key, value) in to_be_replaced.iter() {
                let _ = search_and_replace(&to_main, key, value);
            }
        }
        None => {
            for (key, value) in to_be_replaced.iter() {
                let _ = search_and_replace(&to_main, key, value);
            }
        }
    }
    println!("[+] Done assembling Rust code!");
    return Path::new(&folder).to_path_buf();
}
