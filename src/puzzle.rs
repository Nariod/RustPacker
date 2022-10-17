// Module building the end-result Rust code
use crate::arg_parser::{Execution, Order};
use fs_extra::dir::{copy, CopyOptions};
use random_string::generate;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::env::set_current_dir;
use std::env::current_dir;


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
    file.write(new_content.as_bytes())?;

    Ok(())
}

fn create_root_folder() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output_directory = String::from("shared");
    //let original_wd = current_dir()?;
    let charset = "abcdefghijklmnopqrstuvwxyz";
    let random = generate(12, charset);
    let prefix = "output_";
    let result = [prefix, &random].join("");
    println!("[+] Creating output folder: {}", &result);
    let mut target_dir = PathBuf::new();
    target_dir.push(output_directory);
    target_dir.push(result);
    //set_current_dir("shared")?;
    fs::create_dir(&target_dir)?;
    //set_current_dir(original_wd)?; // set back to default working dir

    Ok(target_dir)
}

fn copy_template(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let options = CopyOptions {
        content_only: true,
        ..Default::default()
    };
    copy(source, dest, &options)?;

    Ok(())
}

pub fn meta_puzzle(order: Order, shellcode: Vec<u8>) -> PathBuf {
    println!("[+] Assembling Rust code..");

    //let path_to_template;
    let path_to_template =  match order.execution {
        Execution::CreateThread => Path::new("templates/createThread/."),
        Execution::CreateRemoteThread => {
            Path::new("templates/createRemoteThread/.")
        }
    };
    let search = "{{shellcode}}";
    let replace: String = format!("{:?}", &shellcode);

    //let folder: String;
    let folder: PathBuf = match create_root_folder() {
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
    //dbg!(to_main.clone());
    let _ = search_and_replace(&to_main, search, &replace);
    println!("[+] Done assembling Rust code!");
    return Path::new(&folder).to_path_buf();
}
