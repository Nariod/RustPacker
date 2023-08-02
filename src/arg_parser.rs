// Module that handles the CLI arguments and checks them for correct values.

use clap::{Arg, ArgMatches, Command, PossibleValue};
use std::path::PathBuf;
use std::str::FromStr;

use crate::tools::absolute_path;

#[derive(Debug)]
pub struct Order {
    pub shellcode_path: PathBuf,
    pub execution: Execution,
    pub encryption: Option<Encryption>,
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
    let args = Command::new("RustPacker")
        .author("by Nariod")
        .version("0.10")
        .about("Shellcode packer written in Rust.")
        .arg_required_else_help(true)
        .arg(
            Arg::with_name("Path to shellcode file")
                .takes_value(true)
                .short('f')
                .required(true),
        )
        .arg(
            Arg::with_name("Binary output format")
                .takes_value(true)
                .short('b')
                .required(true)
                .value_parser([
                    PossibleValue::new("exe").help("EXE format"),
                    PossibleValue::new("dll").help("DLL format"),
                ]),
        )
        .arg(
            Arg::with_name("Execution technique")
                .takes_value(true)
                .short('i')
                .required(true)
                .value_parser([
                    // PossibleValue::new("ct").help("Create Thread"),
                    // PossibleValue::new("crt").help("Create Remote Thread"),
                    PossibleValue::new("ntapc").help("Self inject using APC low level APIs"),
                    PossibleValue::new("ntcrt").help("Create Remote Thread using low level APIs"),
                    PossibleValue::new("syscrt").help("Create Remote Thread using syscalls"),
                    PossibleValue::new("wincrt")
                        .help("Create Remote Thread using the official Windows Crate"),
                ]),
        )
        .arg(
            Arg::with_name("Target process")
                .takes_value(true)
                .short('t')
                .help(
                    "Target processes to inject into, defaults to 'dllhost.exe'. Case sensitive!",
                ),
        )
        .arg(Arg::with_name("Sandbox checks").short('s'))
        .arg(
            Arg::with_name("Encryption / encoding method")
                .takes_value(true)
                .short('e')
                .required(true)
                .value_parser([
                    PossibleValue::new("xor").help("'Exclusive or' encoding"),
                    PossibleValue::new("aes").help("AES 256 encryption"),
                ]),
        )
        .get_matches();

    args
}

fn args_checker(args: ArgMatches) -> Result<Order, Box<dyn std::error::Error>> {
    let sp: String = String::from_str(args.value_of("Path to shellcode file").unwrap())?;
    let relative_shellcode_path: PathBuf = [sp].iter().collect();
    let shellcode_path = match absolute_path(relative_shellcode_path) {
        Ok(path) => path,
        Err(err) => panic!("{:?}", err),
    };

    let encryption = match args.value_of("Encryption / encoding method") {
        Some("xor") => Some(Encryption::Xor),
        Some("aes") => Some(Encryption::Aes),
        _ => panic!("Don't even know how this error exists."),
    };

    //let sandbox: Option<bool> = None;
    //let output: Option<String> = None;

    let s = String::from_str(args.value_of("Execution technique").unwrap())?;
    let execution: Execution = match s.as_str() {
        // "ct" => Execution::CreateThread,
        // "crt" => Execution::CreateRemoteThread,
        "ntapc" => Execution::NtQueueUserAPC,
        "ntcrt" => Execution::NtCreateRemoteThread,
        "syscrt" => Execution::SysCreateRemoteThread,
        "wincrt" => Execution::WinCreateRemoteThread,
        _ => panic!("Don't even know how this error exists."),
    };

    let s = String::from_str(args.value_of("Binary output format").unwrap())?;
    let format: Format = match s.as_str() {
        "exe" => Format::Exe,
        "dll" => Format::Dll,
        _ => panic!("Don't even know how this error exists."),
    };

    let target_process = match args.value_of("Target process") {
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
    println!("[+] Parsing arguments..");
    let args = parser();
    let order: Order = match args_checker(args) {
        Ok(content) => content,
        Err(err) => panic!("{:?}", err),
    };
    println!("[+] Done parsing arguments!");

    order
}
