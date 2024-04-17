// Module that handles the CLI arguments and checks them for correct values.

use clap::{Arg, ArgAction, ArgMatches, Command};
use std::{path::PathBuf, process::exit};

use crate::tools::absolute_path;

#[derive(Debug, Clone)]
pub struct Order {
    pub shellcode_path: PathBuf,
    pub execution: Execution,
    pub encryption: Encryption,
    pub format: Format,
    pub target_process: String,
    pub compile_mode: CompileMode,
    //sandbox: Option<bool>,
    //output: Option<String>,
}

#[derive(Debug, Clone)]
pub enum CompileMode {
    Release,
    Debug,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Execution {
    // CreateRemoteThread,
    // CreateThread,
    //NtCreateRemoteThread,
    //WinCreateRemoteThread,
    SysCreateRemoteThread,
    NtQueueUserAPC,
    Fiber,
}

#[derive(Debug, Clone)]
pub enum Encryption {
    Xor,
    Aes,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Format {
    Exe,
    Dll,
}

fn parser() -> ArgMatches {
    Command::new("RustPacker")
        .author("by Nariod")
        .version("2.0")
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
                        .help("Self inject using APC low level APIs. Compatible with both exe and dll formats."),
                    clap::builder::PossibleValue::new("fiber")
                        .help("Self inject using Fibers. Compatible with both exe and dll formats."),
                    clap::builder::PossibleValue::new("syscrt")
                        .help("Create Remote Thread using syscalls. Compatible with exe format only."),
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
        .arg(
            Arg::new("Debug mode")
                .short('d')
                .required(false)
                .num_args(0)
                .action(ArgAction::SetTrue)
                .help("Compile the malware in debug mode for analysis.")
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
        //"ntcrt" => Execution::NtCreateRemoteThread,
        "syscrt" => Execution::SysCreateRemoteThread,
        //"wincrt" => Execution::WinCreateRemoteThread,
        "fiber" => Execution::Fiber,
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

    let compile_mode = match args.get_one::<bool>("Debug mode") {
        Some(true) => {
            println!("[+] Compiling in debug mode, NOT OPSEC SAFE !");
            CompileMode::Debug
        }
        Some(false) => CompileMode::Release,
        None => panic!("Don't even know how this error is possible"),
    };

    let result = Order {
        shellcode_path,
        execution,
        encryption,
        format,
        target_process,
        compile_mode,
        //sandbox,
        //output,
    };

    if result.format == Format::Dll && result.execution != Execution::NtQueueUserAPC && result.execution != Execution::Fiber {
        println!("[-] DLL format is incompatible with remote injection techniques. Use the ntAPC or Fiber templates for DLL compatibility.");
        exit(0);
    }

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
