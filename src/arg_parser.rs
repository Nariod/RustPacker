use clap::{Arg, ArgMatches, Command};
use std::fmt;
use std::path::PathBuf;

use crate::tools::absolute_path;

#[derive(Debug, Clone)]
pub struct Order {
    pub shellcode_path: PathBuf,
    pub execution: Execution,
    pub encryption: Encryption,
    pub format: Format,
    pub target_process: String,
    pub sandbox: Option<String>,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum Execution {
    SysCreateRemoteThread,
    NtCreateRemoteThread,
    NtQueueUserAPC,
    WinCreateRemoteThread,
    WinFiber,
    NtFiber,
    SysFiber,
    EarlyCascade,
}

impl fmt::Display for Execution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Execution::SysCreateRemoteThread => "sysCRT",
            Execution::NtCreateRemoteThread => "ntCRT",
            Execution::NtQueueUserAPC => "ntAPC",
            Execution::WinCreateRemoteThread => "winCRT",
            Execution::WinFiber => "winFIBER",
            Execution::NtFiber => "ntFIBER",
            Execution::SysFiber => "sysFIBER",
            Execution::EarlyCascade => "ntEarlyCascade",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone)]
pub enum Encryption {
    Xor,
    Aes,
    Uuid,
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Encryption::Xor => "xor",
            Encryption::Aes => "aes",
            Encryption::Uuid => "uuid",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone)]
pub enum Format {
    Exe,
    Dll,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Format::Exe => "exe",
            Format::Dll => "dll",
        };
        write!(f, "{}", s)
    }
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
                        .help("Create Remote Thread using indirect syscalls"),
                    clap::builder::PossibleValue::new("wincrt")
                        .help("Create Remote Thread using the official Windows Crate"),
                    clap::builder::PossibleValue::new("winfiber")
                        .help("Self execute using Fibers and the official Windows Crate"),
                    clap::builder::PossibleValue::new("ntfiber")
                        .help("Self execute using Fibers and low level APIs"),
                    clap::builder::PossibleValue::new("sysfiber")
                        .help("Self execute using Fibers and indirect syscalls"),
                    clap::builder::PossibleValue::new("earlycascade")
                        .help("EarlyCascade injection via shim engine callback hijacking"),
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
                    clap::builder::PossibleValue::new("uuid").help("UUID-based shellcode encoding"),
                ]),
        )
        .arg(
            Arg::new("Output path")
                .short('o')
                .required(false)
                .help("Optional output path for the resulting binary"),
        )
        .arg(
            Arg::new("Sandbox Check")
                .short('s')
                .required(false)
                .help("Sandbox check. Domain Pinning to the provided domain name"),
        )
        .get_matches()
}

fn args_checker(args: ArgMatches) -> Order {
    let sp: String = args
        .get_one::<String>("Path to shellcode file")
        .unwrap()
        .clone();
    let shellcode_path = absolute_path(PathBuf::from(sp)).expect("Invalid shellcode path");

    let encryption: Encryption = match args
        .get_one::<String>("Encryption / encoding method")
        .unwrap()
        .as_str()
    {
        "xor" => Encryption::Xor,
        "aes" => Encryption::Aes,
        "uuid" => Encryption::Uuid,
        _ => unreachable!("clap validates encryption values"),
    };

    let sandbox: Option<String> = args
        .get_one::<String>("Sandbox Check")
        .map(|s| s.to_string());

    let execution: Execution = match args
        .get_one::<String>("Execution technique")
        .unwrap()
        .as_str()
    {
        "ntapc" => Execution::NtQueueUserAPC,
        "ntcrt" => Execution::NtCreateRemoteThread,
        "syscrt" => Execution::SysCreateRemoteThread,
        "wincrt" => Execution::WinCreateRemoteThread,
        "winfiber" => Execution::WinFiber,
        "ntfiber" => Execution::NtFiber,
        "sysfiber" => Execution::SysFiber,
        "earlycascade" => Execution::EarlyCascade,
        _ => unreachable!("clap validates execution values"),
    };

    let format: Format = match args
        .get_one::<String>("Binary output format")
        .unwrap()
        .as_str()
    {
        "exe" => Format::Exe,
        "dll" => Format::Dll,
        _ => unreachable!("clap validates format values"),
    };

    let target_process = args
        .get_one::<String>("Target process")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "dllhost.exe".to_string());

    let output = args.get_one::<String>("Output path").map(|path| {
        absolute_path(PathBuf::from(path)).expect("Invalid output path")
    });

    Order {
        shellcode_path,
        execution,
        encryption,
        format,
        target_process,
        sandbox,
        output,
    }
}

pub fn parse_args() -> Order {
    let args = parser();
    args_checker(args)
}
