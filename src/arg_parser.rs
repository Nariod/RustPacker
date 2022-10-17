// Module that handles the CLI arguments and checks them for correct values.

use clap::{Arg, ArgMatches, Command, PossibleValue};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug)]
pub struct Order {
    pub shellcode_path: PathBuf,
    pub execution: Execution,
    encryption: Option<Encryption>,
    sandbox: Option<bool>,
    output: Option<String>,
}

#[derive(Debug)]
pub enum Execution {
    CreateRemoteThread,
    CreateThread,
}

#[derive(Debug)]
pub enum Encryption {
    Xor,
    Aes,
}

fn parser() -> ArgMatches {
    let args = Command::new("RustPacker")
        .author("by Nariod")
        .version("0.1")
        .about("Shellcode packer written in Rust.")
        .arg_required_else_help(true)
        .arg(
            Arg::with_name("Path to shellcode file")
                .takes_value(true)
                .short('f')
                .required(true),
        )
        .arg(Arg::with_name("Output file").takes_value(true).short('o'))
        .arg(
            Arg::with_name("Execution technique")
                .takes_value(true)
                .short('i')
                .required(true)
                .value_parser([
                    PossibleValue::new("ct").help("Create Thread"),
                    PossibleValue::new("crt").help("Create Remote Thread"),
                ]),
        )
        .arg(Arg::with_name("Sandbox checks").short('s'))
        .arg(
            Arg::with_name("Encryption / encoding method")
                .takes_value(true)
                .short('e')
                .value_parser([
                    PossibleValue::new("xor").help("'Exclusive or' encoding"),
                    PossibleValue::new("aes").help("AES encryption"),
                ]),
        )
        .get_matches();

    args
}

fn args_checker(args: ArgMatches) -> Result<Order, Box<dyn std::error::Error>> {
    let sp: String = String::from_str(args.value_of("Path to shellcode file").unwrap())?;
    let shellcode_path: PathBuf = [sp].iter().collect();
    let encryption: Option<Encryption> = None;
    let sandbox: Option<bool> = None;
    let output: Option<String> = None;

    let s = String::from_str(args.value_of("Execution technique").unwrap())?;
    let execution: Execution = match s.as_str() {
        "ct" => Execution::CreateThread,
        "crt" => Execution::CreateRemoteThread,
        _ => panic!("Don't even know how this error exists."),
    };

    let result = Order {
        shellcode_path,
        execution,
        encryption,
        sandbox,
        output,
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
