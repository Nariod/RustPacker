// Module that handles the CLI arguments and checks them for correct values.

use clap::{Arg, ArgMatches, Command, PossibleValue};
use std::path::{PathBuf};
//use std::process::Output;
use std::str::FromStr;

#[derive(Debug)]
pub struct Order {
    shellcode_path: PathBuf,
    pub execution: Execution,
    encryption: Option<Encryption>,
    sandbox: Option<bool>,
    output: Option<String>,
}

#[derive(Debug)]
pub enum Execution {
    //CreateRemoteThread(String),
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
                ]),
        )
        .arg(
            Arg::with_name("Sandbox checks")
                .short('s')
        )
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
    //dbg!(args.clone());
    let sp: String = String::from_str(args.value_of("Path to shellcode file").unwrap())?;
    let shellcode_path: PathBuf = [sp].iter().collect();
    let execution: Execution;
    let encryption: Option<Encryption> = None;
    let sandbox: Option<bool> = None;
    let output: Option<String> = None;

    let s = String::from_str(args.value_of("Execution technique").unwrap())?;
    match s.as_str() {
        "ct" => execution = Execution::CreateThread,
        _ => panic!("Don't even know how this error exists."),
    }

    //let e = String::from_str(args.value_of("Encryption / encoding method").unwrap())?;

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
    let order:Order;
    let args = parser();
    match args_checker(args) {
        Ok(content) => order = content,
        Err(err) => panic!("{:?}", err),
    } 
    println!("[+] Done parsing arguments!");
    return order;
}