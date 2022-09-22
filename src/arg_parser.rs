use clap::{Arg, ArgMatches, Command, PossibleValue};
use std::path::Path;
use std::str::FromStr;

// File that handles the CLI arguments and checks them for correct values.

pub struct Order {
    shellcode_path: Box<Path>,
    execution: Execution,
    encryption: Option<Encryption>,
    sandbox: Option<bool>,
    output: Option<String>,
}

pub enum Execution {
    CreateRemoteThread,
    CreateThread,
}

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
                    PossibleValue::new("crt").help("Create Remote Thread"),
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
    let shellcode_path = Path::new(String::from_str(args.value_of("Path to shellcode file").unwrap()));
    let execution = String::from_str(args.value_of("Execution technique").unwrap())?;
    let mut encryption;
    if args.value_of("Encryption / encoding method").unwrap()? == None {
        encryption = None;
    } else {
        encryption = Some(args.value_of("Encryption / encoding method").unwrap())?;
    }
    let mut sandbox;
    if args.value_of("Encryption / encoding method").unwrap()? == None {
        encryption = None;
    } else {
        encryption = Some(String::from_str(args.value_of("Encryption / encoding method").unwrap()))?;
    }

    let result = Order {
        shellcode_path: shellcode_path,
        execution: execution,
        encryption: encryption,
        sandbox: sandbox,
        output: output,
    };

    Ok(result)
}

pub fn meta_arg_parser() {
    let args = parser();
    args_checker(args);
}