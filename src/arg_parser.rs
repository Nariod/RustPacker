use clap::{Arg, ArgMatches, Command, PossibleValue};

// File that handles the CLI arguments and checks them for correct values.

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
            Arg::with_name("Encryption / encoding method")
                .takes_value(true)
                .short('e')
                .required(true)
                .value_parser([
                    PossibleValue::new("xor").help("'Exclusive or' encoding"),
                    PossibleValue::new("aes").help("AES encryption"),
                ]),
        )
        .get_matches();

    args
}

pub fn meta_arg_parser() {
    let _args = parser();
}