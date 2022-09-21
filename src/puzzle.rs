// file that handle the target Rust code puzzle :)
use std::path::Path;

struct Order {
    shellcode: Vec<u8>,
    execution: Execution,
    encryption: Option<Encryption>,
    sandbox: Option<bool>,
}

enum Execution {
    CreateRemoteThread,
    CreateThread,
}

enum Encryption {
    Xor,
    Aes,
}

fn string_reader_from_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}

pub fn meta_puzzle() {
    println!("meta_puzzle TBD");
    let path_to_main = Path::new("template/src/main.rs");
    match string_reader_from_file(path_to_main) {
        Ok(content) => println!("{}",content),
        Err(err) => panic!("{:?}", err),
    }
}