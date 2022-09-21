// file that handle the target Rust code puzzle :)

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


pub fn meta_puzzle() {
    println!("meta_puzzle TBD");
}