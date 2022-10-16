// Module that gets the content of a shellcode file, and returns its content in a Vec<u8>.
use std::path::Path;
use std::path::PathBuf;

fn shellcode_reader_from_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    Ok(bytes)
}

pub fn meta_shellcode_reader(file_path: &PathBuf) -> Vec<u8> {
    println!("[+] Reading binary file..");
    let path_to_shellcode_file = Path::new(&file_path);
    let shellcode = shellcode_reader_from_file(path_to_shellcode_file);

    match shellcode {
        Ok(bytes) => {
            println!("[+] Done reading binary file!");

            bytes
        }
        Err(err) => panic!("{:?}", err),
    }
}
