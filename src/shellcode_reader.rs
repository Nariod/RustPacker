// Module that gets the content of a shellcode file, and returns its content in a Vec<u8>.
use std::path::Path;

fn vec_from_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    Ok(bytes)
}

pub fn meta_vec_from_file(file_path: &Path) -> Vec<u8> {
    println!("[+] Reading binary file..");
    let path_to_shellcode_file = Path::new(&file_path);
    let shellcode = vec_from_file(path_to_shellcode_file);

    match shellcode {
        Ok(bytes) => {
            println!("[+] Done reading binary file!");

            bytes
        }
        Err(err) => panic!("{:?}", err),
    }
}
