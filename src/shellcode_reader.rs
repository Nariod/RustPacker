use std::path::{Path};
pub struct ShellcodeReader;

impl ShellcodeReader {
    pub fn vec_from_file(file_path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(file_path)?;
        Ok(bytes)
    }

    pub fn meta_vec_from_file(file_path: &Path) -> Vec<u8> {
        println!("[+] Reading binary file..");
        let path_to_shellcode_file = Path::new(&file_path);
        let shellcode = ShellcodeReader::vec_from_file(path_to_shellcode_file);

        match shellcode {
            Ok(bytes) => {
                println!("[+] Done reading binary file!");
                bytes
            }
            Err(err) => panic!("{:?}", err),
        }
    }
}
