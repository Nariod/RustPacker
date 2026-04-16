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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_vec_from_file_reads_content() {
        let dir = std::env::temp_dir().join("rustpacker_test_reader");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.bin");
        let content: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        fs::write(&path, &content).unwrap();

        let result = vec_from_file(&path).unwrap();
        assert_eq!(result, content);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_vec_from_file_empty() {
        let dir = std::env::temp_dir().join("rustpacker_test_reader_empty");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.bin");
        fs::write(&path, &[]).unwrap();

        let result = vec_from_file(&path).unwrap();
        assert!(result.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_meta_vec_from_file_reads_content() {
        let dir = std::env::temp_dir().join("rustpacker_test_meta_reader");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.bin");
        let content: Vec<u8> = vec![0x41, 0x42, 0x43];
        fs::write(&path, &content).unwrap();

        let result = meta_vec_from_file(&path);
        assert_eq!(result, content);

        fs::remove_dir_all(&dir).unwrap();
    }
}
