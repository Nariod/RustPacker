use std::path::Path;

pub fn read_shellcode(file_path: &Path) -> Vec<u8> {
    println!("[+] Reading binary file..");
    match std::fs::read(file_path) {
        Ok(bytes) => {
            println!("[+] Done reading binary file!");
            bytes
        }
        Err(err) => panic!("Failed to read shellcode file {:?}: {}", file_path, err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_shellcode_content() {
        let dir = std::env::temp_dir().join("rustpacker_test_reader");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.bin");
        let content: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        fs::write(&path, &content).unwrap();

        let result = read_shellcode(&path);
        assert_eq!(result, content);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_shellcode_empty() {
        let dir = std::env::temp_dir().join("rustpacker_test_reader_empty");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.bin");
        fs::write(&path, &[]).unwrap();

        let result = read_shellcode(&path);
        assert!(result.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }
}
