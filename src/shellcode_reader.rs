use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

/// Error type for shellcode reading operations
#[derive(Error, Debug)]
pub enum ShellcodeError {
    /// Failed to open the shellcode file
    #[error("Failed to open shellcode file: {0}")]
    OpenError(std::io::Error),
    
    /// Failed to read the shellcode file
    #[error("Failed to read shellcode file: {0}")]
    ReadError(std::io::Error),
}

/// Read shellcode from a file
/// 
/// # Arguments
/// * `file_path` - Path to the shellcode file
/// 
/// # Returns
/// The shellcode bytes
/// 
/// # Errors
/// Returns a `ShellcodeError` if the file cannot be opened or read
pub fn read_shellcode(file_path: &Path) -> Result<Vec<u8>, ShellcodeError> {
    println!("[+] Reading binary file..");
    
    let mut file = File::open(file_path)
        .map_err(ShellcodeError::OpenError)?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(ShellcodeError::ReadError)?;
    
    println!("[+] Done reading binary file!");
    Ok(buffer)
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

        let result = read_shellcode(&path).unwrap();
        assert_eq!(result, content);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_shellcode_empty() {
        let dir = std::env::temp_dir().join("rustpacker_test_reader_empty");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.bin");
        fs::write(&path, &[]).unwrap();

        let result = read_shellcode(&path).unwrap();
        assert!(result.is_empty());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_shellcode_nonexistent() {
        let path = std::path::Path::new("/nonexistent/path/test.bin");
        let result = read_shellcode(path);
        assert!(result.is_err());
    }
}
