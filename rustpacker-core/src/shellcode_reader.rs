//! Shellcode reader module
//!
//! This module provides functionality for reading shellcode from files.

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
    /// Input file failed shellcode sanity checks
    #[error("Invalid shellcode: {0}")]
    ValidationError(String),
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
/// Heuristic sanity checks on the input file, so that an obviously wrong
/// input (a PE binary, a text file, an empty file) fails with an
/// actionable message instead of producing a silently-broken payload.
fn validate_shellcode(buffer: &[u8]) -> Result<(), ShellcodeError> {
    if buffer.is_empty() {
        return Err(ShellcodeError::ValidationError(
            "Shellcode file is empty".to_string(),
        ));
    }
    if buffer.starts_with(b"MZ") {
        return Err(ShellcodeError::ValidationError(
            "Input looks like a PE executable (MZ magic), not raw shellcode. Generate raw-format shellcode (e.g. msfvenom -f raw)".to_string(),
        ));
    }
    let printable = buffer.iter().filter(|b| **b >= 0x20 && **b <= 0x7E).count();
    if printable * 10 > buffer.len() * 9 {
        return Err(ShellcodeError::ValidationError(
            "Input is mostly printable ASCII (over 90%), which is unusual for raw shellcode. Double-check the file format and encoding".to_string(),
        ));
    }
    Ok(())
}

pub fn read_shellcode(file_path: &Path) -> Result<Vec<u8>, ShellcodeError> {
    println!("[+] Reading binary file..");
    let buffer = read_payload(file_path)?;
    validate_shellcode(&buffer)?;
    println!("[+] Done reading binary file!");
    Ok(buffer)
}

/// Read a binary payload without shellcode sanity checks.
/// Internal use only: re-reads of already-encrypted intermediate files
/// (e.g. WAT wrapping) must not go through user-input validation.
pub fn read_payload(file_path: &Path) -> Result<Vec<u8>, ShellcodeError> {
    let mut file = File::open(file_path).map_err(ShellcodeError::OpenError)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(ShellcodeError::ReadError)?;
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
        let content = vec![0xDE, 0xAD, 0xBE, 0xEF];
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
        fs::write(&path, []).unwrap();
        assert!(matches!(
            read_shellcode(&path),
            Err(ShellcodeError::ValidationError(_))
        ));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_shellcode_rejects_pe_magic() {
        let dir = std::env::temp_dir().join("rustpacker_test_reader_pe");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.exe");
        fs::write(&path, [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00]).unwrap();
        let err = read_shellcode(&path).unwrap_err();
        assert!(err.to_string().contains("PE executable"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_shellcode_rejects_mostly_printable() {
        let dir = std::env::temp_dir().join("rustpacker_test_reader_text");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notes.txt");
        fs::write(&path, b"this is clearly a text file, not shellcode!").unwrap();
        assert!(matches!(
            read_shellcode(&path),
            Err(ShellcodeError::ValidationError(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_shellcode_nonexistent() {
        let path = std::path::Path::new("/nonexistent/path/test.bin");
        let result = read_shellcode(path);
        assert!(result.is_err());
    }
}
