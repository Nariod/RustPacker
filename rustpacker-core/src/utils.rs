//! Utility functions for RustPacker
//!
//! This module contains various utility functions used throughout the application,
//! including file operations, path handling, and random generation.

use path_clean::PathClean;
use rand::distr::Alphanumeric;
use rand::RngExt;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Convert a path to an absolute path
///
/// # Arguments
/// * `path` - The path to convert
///
/// # Returns
/// The absolute path
pub fn absolute_path(path: impl AsRef<Path>) -> Result<PathBuf> {
    // thanks to https://stackoverflow.com/questions/30511331/getting-the-absolute-path-from-a-pathbuf
    let path = path.as_ref();

    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .context("Failed to determine current directory")?
            .join(path)
    }
    .clean();

    Ok(absolute_path)
}

/// Write content to a file
///
/// # Arguments
/// * `content` - The content to write
/// * `path` - The path to the file
///
/// # Returns
/// Result indicating success or failure
pub fn write_to_file(content: &[u8], path: &Path) -> Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("Failed to create file: {}", path.display()))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write to file: {}", path.display()))?;

    Ok(())
}

/// Generate a random u8 value
///
/// # Returns
/// A random u8 value
pub fn random_u8() -> u8 {
    rand::random()
}

/// Generate a random AES key (32 bytes)
///
/// # Returns
/// A random AES key
pub fn random_aes_key() -> [u8; 32] {
    rand::random::<[u8; 32]>()
}

/// Generate a random AES IV (16 bytes)
///
/// # Returns
/// A random AES IV
pub fn random_aes_iv() -> [u8; 16] {
    rand::random::<[u8; 16]>()
}

/// Generate a random filename
///
/// # Arguments
/// * `format` - The file format (exe or dll)
///
/// # Returns
/// A random filename with the given format
pub fn generate_random_filename(format: &str) -> String {
    let mut rng = rand::rng();
    let random_string: String = (0..8).map(|_| rng.sample(Alphanumeric) as char).collect();
    format!("{}.{}", random_string, format)
}

/// Get the source binary filename based on execution and format
///
/// # Arguments
/// * `execution` - The execution method
/// * `format` - The output format
/// * `output_folder` - The output folder path
///
/// # Returns
/// The path to the source binary
pub fn get_source_binary_filename(
    execution: &crate::config::Execution,
    format: &crate::config::Format,
    output_folder: &Path,
) -> PathBuf {
    let binary_name = format!("{}.{}", execution.template_name(), format);
    let target_dir = "target/x86_64-pc-windows-gnu/release";
    output_folder.join(target_dir).join(binary_name)
}

/// Process the output binary
///
/// # Arguments
/// * `order` - The configuration order
/// * `output_folder_path` - The output folder path
///
/// # Returns
/// Result indicating success or failure
pub fn process_output(order: &crate::config::Order, output_folder_path: &Path) -> Result<()> {
    let output_path = match &order.output {
        Some(p) => p,
        None => return Ok(()),
    };

    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create output directory: {}", parent.display())
            })?;
        }
    }

    let source_binary =
        get_source_binary_filename(&order.execution, &order.format, output_folder_path);

    if !source_binary.is_file() {
        return Err(anyhow::anyhow!(
            "Source file does not exist: {}",
            source_binary.display()
        ));
    }

    fs::copy(&source_binary, output_path).with_context(|| {
        format!(
            "Failed to copy source binary from {} to {}",
            source_binary.display(),
            output_path.display()
        )
    })?;
    println!("[+] Your binary has been written here: {:?}", output_path);

    Ok(())
}

/// Rename the source binary with a random filename
///
/// # Arguments
/// * `order` - The configuration order
/// * `output_folder_path` - The output folder path
///
/// # Returns
/// Result indicating success or failure
pub fn rename_source_binary(order: &crate::config::Order, output_folder_path: &Path) -> Result<()> {
    let source_binary =
        get_source_binary_filename(&order.execution, &order.format, output_folder_path);

    if !source_binary.exists() {
        return Err(anyhow::anyhow!(
            "Source file does not exist: {}",
            source_binary.display()
        ));
    }

    let random_filename = generate_random_filename(&order.format.to_string());
    let release_dir = source_binary
        .parent()
        .context("Source binary has no parent directory")?;
    let new_path = release_dir.join(random_filename);

    fs::rename(&source_binary, &new_path).with_context(|| {
        format!(
            "Failed to rename source binary from {} to {}",
            source_binary.display(),
            new_path.display()
        )
    })?;
    println!("[+] Source binary has been renamed to: {:?}", new_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Execution, Format};

    #[test]
    fn test_write_to_file_and_read_back() {
        let dir = std::env::temp_dir().join("rustpacker_test_utils_write");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_output.bin");
        let content: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE];

        write_to_file(&content, &path).unwrap();
        let read_back = fs::read(&path).unwrap();
        assert_eq!(read_back, content);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_absolute_path_already_absolute() {
        let path = if cfg!(windows) {
            Path::new("C:\\tmp\\test")
        } else {
            Path::new("/tmp/test")
        };
        let result = absolute_path(path).unwrap();
        assert!(result.is_absolute());
        assert_eq!(result, path);
    }

    #[test]
    fn test_absolute_path_relative() {
        let result = absolute_path("some_relative_path").unwrap();
        assert!(result.is_absolute());
        assert!(result.to_string_lossy().contains("some_relative_path"));
    }

    #[test]
    fn test_random_u8_returns_value() {
        let _val = random_u8();
    }

    #[test]
    fn test_random_aes_key_length() {
        let key = random_aes_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_random_aes_iv_length() {
        let iv = random_aes_iv();
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn test_generate_random_filename_format() {
        let filename = generate_random_filename("exe");
        assert!(filename.ends_with(".exe"));
        assert_eq!(filename.len(), 12); // 8 random chars + ".exe"
    }

    #[test]
    fn test_get_source_binary_filename() {
        let execution = Execution::NtCreateRemoteThread;
        let format = Format::Dll;
        let path = get_source_binary_filename(&execution, &format, Path::new("/output"));
        assert!(path.to_string_lossy().contains("ntCRT.dll"));
    }
}
