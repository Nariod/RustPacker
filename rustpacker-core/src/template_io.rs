//! Filesystem operations for template generation.
//!
//! Handles creating the output folder, copying template directories, and
//! the low-level search-and-replace used to substitute placeholders.

use crate::config::Execution;
use anyhow::{Context, Result};
use fs_extra::dir::{copy, CopyOptions};
use rand::distr::Alphanumeric;
use rand::RngExt;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OUTPUT_DIR: &str = "shared";

/// Substitute every occurrence of `search` with `replace` in the file at `path`.
pub fn search_and_replace(path: &Path, search: &str, replace: &str) -> Result<()> {
    let content = fs::read_to_string(path).with_context(|| {
        format!(
            "Failed to read template file for replacement: {}",
            path.display()
        )
    })?;
    let new_content = content.replace(search, replace);
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| {
            format!(
                "Failed to open template file for writing: {}",
                path.display()
            )
        })?;
    file.write_all(new_content.as_bytes())
        .with_context(|| format!("Failed to write replaced template file: {}", path.display()))?;
    Ok(())
}

/// Create a timestamped output folder under `shared/`.
///
/// A random suffix is appended so that two folders created within the same
/// second never collide (the second `fs::create_dir` would otherwise fail
/// with "File exists").
pub fn create_output_folder() -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock before UNIX epoch")?
        .as_secs();
    let suffix: String = (0..6)
        .map(|_| rand::rng().sample(Alphanumeric) as char)
        .collect();
    let folder_name = format!("output_{}_{}", timestamp, suffix);
    println!("[+] Creating output folder: {}", folder_name);
    let path = Path::new(OUTPUT_DIR).join(folder_name);
    fs::create_dir(&path)
        .with_context(|| format!("Failed to create output folder: {}", path.display()))?;
    Ok(path)
}

/// Copy a template directory into the destination folder (content only).
pub fn copy_template(source: &Path, dest: &Path) -> Result<()> {
    let options = CopyOptions {
        content_only: true,
        ..Default::default()
    };
    copy(source, dest, &options).context("Failed to copy template directory")?;
    Ok(())
}

/// Resolve the on-disk path of a template from its execution method.
pub fn get_template_path(execution: &Execution) -> PathBuf {
    Path::new("templates").join(format!("{}/.", execution.template_name()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Execution;

    #[test]
    fn test_get_template_path() {
        let path = get_template_path(&Execution::NtCreateRemoteThread);
        assert!(path.to_string_lossy().contains("templates/ntCRT"));
    }
}
