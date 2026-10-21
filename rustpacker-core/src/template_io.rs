//! Filesystem operations for template generation.
//!
//! Handles creating the output folder, copying template directories, and
//! the low-level search-and-replace used to substitute placeholders.

use crate::config::Execution;
use anyhow::{anyhow, Context, Result};
use fs_extra::dir::{copy, CopyOptions};
use rand::distr::Alphanumeric;
use rand::RngExt;
use std::fs::{self, OpenOptions};
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OUTPUT_DIR: &str = "shared";
pub const TEMPLATES_DIR: &str = "templates";

/// Locate the project root: the directory holding `templates/`, so that
/// RustPacker can be invoked from anywhere inside the project.
pub fn find_project_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir().context("Failed to determine current directory")?;
    loop {
        if dir.join(TEMPLATES_DIR).is_dir() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(anyhow!(
                "Templates directory not found. Run RustPacker from the project root (the directory containing '{}').",
                TEMPLATES_DIR
            ));
        }
    }
}

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
    let path = find_project_root()?.join(OUTPUT_DIR).join(folder_name);
    fs::create_dir(&path)
        .with_context(|| format!("Failed to create output folder: {}", path.display()))?;
    Ok(path)
}

/// Remove every generated folder under shared/.
pub fn clean_output_folders() -> Result<()> {
    let shared_dir = find_project_root()?.join(OUTPUT_DIR);
    if !shared_dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&shared_dir)
        .with_context(|| format!("Failed to list {}", shared_dir.display()))?
    {
        let entry = entry.context("Failed to read shared/ entry")?;
        if entry.file_name().to_string_lossy().starts_with("output_") {
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
                println!("[+] Removed {}", path.display());
            }
        }
    }
    Ok(())
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
pub fn get_template_path(execution: &Execution) -> Result<PathBuf> {
    let root = find_project_root()?;
    Ok(root
        .join(TEMPLATES_DIR)
        .join(format!("{}/.", execution.template_name())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Execution;

    #[test]
    fn test_get_template_path() {
        let result = get_template_path(&Execution::NtCreateRemoteThread);
        assert!(result.is_ok());
        assert!(result
            .unwrap()
            .to_string_lossy()
            .contains("templates/ntCRT"));
    }
}
