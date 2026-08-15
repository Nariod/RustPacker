//! Generator module for RustPacker
//!
//! Orchestrates the generation of Rust code for shellcode loaders.
//! The heavy lifting is split across companion modules:
//! - [`template_io`] for filesystem operations
//! - [`replacements`] for building the placeholder substitution map
//! - [`dll`] for DLL-specific generation logic

use crate::config::{Format, Order};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::dll::{apply_dll_format, apply_proxy_config, apply_replacements};
use crate::replacements::build_replacements;
use crate::template_io::{copy_template, create_output_folder, get_template_path};

/// Ensure no template placeholder remains in a generated file.
///
/// Called after every substitution step so that a malformed template (a
/// forgotten placeholder, a renamed variable) fails fast with a clear error
/// listing the offending lines, instead of surfacing as a cryptic
/// `cargo build` failure on the Windows target.
pub fn validate_no_placeholders(path: &Path) -> Result<()> {
    let content = fs::read_to_string(path).with_context(|| {
        format!(
            "Failed to read generated file for validation: {}",
            path.display()
        )
    })?;
    let leftovers: Vec<&str> = content
        .lines()
        .filter(|line| line.contains("{{") && line.contains("}}"))
        .collect();
    if leftovers.is_empty() {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "Unsubstituted template placeholders remain in {}:\n{}",
        path.display(),
        leftovers
            .iter()
            .map(|l| format!("  {}", l.trim()))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// Copy the shared `common.rs` helper into the generated project's `src/`.
///
/// Templates declare `mod common;` via the {{COMMON_MODULE}} placeholder;
/// this provides the implementation from a single source of truth
/// (`templates/common.rs`) instead of one copy per template.
fn copy_common_module(src_dir: &Path) -> Result<()> {
    let common_src = Path::new("templates").join("common.rs");
    fs::copy(&common_src, src_dir.join("common.rs")).with_context(|| {
        format!(
            "Failed to copy shared common.rs from {}",
            common_src.display()
        )
    })?;
    Ok(())
}

/// Generate Rust loader code from order configuration
pub fn assemble(order: Order) -> Result<PathBuf> {
    println!("[+] Assembling Rust code..");

    let template_path = get_template_path(&order.execution);
    let folder = create_output_folder()?;
    copy_template(&template_path, &folder)?;

    let src_dir = folder.join("src");
    copy_common_module(&src_dir)?;
    let main_rs = src_dir.join("main.rs");
    let cargo_toml = folder.join("Cargo.toml");

    let mut replacements = build_replacements(&order, &src_dir)?;

    let is_proxy = order.proxy_dll.is_some();
    let target_file = match order.format {
        Format::Dll => apply_dll_format(&mut replacements, &main_rs, is_proxy)?,
        Format::Exe => main_rs,
    };

    apply_replacements(&replacements, &target_file, &cargo_toml)?;

    if is_proxy {
        apply_proxy_config(&order, &folder)?;
    }

    // Fail fast if any template placeholder was not substituted: a leftover
    // {{...}} would otherwise produce a cryptic cargo build failure on the
    // Windows target that is hard for the end user to diagnose.
    validate_no_placeholders(&target_file)?;
    validate_no_placeholders(&cargo_toml)?;

    println!("[+] Done assembling Rust code!");
    Ok(folder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Encryption, Execution, Format, Order};
    use std::path::Path;

    /// All template × encryption × format combinations that assemble() must
    /// turn into a fully-substituted, compilable Rust project.
    ///
    /// This is the integration filet: a regression in the templating contract
    /// (a forgotten placeholder, a renamed template variable) would otherwise
    /// only surface as a cryptic `cargo build` failure on the Windows target
    /// at the very end of the pipeline.
    fn all_combinations() -> Vec<(Execution, Encryption, Format)> {
        let executions = [
            Execution::NtQueueUserAPC,
            Execution::NtCreateRemoteThread,
            Execution::SysCreateRemoteThread,
            Execution::WinCreateRemoteThread,
            Execution::WinFiber,
            Execution::NtFiber,
            Execution::SysFiber,
            Execution::EarlyCascade,
        ];
        let encryptions = [Encryption::Xor, Encryption::Aes, Encryption::Uuid];
        let formats = [Format::Exe, Format::Dll];

        let mut combos = Vec::new();
        for &e in &executions {
            for &enc in &encryptions {
                for &f in &formats {
                    combos.push((e, enc, f));
                }
            }
        }
        combos
    }

    /// Build an Order pointing at a shellcode file in `dir`.
    fn make_order(
        shellcode: &Path,
        execution: Execution,
        encryption: Encryption,
        format: Format,
    ) -> Order {
        Order {
            shellcode_path: shellcode.to_path_buf(),
            format,
            execution,
            encryption,
            target_process: "notepad.exe".to_string(),
            sandbox: None,
            output: None,
            proxy_dll: None,
        }
    }

    #[test]
    fn test_assemble_leaves_no_template_placeholders() {
        // assemble() resolves `templates/` relative to the CWD and writes to
        // `shared/` relative to the CWD. Isolate the test in a tempdir that
        // mirrors the project layout so it never touches the real repo.
        let dir = std::env::temp_dir().join("rustpacker_test_assemble_integration");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Copy the real templates/ so the contract tested matches production.
        // CWD during `cargo test` is the crate dir, so resolve the workspace
        // root from CARGO_MANIFEST_DIR (rustpacker-core -> parent is the root
        // that holds templates/).
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let templates_src = workspace_root.join("templates");
        let options = fs_extra::dir::CopyOptions {
            content_only: false,
            ..Default::default()
        };
        fs_extra::dir::copy(&templates_src, &dir, &options).unwrap();

        // assemble() writes generated projects under ./shared/ (relative to CWD).
        fs::create_dir_all(dir.join("shared")).unwrap();

        let shellcode = dir.join("shellcode.bin");
        fs::write(&shellcode, [0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8]).unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        for (execution, encryption, format) in all_combinations() {
            let order = make_order(&shellcode, execution, encryption, format);
            let folder = assemble(order).expect("assemble should succeed");

            let src_dir = folder.join("src");
            let source_file = if matches!(format, Format::Dll) {
                src_dir.join("lib.rs")
            } else {
                src_dir.join("main.rs")
            };
            let cargo_toml = folder.join("Cargo.toml");

            assert!(
                source_file.exists(),
                "source file missing for {execution}/{encryption}/{format}"
            );
            assert!(
                cargo_toml.exists(),
                "Cargo.toml missing for {execution}/{encryption}/{format}"
            );

            // assemble() now validates placeholders itself; double-check here
            // so a regression is attributed to this test rather than to a
            // later cargo build on the Windows target.
            validate_no_placeholders(&source_file).expect("leftover placeholders in source");
            validate_no_placeholders(&cargo_toml).expect("leftover placeholders in Cargo.toml");

            let enc_name = crate::replacements::get_encrypted_filename(&encryption);
            assert!(
                src_dir.join(enc_name).exists(),
                "encrypted payload missing for {execution}/{encryption}/{format}"
            );
        }

        std::env::set_current_dir(&original_dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_validate_no_placeholders_accepts_clean_file() {
        let dir = std::env::temp_dir().join("rustpacker_test_validate_clean");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("main.rs");
        fs::write(&path, "fn main() { println!(\"hi\"); }\n").unwrap();
        assert!(validate_no_placeholders(&path).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_validate_no_placeholders_rejects_leftover() {
        let dir = std::env::temp_dir().join("rustpacker_test_validate_leftover");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("main.rs");
        fs::write(&path, "fn main() { \n    {{MAIN}}\n}\n").unwrap();

        let err = validate_no_placeholders(&path).expect_err("should detect leftover");
        assert!(format!("{err:#}").contains("Unsubstituted template placeholders"));
        assert!(format!("{err:#}").contains("{{MAIN}}"));

        let _ = fs::remove_dir_all(&dir);
    }
}
