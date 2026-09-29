use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};

const BUILD_TARGET: &str = "x86_64-pc-windows-gnu";

/// RUSTFLAGS applied when cross-compiling Windows payloads with cargo,
/// whether from the host or from inside the all-in-one container.
/// Single source of truth for the `crt-static` flag.
const CRT_STATIC_RUSTFLAGS: &str = "-C target-feature=+crt-static";

/// Check if Rust is available in the current environment
fn is_rust_available() -> bool {
    Command::new("rustc")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_compiler(path_to_cargo_folder: &Path) -> Result<()> {
    if is_rust_available() {
        println!("[+] Using local Rust for cross-compilation");
        return compile_with_cargo(path_to_cargo_folder);
    }

    Err(anyhow!(
        "No Rust toolchain available. Install Rust via https://rustup.rs and add the {} target.",
        BUILD_TARGET
    ))
}

/// Compile using cargo (on the host or inside the all-in-one container)
fn compile_with_cargo(path_to_cargo_folder: &Path) -> Result<()> {
    let target = BUILD_TARGET;
    let manifest = path_to_cargo_folder.join("Cargo.toml");

    let mut cmd = Command::new("cargo");

    // Set environment variables for cross-compilation
    cmd.env("CFLAGS_x86_64_pc_windows_gnu", "-lrt");
    cmd.env("LDFLAGS_x86_64_pc_windows_gnu", "-lrt");
    cmd.env("RUSTFLAGS", CRT_STATIC_RUSTFLAGS);

    if cfg!(not(target_os = "windows")) {
        cmd.env("CFLAGS", "-lrt");
        cmd.env("LDFLAGS", "-lrt");
    }

    let output = cmd
        .args(["build", "--release", "--manifest-path"])
        .arg(&manifest)
        .args(["--target", target])
        .output()
        .context("Failed to spawn cargo build command")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", err);
        return Err(anyhow::anyhow!("Compilation failed: {}", output.status));
    }

    if !output.stderr.is_empty() {
        let warnings = String::from_utf8_lossy(&output.stderr);
        println!("{}", warnings);
    }

    Ok(())
}

/// Compile the generated Rust code
///
/// # Arguments
/// * `path_to_cargo_folder` - Path to the folder containing Cargo.toml
pub fn compile(path_to_cargo_folder: &Path) -> Result<()> {
    println!("[+] Starting to compile your malware..");
    run_compiler(path_to_cargo_folder).context("Compilation failed")?;
    Ok(())
}
