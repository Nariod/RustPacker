use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::{Command, Stdio};

const BUILD_TARGET: &str = "x86_64-pc-windows-gnu";
const GNU_LINKER: &str = "x86_64-w64-mingw32-gcc";

/// RUSTFLAGS applied when cross-compiling Windows payloads with cargo,
/// whether from the host or from inside the all-in-one container.
/// Single source of truth for the `crt-static` flag.
const CRT_STATIC_RUSTFLAGS: &str = "-C target-feature=+crt-static";

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_rust_available() -> bool {
    command_succeeds("rustc", &["--version"])
}

fn is_target_installed() -> bool {
    let output = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).contains(BUILD_TARGET),
        _ => true,
    }
}

fn is_linker_available() -> bool {
    if cfg!(target_os = "windows") {
        return true;
    }
    command_succeeds(GNU_LINKER, &["--version"])
}

fn missing_toolchain_error() -> anyhow::Error {
    anyhow!(
        "Cross-compilation toolchain incomplete. Install the missing pieces:\n  \
         rustup target add {BUILD_TARGET}\n  \
         # plus a mingw-w64 linker, e.g. on Debian/Ubuntu: apt install mingw-w64\n  \
         (or use the all-in-one container, which ships a ready toolchain)"
    )
}

fn run_compiler(path_to_cargo_folder: &Path) -> Result<()> {
    if !is_rust_available() {
        return Err(anyhow!(
            "No Rust toolchain available. Install Rust via https://rustup.rs and add the {} target.",
            BUILD_TARGET
        ));
    }
    if !is_target_installed() || !is_linker_available() {
        return Err(missing_toolchain_error());
    }
    println!("[+] Using local Rust for cross-compilation");
    compile_with_cargo(path_to_cargo_folder)
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
        return Err(anyhow!("Compilation failed: {}", output.status));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_toolchain_error_mentions_target() {
        let msg = format!("{}", missing_toolchain_error());
        assert!(msg.contains(BUILD_TARGET));
        assert!(msg.contains("mingw"));
    }
}
