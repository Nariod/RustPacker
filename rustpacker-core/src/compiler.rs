use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::utils::absolute_path;
use anyhow::{Context, Result};

const BUILDER_IMAGE: &str = "rustpacker";
const BUILD_TARGET: &str = "x86_64-pc-windows-gnu";
const DOCKERFILE: &str = "Dockerfile.all-in-one";

/// RUSTFLAGS applied when cross-compiling Windows payloads (container or local cargo).
/// Single source of truth for the `crt-static` flag.
const CRT_STATIC_RUSTFLAGS: &str = "-C target-feature=+crt-static";

fn is_running_in_container() -> bool {
    Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || env::var("CONTAINER").is_ok()
}

fn find_container_runtime() -> Option<&'static str> {
    ["podman", "docker"].into_iter().find(|cmd| {
        Command::new(cmd)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Check if the container image is available locally
fn is_image_available(runtime: &str) -> bool {
    Command::new(runtime)
        .args(["image", "inspect", BUILDER_IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build the all-in-one container image locally if it is not already present.
/// RustPacker is meant to be built and used locally; there is no prebuilt remote image.
fn ensure_image_available(runtime: &str) -> Result<()> {
    if is_image_available(runtime) {
        return Ok(());
    }

    println!(
        "[+] Building {} image (one-time, cached for next runs)...",
        BUILDER_IMAGE
    );
    let project_root = find_project_root()?;
    let dockerfile = project_root.join(DOCKERFILE);
    if !dockerfile.exists() {
        return Err(anyhow::anyhow!(
            "Dockerfile not found at {}. Build the image manually: {} build -t {} -f {} .",
            dockerfile.display(),
            runtime,
            BUILDER_IMAGE,
            DOCKERFILE
        ));
    }

    let output = Command::new(runtime)
        .args(["build", "-t", BUILDER_IMAGE, "-f", DOCKERFILE, "."])
        .current_dir(&project_root)
        .output()
        .context("Failed to spawn container build command")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Failed to build {}: {}",
            BUILDER_IMAGE,
            err
        ));
    }

    Ok(())
}

/// Locate the project root (the directory containing the Dockerfile and templates/).
/// Walks up from the current directory until it finds `Dockerfile.all-in-one`.
fn find_project_root() -> Result<PathBuf> {
    let mut dir = env::current_dir().context("Failed to determine current directory")?;
    loop {
        if dir.join(DOCKERFILE).exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(anyhow::anyhow!(
                "Could not find {} in the current directory or any parent directory.",
                DOCKERFILE
            ));
        }
    }
}

fn compile_in_container(runtime: &str, path_to_cargo_folder: &Path) -> Result<()> {
    ensure_image_available(runtime)?;

    let abs_path = absolute_path(path_to_cargo_folder)
        .context("Failed to resolve absolute path for cargo folder")?;

    // Use the all-in-one container image
    let output = Command::new(runtime)
        .args(["run", "--rm"])
        .args(["-v", &format!("{}:/workdir:z", abs_path.display())])
        .args(["-e", "CFLAGS_x86_64_pc_windows_gnu=-lrt"])
        .args(["-e", "LDFLAGS_x86_64_pc_windows_gnu=-lrt"])
        .args(["-e", &format!("RUSTFLAGS={}", CRT_STATIC_RUSTFLAGS)])
        .arg(BUILDER_IMAGE)
        .output()
        .context("Failed to spawn container run command")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", err);
        return Err(anyhow::anyhow!(
            "Container compilation failed: {}",
            output.status
        ));
    }

    if !output.stderr.is_empty() {
        let warnings = String::from_utf8_lossy(&output.stderr);
        println!("{}", warnings);
    }

    Ok(())
}

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
    // If we're already in a container with Rust available, compile locally
    if is_running_in_container() && is_rust_available() {
        return compile_with_cargo(path_to_cargo_folder);
    }

    // If Rust is available locally, try to compile directly
    if is_rust_available() {
        println!("[+] Using local Rust for cross-compilation");
        return compile_with_cargo(path_to_cargo_folder);
    }

    // Otherwise, use container runtime for cross-compilation
    if let Some(runtime) = find_container_runtime() {
        println!("[+] Using {} for cross-compilation", runtime);
        return compile_in_container(runtime, path_to_cargo_folder);
    }

    // No compilation method available - force container usage
    Err(anyhow::anyhow!(
        "No container runtime (podman/docker) found. Please install Podman or Docker and ensure it's in your PATH."
    ))
}

/// Compile using cargo (for use inside containers or when Rust is available locally)
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
    println!("[+] Successfully compiled! Rust code and compiled binary are in the 'shared' folder");
    Ok(())
}
