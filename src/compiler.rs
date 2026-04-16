use std::path::Path;
use std::process::{Command, Stdio};
use std::{env, fs};

use crate::tools::absolute_path;

const BUILDER_IMAGE: &str = "rustpacker-builder";
const BUILDER_DOCKERFILE: &str = include_str!("../Dockerfile.builder");
const BUILD_TARGET: &str = "x86_64-pc-windows-gnu";

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

fn image_exists(runtime: &str) -> bool {
    Command::new(runtime)
        .args(["image", "inspect", BUILDER_IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn build_builder_image(runtime: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] Building {} image (first run only)...", BUILDER_IMAGE);

    let temp_dir = env::temp_dir().join("rustpacker-builder");
    fs::create_dir_all(&temp_dir)?;
    let dockerfile = temp_dir.join("Dockerfile");
    fs::write(&dockerfile, BUILDER_DOCKERFILE)?;

    let output = Command::new(runtime)
        .args(["build", "-t", BUILDER_IMAGE, "-f"])
        .arg(&dockerfile)
        .arg(&temp_dir)
        .output()?;

    fs::remove_dir_all(&temp_dir).ok();

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to build {}: {}", BUILDER_IMAGE, err).into());
    }

    Ok(())
}

fn ensure_builder_image(runtime: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !image_exists(runtime) {
        build_builder_image(runtime)?;
    }
    Ok(())
}

fn compile_in_container(
    runtime: &str,
    path_to_cargo_folder: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_builder_image(runtime)?;

    let abs_path = absolute_path(path_to_cargo_folder)?;
    let mount = format!("{}:/build:z", abs_path.display());
    let cache_mount = "rustpacker-cargo-cache:/usr/local/cargo/registry:z";

    let output = Command::new(runtime)
        .args(["run", "--rm"])
        .args(["-v", &mount])
        .args(["-v", cache_mount])
        .args(["-e", "CFLAGS=-lrt"])
        .args(["-e", "LDFLAGS=-lrt"])
        .args(["-e", "RUSTFLAGS=-C target-feature=+crt-static"])
        .arg(BUILDER_IMAGE)
        .args(["cargo", "build", "--release", "--target", BUILD_TARGET])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", err);
        return Err(format!("Container compilation failed: {}", output.status).into());
    }

    if !output.stderr.is_empty() {
        let warnings = String::from_utf8_lossy(&output.stderr);
        println!("{}", warnings);
    }

    Ok(())
}

fn local_build_target() -> &'static str {
    if cfg!(target_os = "windows") {
        "x86_64-pc-windows-msvc"
    } else {
        BUILD_TARGET
    }
}

fn compile_locally(path_to_cargo_folder: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let target = local_build_target();
    let manifest = path_to_cargo_folder.join("Cargo.toml");
    let mut cmd = Command::new("cargo");

    if cfg!(not(target_os = "windows")) {
        cmd.env("CFLAGS", "-lrt");
        cmd.env("LDFLAGS", "-lrt");
    }

    let output = cmd
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .args(["build", "--release", "--manifest-path"])
        .arg(&manifest)
        .args(["--target", target])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", err);
        return Err(format!("Compilation failed: {}", output.status).into());
    }

    if !output.stderr.is_empty() {
        let warnings = String::from_utf8_lossy(&output.stderr);
        println!("{}", warnings);
    }

    Ok(())
}

fn run_compiler(path_to_cargo_folder: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if is_running_in_container() {
        return compile_locally(path_to_cargo_folder);
    }

    if let Some(runtime) = find_container_runtime() {
        println!("[+] Using {} for cross-compilation", runtime);
        return compile_in_container(runtime, path_to_cargo_folder);
    }

    println!("[!] No container runtime found, falling back to local compilation");
    compile_locally(path_to_cargo_folder)
}

pub fn compile(path_to_cargo_folder: &Path) {
    println!("[+] Starting to compile your malware..");
    run_compiler(path_to_cargo_folder).unwrap_or_else(|err| {
        panic!("Compilation failed: {:?}", err);
    });
    println!("[+] Successfully compiled! Rust code and compiled binary are in the 'shared' folder");
}
