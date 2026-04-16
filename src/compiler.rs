use std::env::set_current_dir;
use std::path::Path;
use std::process::Command;

fn run_compiler(path_to_cargo_folder: &Path) -> Result<(), Box<dyn std::error::Error>> {
    set_current_dir(path_to_cargo_folder)?;
    let output = Command::new("cargo")
        .env("CFLAGS", "-lrt")
        .env("LDFLAGS", "-lrt")
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .arg("build")
        .arg("--release")
        .args(["--target", "x86_64-pc-windows-gnu"])
        .output()?;

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        eprintln!("{}", error_message);
        return Err(format!("Compilation failed with status: {}", output.status).into());
    }

    if !output.stderr.is_empty() {
        let warnings = String::from_utf8_lossy(&output.stderr);
        println!("{}", warnings);
    }

    Ok(())
}

pub fn compile(path_to_cargo_folder: &Path) {
    println!("[+] Starting to compile your malware..");
    run_compiler(path_to_cargo_folder).unwrap_or_else(|err| {
        panic!("Compilation failed: {:?}", err);
    });
    println!("[+] Successfully compiled! Rust code and compiled binary are in the 'shared' folder");
}
