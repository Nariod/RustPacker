use std::env::set_current_dir;
use std::path::PathBuf;
use std::process::Command;

fn compiler(path_to_cargo_project: &mut PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let path_to_cargo_folder = path_to_cargo_project.clone();
    path_to_cargo_project.push("Cargo.toml");
    set_current_dir(path_to_cargo_folder)?;
    let output = Command::new("cargo")
        .env("CFLAGS", "-lrt")
        .env("LDFLAGS", "-lrt")
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .arg("build")
        .arg("--release")
        .args(["--target", "x86_64-pc-windows-gnu"])
        .output()?;

    if !output.stderr.is_empty() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        println!("{}", error_message);
        //Err(error_message)?
    }
    Ok(())
}

pub fn meta_compiler(path_to_cargo_project: &mut PathBuf) {
    println!("[+] Starting to compile your malware..");
    let res = compiler(path_to_cargo_project);
    match res {
        Ok(()) => {
            println!("[+] Successfully compiled! Rust code and compiled binary are in the 'shared' folder");
        }
        Err(err) => panic!("{:?}", err),
    }
}
