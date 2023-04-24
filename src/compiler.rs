use std::env::set_current_dir;
use std::path::PathBuf;
use std::process::Command;

fn compiler(path_to_cargo_project: &mut PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let path_to_cargo_folder = path_to_cargo_project.clone();
    path_to_cargo_project.push("Cargo.toml");
    set_current_dir(path_to_cargo_folder)?;
    let output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .output()?;

    println!("{:?}", output);

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
