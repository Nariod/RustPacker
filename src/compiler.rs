use std::env::set_current_dir;
use std::path::PathBuf;
use std::process::{Command, Output};

use crate::arg_parser::Order;

fn compiler(
    order: Order,
    path_to_cargo_project: &mut PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("{:#?}", &order);
    let path_to_cargo_folder = path_to_cargo_project.clone();
    path_to_cargo_project.push("Cargo.toml");
    set_current_dir(path_to_cargo_folder)?;
    // set the compile mode to "--release" or "" as debug is the default compile state
    let output: Output = match order.compile_mode {
        crate::arg_parser::CompileMode::Release => Command::new("cargo")
            .env("CFLAGS", "-lrt")
            .env("LDFLAGS", "-lrt")
            .env("RUSTFLAGS", "-C target-feature=+crt-static")
            .arg("build")
            .arg("--release")
            .output()?,
        crate::arg_parser::CompileMode::Debug => Command::new("cargo")
            .env("CFLAGS", "-lrt")
            .env("LDFLAGS", "-lrt")
            .env("RUSTFLAGS", "-C target-feature=+crt-static")
            .arg("build")
            .output()?,
    };

    if !output.stderr.is_empty() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        Err(error_message)?
    }
    Ok(())
}

pub fn meta_compiler(order: Order, path_to_cargo_project: &mut PathBuf) {
    println!("[+] Starting to compile your malware..");
    let res = compiler(order, path_to_cargo_project);
    match res {
        Ok(()) => {
            println!("[+] Successfully compiled! Rust code and compiled binary are in the 'shared' folder");
        }
        Err(err) => panic!("{:?}", err),
    }
}
