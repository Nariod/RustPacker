use cargo::core::{compiler::CompileMode, Workspace};
use cargo::ops::compile;
use cargo::ops::CompileOptions;
use cargo::util::interning::InternedString;
use cargo::Config;
use path_absolutize::*;
use std::env::current_dir;
use std::env::set_current_dir;
use std::path::PathBuf;

fn compiler(path_to_cargo_project: &mut PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    //thanks to https://github.com/rust-lang/cargo/issues/11245#issuecomment-1279994416
    let original_wd = current_dir()?;
    let path_to_cargo_folder = path_to_cargo_project.clone();
    path_to_cargo_project.push("Cargo.toml");
    let absolute_toml_path = path_to_cargo_project.absolutize()?;
    set_current_dir(path_to_cargo_folder)?; //needed to make sure cargo use the target .cargo/config file.. FFS
    let config: Config = Config::default()?;
    set_current_dir(original_wd)?; // set back to default working dir
    let ws = Workspace::new(&absolute_toml_path, &config)?;
    let mut compile_options: CompileOptions = CompileOptions::new(&config, CompileMode::Build)?;
    compile_options.build_config.requested_profile = InternedString::new("release");
    compile(&ws, &compile_options)?;

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
