use cargo::ops::compile;
use std::fs;
use std::path::PathBuf;
use cargo::ops::{CompileOptions};
use cargo::core::{compiler::CompileMode, Workspace};
use cargo::util::interning::InternedString;
use cargo::Config;
use path_absolutize::*;

fn compiler(path_to_cargo_project: &mut PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    path_to_cargo_project.push("Cargo.toml");
    dbg!(path_to_cargo_project.clone());
    let absolute_toml_path = path_to_cargo_project.absolutize()?;
    let config: Config = Config::default()?;
    let ws = Workspace::new(&absolute_toml_path, &config)?;
    let mut compile_options: CompileOptions = CompileOptions::new(&config, CompileMode::Build)?;
    compile_options.build_config.requested_profile = InternedString::new("release");
    compile(&ws, &compile_options)?;

    Ok(())
}

pub fn meta_compiler(path_to_cargo_project: &mut PathBuf) {
    let res = compiler(path_to_cargo_project);
    match res {
        Ok(()) => println!("[+] Successfully compiled!"),
        Err(err) => panic!("{:?}", err),
    }
}