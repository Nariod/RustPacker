mod aes;
mod arg_parser;
mod compiler;
mod puzzle;
mod shellcode_reader;
mod tools;
mod uuid_enc;
mod xor;
mod sandbox;

use std::env;
use std::io;

fn main() -> io::Result<()> {
    let current_dir = env::current_dir()?;

    let order = arg_parser::parse_args();
    let output_folder_path = puzzle::assemble(order.clone());
    compiler::compile(&output_folder_path);

    env::set_current_dir(current_dir)?;

    tools::process_output(&order, &output_folder_path)?;
    tools::rename_source_binary(&order, &output_folder_path)?;

    Ok(())
}
