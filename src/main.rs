#![allow(non_snake_case)]
// The main module only calls the meta functions in each of the needed modules. Must be simple to read and very short.
mod aes;
mod arg_parser;
mod compiler;
mod puzzle;
mod shellcode_reader;
mod tools;
mod xor;

use std::env;
use std::io;

fn main() -> io::Result<()> {
    // Save the current working directory
    let current_dir = env::current_dir()?;

    let order = arg_parser::meta_arg_parser();
    let output_folder_path = puzzle::meta_puzzle(order.clone()); // Clone order to avoid moving it
    compiler::meta_compiler(&mut output_folder_path.clone());

    // Change back to the original working directory
    env::set_current_dir(current_dir)?;

    // Create the folders if they do not exist for the output
    tools::process_output(&order, &output_folder_path)?;

    // Generate a random filename for the source binary
    tools::rename_source_binary(&order, &output_folder_path)?;

    Ok(())
}
