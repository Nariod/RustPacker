mod aes;
mod arg_parser;
mod compiler;
mod dll_proxy;
mod pe_parser;
mod puzzle;
mod shellcode_reader;
mod tools;
mod uuid_enc;
mod xor;
mod sandbox;

use std::io;

fn main() -> io::Result<()> {
    let order = arg_parser::parse_args();
    let output_folder_path = puzzle::assemble(order.clone());
    compiler::compile(&output_folder_path);

    tools::process_output(&order, &output_folder_path)?;
    tools::rename_source_binary(&order, &output_folder_path)?;

    Ok(())
}
