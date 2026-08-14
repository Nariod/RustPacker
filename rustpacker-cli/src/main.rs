//! RustPacker CLI
//!
//! This is the command-line interface for RustPacker.

use rustpacker_core::{
    assemble, compile, config::parse_args, process_output, rename_source_binary,
};

fn main() -> anyhow::Result<()> {
    let order = parse_args()?;
    let output_folder_path = assemble(order.clone())?;
    compile(&output_folder_path)?;

    process_output(&order, &output_folder_path)?;
    rename_source_binary(&order, &output_folder_path)?;

    Ok(())
}
