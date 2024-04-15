#![allow(non_snake_case)]
// The main module only calls the meta functions in each of the needed modules. Must be simple to read and very short.
mod aes;
mod arg_parser;
mod compiler;
mod puzzle;
mod shellcode_reader;
mod tools;
mod xor;

fn main() {
    let order = arg_parser::meta_arg_parser();
    let mut output_folder = puzzle::meta_puzzle(order.clone());
    compiler::meta_compiler(order, &mut output_folder);
}
