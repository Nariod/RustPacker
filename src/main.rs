// The main module only calls the meta functions in each of the needed modules. Must be simple to read and very short.

mod arg_parser;
mod compiler;
mod puzzle;
mod shellcode_reader;
mod tools;

fn main() {
    let order = arg_parser::meta_arg_parser();
    //let shellcode = shellcode_reader::meta_vec_from_file(&order.shellcode_path);
    let mut output_folder = puzzle::meta_puzzle(order);
    compiler::meta_compiler(&mut output_folder);
}
