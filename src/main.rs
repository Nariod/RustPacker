// The main module only calls the meta functions in each of the needed modules. Must be simple to read and very short.

mod arg_parser;
mod shellcode_reader;
mod puzzle;


fn main() {
    println!("Entering main function");

    let order = arg_parser::meta_arg_parser();
    let shellcode = shellcode_reader::meta_shellcode_reader();
    puzzle::meta_puzzle(order, shellcode);

    println!("Exiting main function");
}