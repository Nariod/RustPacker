mod arg_parser;
mod shellcode_reader;
mod puzzle;

// main file is just to call the meta function in each of the needed module. Must be simple to read and very short.

fn main() {
    dbg!("Entering main function");

    let args = arg_parser::meta_arg_parser();
    let shellcode = shellcode_reader::meta_shellcode_reader();
    puzzle::meta_puzzle();

    dbg!("Exiting main function");
}