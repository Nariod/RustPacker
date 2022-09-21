mod arg_parser;
mod shellcode_reader;
mod puzzle;

// main file is just to call the meta function is each of the needed module. Must be simple to read and very short.

fn main() {
    dbg!("Entering main function");

    arg_parser::meta_arg_parser();
    shellcode_reader::meta_shellcode_reader();
    puzzle::meta_puzzle();

    dbg!("Exiting main function");
}