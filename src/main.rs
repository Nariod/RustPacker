mod arg_parser;
mod shellcode_reader;

fn main() {
    dbg!("Entering main function");
    arg_parser::meta_arg_parser();
    shellcode_reader::meta_shellcode_reader();
    dbg!("Exiting main function");
}
