// Module building the end-result Rust code


use std::path::Path;

fn string_reader_from_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}

pub fn meta_puzzle() {
    println!("meta_puzzle TBD");
    let path_to_main = Path::new("template/src/main.rs");
    match string_reader_from_file(path_to_main) {
        Ok(content) => println!("{}",content),
        Err(err) => panic!("{:?}", err),
    }
}