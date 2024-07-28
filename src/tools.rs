// Module embedding various useful functions

use crate::arg_parser;
use path_clean::PathClean;
use rand::Rng;
use std::env;
use std::fs::{self, File};
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

pub fn absolute_path(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    // thanks to https://stackoverflow.com/questions/30511331/getting-the-absolute-path-from-a-pathbuf
    let path = path.as_ref();

    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    }
    .clean();

    Ok(absolute_path)
}

pub fn write_to_file(content: &[u8], path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    file.write_all(content)?;

    Ok(())
}

pub fn path_to_string(input: &Path) -> String {
    format!("{:?}", &input)
}

pub fn random_u8() -> u8 {
    let random_number: u8 = rand::thread_rng().gen();
    random_number
}

pub fn random_aes_key() -> [u8; 32] {
    rand::thread_rng().gen::<[u8; 32]>()
}

pub fn random_aes_iv() -> [u8; 16] {
    rand::thread_rng().gen::<[u8; 16]>()
}

// Function to retrieve the source binary filename
pub fn get_source_binary_filename(order: &arg_parser::Order, output_folder: &Path) -> PathBuf {
    let source_binary_filename = format!(
        "target/x86_64-pc-windows-gnu/release/{}.{}",
        order.execution, order.format
    );
    let mut source_binary = output_folder.to_path_buf();
    source_binary.push(source_binary_filename);
    source_binary
}

// Function to process the output and manage folders
pub fn process_output(order: &arg_parser::Order, output_folder_path: &PathBuf) -> io::Result<()> {
    if let Some(output_path) = &order.output {
        let output_path = Path::new(output_path);
        if let Some(parent) = output_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
    }

    let is_file = fs::metadata(output_folder_path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);

    let output_folder = if is_file {
        output_folder_path
            .parent()
            .unwrap_or_else(|| {
                eprintln!("Error: Output path is a file but has no parent directory.");
                Path::new("")
            })
            .to_path_buf()
    } else {
        output_folder_path.clone()
    };

    let source_binary = get_source_binary_filename(order, &output_folder);

    if !source_binary.exists() {
        eprintln!("Source file does not exist: {:?}", source_binary);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Source file does not exist",
        ));
    }

    if let Some(output_path) = &order.output {
        let output_path = Path::new(output_path);

        if !source_binary.exists() || !source_binary.is_file() {
            eprintln!(
                "Source file does not exist or is not a file: {:?}",
                source_binary
            );
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Source file does not exist or is not a file",
            ));
        }

        if let Some(parent) = output_path.parent() {
            if !parent.exists() || !parent.is_dir() {
                eprintln!(
                    "Destination directory does not exist or is not a directory: {:?}",
                    parent
                );
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Destination directory does not exist or is not a directory",
                ));
            }
        }

        if let Err(e) = fs::copy(&source_binary, output_path) {
            eprintln!("Failed to copy the file: {:?}", e);
            return Err(e);
        }
        println!("[+] Your binary has been written here: {:?}", output_path);
    }

    Ok(())
}

// Function to generate a random filename with the given format
pub fn generate_random_filename(order: &arg_parser::Order) -> String {
    let mut rng = rand::thread_rng();
    let random_string: String = (0..8)
        .map(|_| rng.sample(rand::distributions::Alphanumeric))
        .map(char::from)
        .collect();
    format!("{}.{}", random_string, order.format)
}

// Function to rename the source binary to a random name
pub fn rename_source_binary(
    order: &arg_parser::Order,
    output_folder_path: &Path,
) -> io::Result<()> {
    let source_binary = get_source_binary_filename(order, output_folder_path);

    if !source_binary.exists() {
        eprintln!("Source file does not exist: {:?}", source_binary);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Source file does not exist",
        ));
    }

    let random_filename = generate_random_filename(order);
    let mut new_path = output_folder_path.to_path_buf();
    new_path.push("target/x86_64-pc-windows-gnu/release/");
    new_path.push(random_filename);

    // Ensure the target directory exists before renaming
    if !new_path.parent().unwrap().exists() {
        fs::create_dir_all(new_path.parent().unwrap())?;
    }

    fs::rename(&source_binary, &new_path)?;

    println!("[+] Source binary has been renamed to: {:?}", new_path);

    Ok(())
}
