// Module embedding various useful functions

use path_clean::PathClean;
use rand::Rng;
use std::env;
use std::fs::File;
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
