use crate::{shellcode_reader::meta_vec_from_file, tools::write_to_file};
use std::{collections::HashMap, path::Path};

fn bytes_to_uuid(chunk: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        chunk[0], chunk[1], chunk[2], chunk[3],
        chunk[4], chunk[5],
        chunk[6], chunk[7],
        chunk[8], chunk[9],
        chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15]
    )
}

fn uuid_encode(shellcode: &[u8]) -> String {
    let mut padded = shellcode.to_vec();
    let remainder = padded.len() % 16;
    if remainder != 0 {
        padded.resize(padded.len() + (16 - remainder), 0);
    }

    padded
        .chunks_exact(16)
        .map(|chunk| {
            let arr: [u8; 16] = chunk.try_into().unwrap();
            bytes_to_uuid(&arr)
        })
        .collect::<Vec<String>>()
        .join("\n")
}

pub fn meta_uuid(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    println!("[+] UUID encoding shellcode..");
    let unencrypted = meta_vec_from_file(input_path);
    let original_len = unencrypted.len();
    let encoded = uuid_encode(&unencrypted);
    match write_to_file(encoded.as_bytes(), export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }

    let mut result: HashMap<String, String> = HashMap::new();

    let decryption_function = "fn hex_to_byte(h: u8, l: u8) -> u8 {
        fn val(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => 0,
            }
        }
        (val(h) << 4) | val(l)
    }
    fn uuid_decode(buf: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut i = 0;
        while i < buf.len() {
            if buf[i] == b'-' || buf[i] == b'\\n' || buf[i] == b'\\r' {
                i += 1;
                continue;
            }
            if i + 1 < buf.len() {
                result.push(hex_to_byte(buf[i], buf[i + 1]));
                i += 2;
            } else {
                break;
            }
        }
        result
    }"
    .to_string();

    let main = format!("vec = uuid_decode(&vec);\n    vec.truncate({});", original_len);

    result.insert(String::from("decryption_function"), decryption_function);
    result.insert(String::from("main"), main);

    println!("[+] Done UUID encoding shellcode!");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_uuid_format() {
        let chunk: [u8; 16] = [0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00,
                                0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51];
        let uuid = bytes_to_uuid(&chunk);
        assert_eq!(uuid, "fc4883e4-f0e8-c000-0000-415141505251");
    }

    #[test]
    fn test_uuid_encode_exact_16_bytes() {
        let input: Vec<u8> = (0..16).collect();
        let encoded = uuid_encode(&input);
        assert_eq!(encoded.lines().count(), 1);
    }

    #[test]
    fn test_uuid_encode_pads_to_16() {
        let input: Vec<u8> = vec![0xfc, 0x48, 0x83];
        let encoded = uuid_encode(&input);
        assert_eq!(encoded.lines().count(), 1);
        assert!(encoded.contains("fc4883"));
    }

    #[test]
    fn test_uuid_encode_multiple_chunks() {
        let input: Vec<u8> = (0..32).collect();
        let encoded = uuid_encode(&input);
        assert_eq!(encoded.lines().count(), 2);
    }

    #[test]
    fn test_uuid_roundtrip() {
        let original: Vec<u8> = vec![
            0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00,
            0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
            0x56, 0x48, 0x31, 0xd2, 0x65,
        ];
        let encoded = uuid_encode(&original);
        let encoded_bytes = encoded.as_bytes();

        // Simulate the runtime decode logic
        fn hex_to_byte(h: u8, l: u8) -> u8 {
            fn val(c: u8) -> u8 {
                match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => 0,
                }
            }
            (val(h) << 4) | val(l)
        }
        fn uuid_decode(buf: &[u8]) -> Vec<u8> {
            let mut result = Vec::new();
            let mut i = 0;
            while i < buf.len() {
                if buf[i] == b'-' || buf[i] == b'\n' || buf[i] == b'\r' {
                    i += 1;
                    continue;
                }
                if i + 1 < buf.len() {
                    result.push(hex_to_byte(buf[i], buf[i + 1]));
                    i += 2;
                } else {
                    break;
                }
            }
            result
        }

        let mut decoded = uuid_decode(encoded_bytes);
        decoded.truncate(original.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_uuid_roundtrip_empty() {
        let original: Vec<u8> = vec![];
        let encoded = uuid_encode(&original);
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_uuid_roundtrip_exact_boundary() {
        let original: Vec<u8> = (0..48).collect();
        let encoded = uuid_encode(&original);
        assert_eq!(encoded.lines().count(), 3);
    }
}
