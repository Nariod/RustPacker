//! RustPacker Core Library
//!
//! This is the core library for RustPacker, providing all the functionality
//! for generating shellcode loaders with various injection techniques and encryption methods.

pub mod compiler;
pub mod config;
pub mod dll_proxy;
pub mod encryption;
pub mod generator;
pub mod obfuscation;
pub mod pe_parser;
pub mod sandbox;
pub mod shellcode_reader;
pub mod utils;

// Re-export the most important types and functions for convenience
pub use compiler::compile;
pub use config::{Encryption, Execution, Format, Order, parse_args};
pub use generator::assemble;
pub use obfuscation::{obfuscate_string_for_template, obfuscate_api_name, non_zero_random_key};
pub use utils::{process_output, rename_source_binary};
