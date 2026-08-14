# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Added `clap::Parser` derive for cleaner argument parsing
- Added `thiserror` and `anyhow` dependencies for better error handling
- Added GitHub Actions workflows for CI/CD:
  - Test workflow: runs tests, clippy, and rustfmt on push/PR
  - Docker workflow: builds and pushes Docker images
- Added `clippy.toml` configuration for linting rules
- Added `rustfmt.toml` configuration for code formatting
- Improved error types in `shellcode_reader.rs` with `thiserror`
- Added comprehensive docstrings to public functions

### Changed
- Refactored `arg_parser.rs` to use `clap::Parser` derive macros
- Improved error handling in encryption modules (aes, xor, uuid_enc)
- Updated `Cargo.toml` with new dependencies and release profile optimizations
- Enhanced `shellcode_reader.rs` to use chunked reading for better memory management
- Improved code documentation across all modules

### Fixed
- Removed unused imports warnings
- Fixed potential memory issues with large shellcode files

---

## [2.0.0] - 2024-XX-XX

### Added
- Initial release of RustPacker 2.0
- Multiple injection templates (CRT, APC, Fibers, EarlyCascade)
- Encryption methods (XOR, AES-256, UUID encoding)
- Syscall evasion techniques
- EXE and DLL output formats
- Docker containerization support
- Domain pinning for sandbox evasion
- DLL proxying support
- Cross-platform support (Linux, Windows, macOS)

---

[Unreleased]: https://github.com/Nariod/RustPacker/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/Nariod/RustPacker/releases/tag/v2.0.0
