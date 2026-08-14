#!/bin/bash
# RustPacker All-in-One Container Entrypoint
#
# Sets up the cross-compilation environment and delegates to the RustPacker
# binary. Argument parsing, validation, alias conversion and help/version
# output are all handled by the binary itself (clap) - this script intentionally
# does not duplicate that logic.

set -e

# Environment variables for cross-compilation (mingw-w64 + Rust target)
export PATH="/usr/local/cargo/bin:/usr/local/rustup/shims:$PATH"
export CARGO_HOME=/usr/local/cargo
export RUSTUP_HOME=/usr/local/rustup
export CFLAGS_x86_64_pc_windows_gnu="-lrt"
export LDFLAGS_x86_64_pc_windows_gnu="-lrt"

# Templates and project files live in /app inside the container
cd /app

# Forward all arguments directly to the RustPacker binary
exec rustpacker "$@"
