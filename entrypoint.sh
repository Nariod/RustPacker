#!/bin/sh
# RustPacker All-in-One Container Entrypoint
# This script handles the container execution and provides a user-friendly interface

set -e

# Export environment variables for cross-compilation
export PATH="/usr/local/cargo/bin:/usr/local/rustup/shims:$PATH"
export CARGO_HOME=/usr/local/cargo
export RUSTUP_HOME=/usr/local/rustup
export CFLAGS_x86_64_pc_windows_gnu="-lrt"
export LDFLAGS_x86_64_pc_windows_gnu="-lrt"
export RUSTFLAGS="-C target-feature=+crt-static"

# Function to display help
show_help() {
    cat << EOF
RustPacker All-in-One Container v2.0.0
=======================================

Cross-compile Windows shellcode loaders from any platform using Podman or Docker.

USAGE:
  podman run --rm -v \$(pwd):/workdir ghcr.io/nariod/rustpacker:latest [OPTIONS]

EXAMPLES:
  # Generate EXE payload with XOR encryption
  podman run --rm -v \$(pwd):/workdir ghcr.io/nariod/rustpacker:latest \\
      --shellcode-path /workdir/shellcode.bin \\
      --format exe \\
      --execution nt-create-remote-thread \\
      --encryption xor \\
      --output /workdir/payload.exe

  # Generate DLL payload with AES encryption
  podman run --rm -v \$(pwd):/workdir ghcr.io/nariod/rustpacker:latest \\
      --shellcode-path /workdir/shellcode.bin \\
      --format dll \\
      --execution ntapc \\
      --encryption aes \\
      --output /workdir/payload.dll

  # With sandbox evasion (domain pinning)
  podman run --rm -v \$(pwd):/workdir ghcr.io/nariod/rustpacker:latest \\
      --shellcode-path /workdir/shellcode.bin \\
      --format exe \\
      --execution syscrt \\
      --encryption uuid \\
      --sandbox example.com \\
      --output /workdir/payload.exe

REQUIRED ARGUMENTS:
  -s, --shellcode-path FILE    Path to the raw shellcode file
  -b, --format FORMAT         Output format: exe or dll
  -i, --execution TEMPLATE    Execution/injection template
  -e, --encryption METHOD     Encryption method: xor, aes, uuid

OPTIONAL ARGUMENTS:
  -t, --target-process NAME   Target process for injection (default: dllhost.exe)
      --sandbox DOMAIN         Enable sandbox check with domain pinning
  -o, --output PATH          Output path for the generated binary
  -p, --proxy-dll PATH       Path to legitimate DLL for proxying (DLL format only)

AVAILABLE EXECUTION TEMPLATES:
  nt-create-remote-thread, ntcrt       - Create Remote Thread (low-level APIs)
  nt-queue-user-apc, ntapc            - Queue User APC (low-level APIs)
  sys-create-remote-thread, syscrt    - Create Remote Thread (indirect syscalls)
  win-create-remote-thread, wincrt    - Create Remote Thread (Windows API)
  win-fiber, winfiber                  - Fiber-based execution (Windows API)
  nt-fiber, ntfiber                    - Fiber-based execution (low-level APIs)
  sys-fiber, sysfiber                  - Fiber-based execution (indirect syscalls)
  early-cascade, earlycascade          - EarlyCascade injection via shim engine

AVAILABLE ENCRYPTION METHODS:
  xor     - XOR encoding
  aes     - AES 256 encryption
  uuid    - UUID-based shellcode encoding

AVAILABLE FORMATS:
  exe     - Windows executable
  dll     - Windows DLL

NOTES:
  - Shellcode files must be in raw binary format (.bin, .raw)
  - Output directory must be writable (use volume mounts)
  - For DLL proxying, use self-injection templates: ntapc, winfiber, ntfiber, sysfiber
  - Container must have access to the shellcode file path

ENVIRONMENT VARIABLES:
  RUSTPACKER_DEBUG=1    Enable debug output
  RUSTPACKER_QUIET=1    Suppress non-essential output

EOF
}

# Function to validate arguments
validate_args() {
    # Check if required arguments are provided
    if [ -z "$SHELLCODE_PATH" ] || [ -z "$FORMAT" ] || [ -z "$EXECUTION" ] || [ -z "$ENCRYPTION" ]; then
        echo "[-] Error: Missing required arguments"
        echo ""
        show_help
        exit 1
    fi

    # Check if shellcode file exists
    if [ ! -f "$SHELLCODE_PATH" ]; then
        echo "[-] Error: Shellcode file not found: $SHELLCODE_PATH"
        exit 1
    fi

    # Validate format
    case "$FORMAT" in
        exe|dll|EXE|DLL) ;;
        *) echo "[-] Error: Invalid format '$FORMAT'. Must be 'exe' or 'dll'"
           exit 1
           ;;
    esac

    # Validate execution template
    case "$EXECUTION" in
        nt-create-remote-thread|ntcrt|nt-queue-user-apc|ntapc|
        sys-create-remote-thread|syscrt|win-create-remote-thread|wincrt|
        win-fiber|winfiber|nt-fiber|ntfiber|sys-fiber|sysfiber|
        early-cascade|earlycascade) ;;
        *) echo "[-] Error: Invalid execution template '$EXECUTION'"
           exit 1
           ;;
    esac

    # Validate encryption method
    case "$ENCRYPTION" in
        xor|aes|uuid|XOR|AES|UUID) ;;
        *) echo "[-] Error: Invalid encryption method '$ENCRYPTION'. Must be 'xor', 'aes', or 'uuid'"
           exit 1
           ;;
    esac
}

# Function to convert template aliases
convert_execution() {
    case "$1" in
        ntcrt) echo "nt-create-remote-thread" ;;
        ntapc) echo "nt-queue-user-apc" ;;
        syscrt) echo "sys-create-remote-thread" ;;
        wincrt) echo "win-create-remote-thread" ;;
        winfiber) echo "win-fiber" ;;
        ntfiber) echo "nt-fiber" ;;
        sysfiber) echo "sys-fiber" ;;
        earlycascade) echo "early-cascade" ;;
        *) echo "$1" ;;
    esac
}

# Function to convert encryption aliases
convert_encryption() {
    case "$1" in
        XOR) echo "xor" ;;
        AES) echo "aes" ;;
        UUID) echo "uuid" ;;
        *) echo "$1" ;;
    esac
}

# Function to convert format aliases
convert_format() {
    case "$1" in
        EXE) echo "exe" ;;
        DLL) echo "dll" ;;
        *) echo "$1" ;;
    esac
}

# Parse command line arguments
SHELLCODE_PATH=""
FORMAT=""
EXECUTION=""
ENCRYPTION=""
TARGET_PROCESS="dllhost.exe"
SANDBOX=""
OUTPUT=""
PROXY_DLL=""

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--shellcode-path)
            SHELLCODE_PATH="$2"
            shift 2
            ;;
        -b|--format)
            FORMAT="$(convert_format $2)"
            shift 2
            ;;
        -i|--execution)
            EXECUTION="$(convert_execution $2)"
            shift 2
            ;;
        -e|--encryption)
            ENCRYPTION="$(convert_encryption $2)"
            shift 2
            ;;
        -t|--target-process)
            TARGET_PROCESS="$2"
            shift 2
            ;;
        --sandbox)
            SANDBOX="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -p|--proxy-dll)
            PROXY_DLL="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            echo "RustPacker v2.0.0 - All-in-One Container"
            exit 0
            ;;
        *)
            echo "[-] Error: Unknown argument '$1'"
            echo ""
            show_help
            exit 1
            ;;
    esac
done

# If no arguments, show help
if [ -z "$SHELLCODE_PATH" ]; then
    show_help
    exit 1
fi

# Validate arguments
validate_args

# Build the command for rustpacker
echo "[+] RustPacker All-in-One Container"
echo "[+] Starting payload generation..."
echo ""

# Convert back to clap-compatible format
EXECUTION_ARG="$EXECUTION"
ENCRYPTION_ARG="$ENCRYPTION"
FORMAT_ARG="$FORMAT"

# Build the command array
CMD_ARGS=()
CMD_ARGS+=("--shellcode-path" "$SHELLCODE_PATH")
CMD_ARGS+=("--format" "$FORMAT_ARG")
CMD_ARGS+=("--execution" "$EXECUTION_ARG")
CMD_ARGS+=("--encryption" "$ENCRYPTION_ARG")
CMD_ARGS+=("--target-process" "$TARGET_PROCESS")

# Add optional arguments
if [ -n "$SANDBOX" ]; then
    CMD_ARGS+=("--sandbox" "$SANDBOX")
fi

if [ -n "$OUTPUT" ]; then
    CMD_ARGS+=("--output" "$OUTPUT")
fi

if [ -n "$PROXY_DLL" ]; then
    CMD_ARGS+=("--proxy-dll" "$PROXY_DLL")
fi

# Debug output
if [ -n "$RUSTPACKER_DEBUG" ]; then
    echo "[DEBUG] Shellcode path: $SHELLCODE_PATH"
    echo "[DEBUG] Format: $FORMAT_ARG"
    echo "[DEBUG] Execution: $EXECUTION_ARG"
    echo "[DEBUG] Encryption: $ENCRYPTION_ARG"
    echo "[DEBUG] Target process: $TARGET_PROCESS"
    echo "[DEBUG] Sandbox: ${SANDBOX:-none}"
    echo "[DEBUG] Output: ${OUTPUT:-auto}"
    echo "[DEBUG] Proxy DLL: ${PROXY_DLL:-none}"
    echo ""
fi

# Execute rustpacker with the built command
echo "[+] Executing: rustpacker ${CMD_ARGS[*]}"
echo ""

# Change to /app directory where templates are located
cd /app

# Execute rustpacker
exec rustpacker "${CMD_ARGS[@]}"