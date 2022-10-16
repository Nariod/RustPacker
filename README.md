# RustPacker
Shellcode packer written in Rust.

# Current state
Functional as it packs a binary file, but useless as I need to add evasion and encryption stuff.

# Quick start

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

## Are you a Rust developer?
If you have some experience with Rust, you're more than welcome to help !
You can help by:
- Review the code for mistakes / improvements
- Opening issues
- Contacting me on Discord for a more in depth review (nariod#4621)


## Todo
- [X] Port createThread Rust template
- [X] Port CreateRemoteThread Rust template
- [X] Debug file to Vec<u8>
- [X] Debug compiler -> Done, FFS !
- [ ] Packer POC
- [ ] Add encryption / encoding
- [ ] Build dockerfile
- [ ] Strip output binaries

## Setup
- install fedora environment
- sudo dnf groupinstall "Development Tools" "Development Libraries"
- sudo dnf install mingw64-winpthreads-static
- curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
- rustup target add x86_64-pc-windows-gnu

## Credits
- Rust discord
- StackOverflow
- https://github.com/postrequest/link

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
