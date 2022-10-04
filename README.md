# RustPacker
Shellcode packer written in Rust.

# Current state
WIP, not functional for now.

## Todo
- [ ] Packer POC
- [ ] Add encryption / encoding
- [ ] Build dockerfile

## Setup
- install fedora environment
- sudo dnf groupinstall "Development Tools" "Development Libraries"
- sudo dnf install mingw64-winpthreads-static
- curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
- rustup target add x86_64-pc-windows-gnu

## Credits
- Rust discord
- StackOverflow

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
