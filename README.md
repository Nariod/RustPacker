# RustPacker
Shellcode packer written in Rust.

# Current state
WIP, not functional for now.

## Are you a Rust developer?
If you have some experience with Rust, you're more than welcome to help !
You can help by:
- Contributing to the project
- Reviewing the Rust code
- Opening issue to discuss Rust code
- Contacting me on Discord for a more in depth review (nariod#4621)

## Todo
- [X] Port createThread Rust template
- [X] Port CreateRemoteThread Rust template
- [X] Debug file to Vec<u8>
- [ ] Debug compiler
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

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
