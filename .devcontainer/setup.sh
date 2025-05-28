#!/bin/bash

set -e

echo "🦀 Setting up RustPacker development environment..."

# Update package lists
echo "📦 Updating package lists..."
sudo apt update

# Install essential dependencies for RustPacker
echo "🔧 Installing system dependencies..."
sudo apt install -y \
    libssl-dev \
    librust-openssl-dev \
    musl-tools \
    mingw-w64 \
    cmake \
    libxml2-dev \
    pkg-config \
    build-essential \
    curl \
    wget \
    git \
    vim \
    nano \
    htop \
    tree \
    unzip

# Install additional useful tools for pentesting/development
echo "🛠️  Installing additional development tools..."
sudo apt install -y \
    hexdump \
    xxd \
    binutils \
    file \
    strings \
    strace \
    ltrace \
    gdb \
    objdump \
    readelf

# Set up Rust environment
echo "🦀 Configuring Rust environment..."

# Add Windows target for cross-compilation
rustup target add x86_64-pc-windows-gnu

# Install useful Rust tools
echo "📦 Installing Rust development tools..."
cargo install cargo-edit
cargo install cargo-watch
cargo install cargo-expand
cargo install cargo-audit
cargo install cargo-outdated
cargo install cargo-tree

# Create .cargo/config.toml for cross-compilation settings
echo "⚙️  Setting up cross-compilation configuration..."
mkdir -p ~/.cargo
cat > ~/.cargo/config.toml << 'EOF'
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
ar = "x86_64-w64-mingw32-ar"

[build]
target = "x86_64-pc-windows-gnu"

[env]
PKG_CONFIG_ALLOW_CROSS = "1"
EOF

# Create shared directory if it doesn't exist
echo "📁 Setting up shared directory..."
mkdir -p /workspace/shared

# Set up git configuration helper
echo "🔧 Setting up git configuration helper..."
cat > /workspace/setup-git.sh << 'EOF'
#!/bin/bash
echo "Setting up Git configuration..."
echo "Enter your Git username:"
read git_username
echo "Enter your Git email:"
read git_email

git config --global user.name "$git_username"
git config --global user.email "$git_email"
git config --global init.defaultBranch main
git config --global pull.rebase false

echo "Git configuration complete!"
EOF
chmod +x /workspace/setup-git.sh

# Create useful aliases
echo "🔗 Setting up helpful aliases..."
cat >> ~/.bashrc << 'EOF'

# RustPacker aliases
alias rp='cargo run --'
alias rpbuild='cargo build --release --target x86_64-pc-windows-gnu'
alias rptest='cargo test'
alias rpcheck='cargo check'
alias rpclippy='cargo clippy'
alias rpclean='cargo clean'

# Useful development aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias tree='tree -C'

# Quick navigation
alias shared='cd /workspace/shared'
alias ws='cd /workspace'

echo "🦀 RustPacker DevContainer Environment Ready!"
echo "💡 Useful commands:"
echo "  rp [args]       - Run RustPacker with arguments"
echo "  rpbuild        - Build release binary for Windows"
echo "  shared         - Navigate to shared directory"
echo "  ./setup-git.sh - Configure git credentials"
EOF

# Set up zsh configuration if zsh is available
if command -v zsh &> /dev/null; then
    cat >> ~/.zshrc << 'EOF'

# RustPacker aliases
alias rp='cargo run --'
alias rpbuild='cargo build --release --target x86_64-pc-windows-gnu'
alias rptest='cargo test'
alias rpcheck='cargo check'
alias rpclippy='cargo clippy'
alias rpclean='cargo clean'

# Useful development aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias tree='tree -C'

# Quick navigation
alias shared='cd /workspace/shared'
alias ws='cd /workspace'

echo "🦀 RustPacker DevContainer Environment Ready!"
echo "💡 Useful commands:"
echo "  rp [args]       - Run RustPacker with arguments"
echo "  rpbuild        - Build release binary for Windows"
echo "  shared         - Navigate to shared directory"
echo "  ./setup-git.sh - Configure git credentials"
EOF
fi

# Create a sample test file for quick testing
echo "📄 Creating sample test files..."
cat > /workspace/shared/README.md << 'EOF'
# RustPacker Shared Directory

This directory is mounted and shared between your host system and the DevContainer.

## Usage

1. Place your raw shellcode files here (e.g., `calc.raw`, `msf.bin`)
2. Run RustPacker commands to generate packed binaries
3. Output binaries will be available in the generated `output_*` directories

## Quick Test

To test RustPacker with a dummy payload:
```bash
# Create a dummy payload (this won't actually work, just for testing the packer)
echo -n -e '\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00' > shared/test.raw

# Pack it with ntcrt template and AES encryption
rp -f shared/test.raw -i ntcrt -e aes -b exe -t notepad.exe
```

## Templates Available

- `ntcrt` - NT API remote thread injection
- `ntapc` - NT API APC injection  
- `syscrt` - Indirect syscalls remote thread injection
- `wincrt` - Windows API remote thread injection
- `ntfiber` - NT API fiber execution
- `winfiber` - Windows API fiber execution
- `sysfiber` - Syscalls fiber execution

## Encryption Options

- `xor` - XOR encryption
- `aes` - AES encryption

## Output Formats

- `exe` - Executable file
- `dll` - Dynamic link library
EOF

# Check if we're in the RustPacker directory and set up the project
if [ -f "Cargo.toml" ]; then
    echo "🔍 RustPacker project detected, running initial checks..."
    
    # Check if project compiles
    echo "🧪 Running initial project checks..."
    cargo check --target x86_64-pc-windows-gnu || echo "⚠️  Initial check failed - this is normal if dependencies need to be installed"
    
    # Fetch dependencies
    echo "📦 Fetching dependencies..."
    cargo fetch
fi

echo "✅ RustPacker DevContainer setup completed successfully!"
echo ""
echo "🚀 You can now:"
echo "   • Use 'rp [args]' to run RustPacker"
echo "   • Use 'rpbuild' to build release binaries"
echo "   • Place shellcode files in the 'shared' directory"
echo "   • Run './setup-git.sh' to configure Git if needed"
echo ""
echo "📚 For more information, check the project README or run 'rp --help'"