use clap::{Parser, ValueEnum};
use std::fmt;
use std::path::PathBuf;

use crate::tools::absolute_path;

/// Main configuration structure for RustPacker
#[derive(Parser, Debug, Clone)]
#[command(name = "RustPacker")]
#[command(author = "by Nariod")]
#[command(version = "2.0.0")]
#[command(about = "Shellcode packer written in Rust.", long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Order {
    /// Path to the raw shellcode file
    #[arg(short, long, value_name = "FILE")]
    pub shellcode_path: PathBuf,

    /// Binary output format: exe or dll
    #[arg(short, long, value_name = "FORMAT")]
    pub format: Format,

    /// Execution technique / injection template
    #[arg(short, long, value_name = "TEMPLATE")]
    pub execution: Execution,

    /// Encryption method: xor, aes, uuid
    #[arg(short, long, value_name = "ENCRYPTION")]
    pub encryption: Encryption,

    /// Target process to inject into (default: dllhost.exe, CRT templates only)
    #[arg(short, long, default_value_t = String::from("dllhost.exe"))]
    pub target_process: String,

    /// Sandbox check: Domain Pinning to the provided domain name
    #[arg(short, long)]
    pub sandbox: Option<String>,

    /// Optional output path for the resulting binary
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Path to legitimate DLL to proxy (place it in shared/ for container mode). 
    /// Requires -b dll and a self-injection template (ntapc, winfiber, ntfiber, sysfiber)
    #[arg(short, long)]
    pub proxy_dll: Option<PathBuf>,
}

/// Execution techniques available for shellcode injection
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Execution {
    /// Self inject using APC low level APIs
    #[value(alias = "ntapc")]
    NtQueueUserAPC,
    /// Create Remote Thread using low level APIs
    #[value(alias = "ntcrt")]
    NtCreateRemoteThread,
    /// Create Remote Thread using indirect syscalls
    #[value(alias = "syscrt")]
    SysCreateRemoteThread,
    /// Create Remote Thread using the official Windows Crate
    #[value(alias = "wincrt")]
    WinCreateRemoteThread,
    /// Self execute using Fibers and the official Windows Crate
    #[value(alias = "winfiber")]
    WinFiber,
    /// Self execute using Fibers and low level APIs
    #[value(alias = "ntfiber")]
    NtFiber,
    /// Self execute using Fibers and indirect syscalls
    #[value(alias = "sysfiber")]
    SysFiber,
    /// EarlyCascade injection via shim engine callback hijacking
    #[value(alias = "earlycascade")]
    EarlyCascade,
}

impl Execution {
    /// Check if this execution method uses self-injection
    pub fn is_self_injection(&self) -> bool {
        matches!(
            self,
            Execution::NtQueueUserAPC
                | Execution::WinFiber
                | Execution::NtFiber
                | Execution::SysFiber
        )
    }
}

impl fmt::Display for Execution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Execution::SysCreateRemoteThread => "sysCRT",
            Execution::NtCreateRemoteThread => "ntCRT",
            Execution::NtQueueUserAPC => "ntAPC",
            Execution::WinCreateRemoteThread => "winCRT",
            Execution::WinFiber => "winFIBER",
            Execution::NtFiber => "ntFIBER",
            Execution::SysFiber => "sysFIBER",
            Execution::EarlyCascade => "ntEarlyCascade",
        };
        write!(f, "{}", s)
    }
}

/// Encryption methods available for shellcode
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Encryption {
    /// XOR encoding
    Xor,
    /// AES 256 encryption
    Aes,
    /// UUID-based shellcode encoding
    Uuid,
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Encryption::Xor => "xor",
            Encryption::Aes => "aes",
            Encryption::Uuid => "uuid",
        };
        write!(f, "{}", s)
    }
}

/// Output binary format
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// EXE format
    Exe,
    /// DLL format
    Dll,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Format::Exe => "exe",
            Format::Dll => "dll",
        };
        write!(f, "{}", s)
    }
}

/// Parse command line arguments and validate them
pub fn parse_args() -> Order {
    let mut order = Order::parse();
    
    // Convert relative paths to absolute
    order.shellcode_path = absolute_path(order.shellcode_path)
        .expect("Invalid shellcode path");
    
    if let Some(ref path) = order.output {
        order.output = Some(absolute_path(path).expect("Invalid output path"));
    }
    
    if let Some(ref path) = order.proxy_dll {
        order.proxy_dll = Some(absolute_path(path).expect("Invalid proxy DLL path"));
    }

    // Validate proxy DLL requirements
    if order.proxy_dll.is_some() {
        if !matches!(order.format, Format::Dll) {
            eprintln!("[-] Error: DLL proxying (-p) requires DLL output format (-b dll)");
            std::process::exit(1);
        }
        if !order.execution.is_self_injection() {
            eprintln!(
                "[-] Error: DLL proxying (-p) only works with self-injection templates: ntapc, winfiber, ntfiber, sysfiber"
            );
            std::process::exit(1);
        }
    }

    order
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_is_self_injection() {
        assert!(Execution::NtQueueUserAPC.is_self_injection());
        assert!(Execution::WinFiber.is_self_injection());
        assert!(Execution::NtFiber.is_self_injection());
        assert!(Execution::SysFiber.is_self_injection());
        
        assert!(!Execution::NtCreateRemoteThread.is_self_injection());
        assert!(!Execution::SysCreateRemoteThread.is_self_injection());
        assert!(!Execution::WinCreateRemoteThread.is_self_injection());
        assert!(!Execution::EarlyCascade.is_self_injection());
    }

    #[test]
    fn test_execution_display() {
        assert_eq!(format!("{}", Execution::SysCreateRemoteThread), "sysCRT");
        assert_eq!(format!("{}", Execution::NtCreateRemoteThread), "ntCRT");
        assert_eq!(format!("{}", Execution::NtQueueUserAPC), "ntAPC");
        assert_eq!(format!("{}", Execution::EarlyCascade), "ntEarlyCascade");
    }

    #[test]
    fn test_encryption_display() {
        assert_eq!(format!("{}", Encryption::Xor), "xor");
        assert_eq!(format!("{}", Encryption::Aes), "aes");
        assert_eq!(format!("{}", Encryption::Uuid), "uuid");
    }

    #[test]
    fn test_format_display() {
        assert_eq!(format!("{}", Format::Exe), "exe");
        assert_eq!(format!("{}", Format::Dll), "dll");
    }
}
