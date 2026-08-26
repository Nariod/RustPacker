//! Configuration types for RustPacker
//!
//! This module contains all the configuration types used throughout the application,
//! including command-line arguments, execution methods, encryption types, and output formats.

use clap::{Parser, ValueEnum};
use std::fmt;
use std::path::PathBuf;

use crate::utils::absolute_path;
use anyhow::{anyhow, Context, Result};

/// Main configuration structure for RustPacker
#[derive(Parser, Debug, Clone)]
#[command(name = "RustPacker")]
#[command(author = "by Nariod")]
#[command(version = "3.0.0")]
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
    #[arg(short = 'i', long, value_name = "TEMPLATE")]
    pub execution: Execution,

    /// Encryption method: xor, aes, uuid
    #[arg(short, long, value_name = "ENCRYPTION")]
    pub encryption: Encryption,

    /// Target process to inject into (default: dllhost.exe, CRT templates only)
    #[arg(short, long, default_value_t = String::from("dllhost.exe"))]
    pub target_process: String,

    /// Sandbox check: Domain Pinning to the provided domain name
    #[arg(long)]
    pub sandbox: Option<String>,

    /// Optional output path for the resulting binary
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Path to legitimate DLL to proxy (place it in shared/ for container mode).
    /// Requires -b dll and a self-injection template (ntapc, winfiber, ntfiber, sysfiber)
    #[arg(short, long)]
    pub proxy_dll: Option<PathBuf>,

    /// Patch ETW functions to disable Event Tracing for Windows (EDR evasion).
    /// Only available for self-injection templates using indirect syscalls.
    #[arg(long)]
    pub etw_patch: bool,
}

/// Execution techniques available for shellcode injection
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Execution {
    /// Self inject using APC low level APIs
    #[value(alias = "ntapc", alias = "ntAPC")]
    NtQueueUserAPC,
    /// Create Remote Thread using low level APIs
    #[value(alias = "ntcrt", alias = "ntCRT")]
    NtCreateRemoteThread,
    /// Create Remote Thread using indirect syscalls
    #[value(alias = "syscrt", alias = "sysCRT")]
    SysCreateRemoteThread,
    /// Create Remote Thread using the official Windows Crate
    #[value(alias = "wincrt", alias = "winCRT")]
    WinCreateRemoteThread,
    /// Self execute using Fibers and the official Windows Crate
    #[value(alias = "winfiber", alias = "winFIBER")]
    WinFiber,
    /// Self execute using Fibers and low level APIs
    #[value(alias = "ntfiber", alias = "ntFIBER")]
    NtFiber,
    /// Self execute using Fibers and indirect syscalls
    #[value(alias = "sysfiber", alias = "sysFIBER")]
    SysFiber,
    /// EarlyCascade injection via shim engine callback hijacking
    #[value(alias = "earlycascade", alias = "ntEarlyCascade")]
    EarlyCascade,
    /// Module stomping via low level APIs (overwrites a legit DLL .text)
    #[value(alias = "ntstomp", alias = "ntStomp")]
    NtModuleStomping,
    /// WebAssembly (WAT) stager: wraps the encrypted payload in a
    /// wasm module (low-entropy WAT text format) and reads it back out
    /// at runtime before executing in-process. Self-injection technique.
    #[value(alias = "ntwat", alias = "ntWat")]
    NtWatStager,
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
                | Execution::NtModuleStomping
                | Execution::NtWatStager
        )
    }

    /// Check if this execution method uses indirect syscalls
    pub fn uses_indirect_syscalls(&self) -> bool {
        matches!(self, Execution::SysCreateRemoteThread | Execution::SysFiber)
    }

    /// Check if this execution method supports ETW patching
    pub fn supports_etw_patch(&self) -> bool {
        self.is_self_injection() && self.uses_indirect_syscalls()
    }

    /// Get the template name for this execution method
    pub fn template_name(&self) -> &'static str {
        match self {
            Execution::NtQueueUserAPC => "ntAPC",
            Execution::NtCreateRemoteThread => "ntCRT",
            Execution::SysCreateRemoteThread => "sysCRT",
            Execution::WinCreateRemoteThread => "winCRT",
            Execution::WinFiber => "winFIBER",
            Execution::NtFiber => "ntFIBER",
            Execution::SysFiber => "sysFIBER",
            Execution::EarlyCascade => "ntEarlyCascade",
            Execution::NtModuleStomping => "ntStomp",
            Execution::NtWatStager => "ntWat",
        }
    }
}

impl fmt::Display for Execution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.template_name())
    }
}

/// Encryption methods available for shellcode
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Encryption {
    /// XOR encoding
    #[value(alias = "xor", alias = "XOR")]
    Xor,
    /// AES 256 encryption
    #[value(alias = "aes", alias = "AES")]
    Aes,
    /// UUID-based shellcode encoding
    #[value(alias = "uuid", alias = "UUID")]
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
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Format {
    /// EXE format
    #[value(alias = "exe", alias = "EXE")]
    Exe,
    /// DLL format
    #[value(alias = "dll", alias = "DLL")]
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

/// Parse command line arguments and validate them.
///
/// Converts relative paths to absolute and enforces the business rules
/// (e.g. DLL proxying requires DLL format + a self-injection template).
/// Returns an error instead of exiting the process.
pub fn parse_args() -> Result<Order> {
    let mut order = Order::parse();

    order.shellcode_path = absolute_path(order.shellcode_path).context("Invalid shellcode path")?;

    if let Some(ref path) = order.output {
        order.output = Some(absolute_path(path).context("Invalid output path")?);
    }

    if let Some(ref path) = order.proxy_dll {
        order.proxy_dll = Some(absolute_path(path).context("Invalid proxy DLL path")?);
    }

    if order.proxy_dll.is_some() {
        if !matches!(order.format, Format::Dll) {
            return Err(anyhow!(
                "DLL proxying (-p) requires DLL output format (-b dll)"
            ));
        }
        if !order.execution.is_self_injection() {
            return Err(anyhow!(
                "DLL proxying (-p) only works with self-injection templates: ntapc, winfiber, ntfiber, sysfiber"
            ));
        }
    }

    if order.etw_patch && !order.execution.supports_etw_patch() {
        let eligible: Vec<&str> = Execution::all()
            .iter()
            .filter(|e| e.supports_etw_patch())
            .map(|e| e.template_name())
            .collect();
        return Err(anyhow!(
            "ETW patching (--etw-patch) is only supported with self-injection templates using indirect syscalls. Current eligible templates: {}",
            eligible.join(", ")
        ));
    }

    Ok(order)
}

/// Helper to get all execution variants for iteration
impl Execution {
    pub fn all() -> &'static [Execution] {
        &[
            Execution::NtQueueUserAPC,
            Execution::NtCreateRemoteThread,
            Execution::SysCreateRemoteThread,
            Execution::WinCreateRemoteThread,
            Execution::WinFiber,
            Execution::NtFiber,
            Execution::SysFiber,
            Execution::EarlyCascade,
            Execution::NtModuleStomping,
            Execution::NtWatStager,
        ]
    }
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
        assert!(Execution::NtModuleStomping.is_self_injection());
        assert!(Execution::NtWatStager.is_self_injection());

        assert!(!Execution::NtCreateRemoteThread.is_self_injection());
        assert!(!Execution::SysCreateRemoteThread.is_self_injection());
        assert!(!Execution::WinCreateRemoteThread.is_self_injection());
        assert!(!Execution::EarlyCascade.is_self_injection());
    }

    #[test]
    fn test_execution_uses_indirect_syscalls() {
        assert!(Execution::SysCreateRemoteThread.uses_indirect_syscalls());
        assert!(Execution::SysFiber.uses_indirect_syscalls());

        assert!(!Execution::NtQueueUserAPC.uses_indirect_syscalls());
        assert!(!Execution::NtCreateRemoteThread.uses_indirect_syscalls());
        assert!(!Execution::WinCreateRemoteThread.uses_indirect_syscalls());
        assert!(!Execution::WinFiber.uses_indirect_syscalls());
        assert!(!Execution::NtFiber.uses_indirect_syscalls());
        assert!(!Execution::EarlyCascade.uses_indirect_syscalls());
        assert!(!Execution::NtModuleStomping.uses_indirect_syscalls());
        assert!(!Execution::NtWatStager.uses_indirect_syscalls());
    }

    #[test]
    fn test_execution_supports_etw_patch() {
        assert!(Execution::SysFiber.supports_etw_patch());

        assert!(!Execution::NtQueueUserAPC.supports_etw_patch());
        assert!(!Execution::NtCreateRemoteThread.supports_etw_patch());
        assert!(!Execution::SysCreateRemoteThread.supports_etw_patch());
        assert!(!Execution::WinCreateRemoteThread.supports_etw_patch());
        assert!(!Execution::WinFiber.supports_etw_patch());
        assert!(!Execution::NtFiber.supports_etw_patch());
        assert!(!Execution::EarlyCascade.supports_etw_patch());
        assert!(!Execution::NtModuleStomping.supports_etw_patch());
        assert!(!Execution::NtWatStager.supports_etw_patch());
    }

    #[test]
    fn test_execution_display() {
        assert_eq!(format!("{}", Execution::SysCreateRemoteThread), "sysCRT");
        assert_eq!(format!("{}", Execution::NtCreateRemoteThread), "ntCRT");
        assert_eq!(format!("{}", Execution::NtQueueUserAPC), "ntAPC");
        assert_eq!(format!("{}", Execution::EarlyCascade), "ntEarlyCascade");
        assert_eq!(format!("{}", Execution::NtModuleStomping), "ntStomp");
        assert_eq!(format!("{}", Execution::NtWatStager), "ntWat");
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

    #[test]
    fn test_template_name() {
        assert_eq!(Execution::NtQueueUserAPC.template_name(), "ntAPC");
        assert_eq!(Execution::NtCreateRemoteThread.template_name(), "ntCRT");
        assert_eq!(Execution::SysCreateRemoteThread.template_name(), "sysCRT");
        assert_eq!(Execution::NtModuleStomping.template_name(), "ntStomp");
        assert_eq!(Execution::NtWatStager.template_name(), "ntWat");
    }
}
