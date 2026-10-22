//! Command-line layer for RustPacker.
//!
//! Parses arguments into an [`Order`] and enforces the business rules
//! (e.g. DLL proxying requires DLL format + a self-injection template).
//! The domain types themselves live in [`crate::config`].

use crate::config::{Execution, Format, Order};
use crate::utils::absolute_path;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::path::PathBuf;

/// Parse command line arguments, resolve paths, and validate the order.
///
/// Returns an error instead of exiting the process.
pub fn parse_args() -> Result<Order> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--list-templates") {
        print_templates();
        std::process::exit(0);
    }
    if args.iter().any(|arg| arg == "--clean")
        && !args
            .iter()
            .any(|arg| arg == "-s" || arg.starts_with("--shellcode-path"))
    {
        crate::template_io::clean_output_folders()?;
        println!("[+] Cleaned generated output folders");
        std::process::exit(0);
    }
    let mut order = Order::parse();

    order.shellcode_path = absolute_path(order.shellcode_path).context("Invalid shellcode path")?;

    if order.output.is_none() {
        let default = PathBuf::from(format!("payload.{}", order.format));
        println!("[i] No --output given, defaulting to {}", default.display());
        order.output = Some(default);
    }
    if let Some(ref path) = order.output {
        let path = absolute_path(path).context("Invalid output path")?;
        let path = if path.is_dir() {
            path.join(format!("payload.{}", order.format))
        } else {
            path
        };
        order.output = Some(path);
    }

    if let Some(ref path) = order.proxy_dll {
        order.proxy_dll = Some(absolute_path(path).context("Invalid proxy DLL path")?);
    }

    validate_order(&order)?;

    Ok(order)
}

/// Reject a feature flag that is enabled for a template that cannot support
/// it, listing the eligible templates.
fn require_template(
    order: &Order,
    enabled: bool,
    supported: impl Fn(&Execution) -> bool,
    flag: &str,
    rule: &str,
) -> Result<()> {
    if !enabled || supported(&order.execution) {
        return Ok(());
    }
    let eligible: Vec<&str> = Execution::all()
        .iter()
        .filter(|e| supported(e))
        .map(|e| e.template_name())
        .collect();
    Err(anyhow!(
        "{flag} is only supported with {rule}. Current eligible templates: {}",
        eligible.join(", ")
    ))
}

/// Print the template catalogue with per-template option support, so users
/// can discover valid combinations without trial and error.
pub fn print_templates() {
    println!("Available templates:");
    println!(
        "{:<15} {:<12} {:<12} {:<12} {:<12}",
        "TEMPLATE", "SELF-INJECT", "INDIRECT", "ETW-PATCH", "STACK-SPOOF"
    );
    for execution in Execution::all() {
        println!(
            "{:<15} {:<12} {:<12} {:<12} {:<12}",
            execution.template_name(),
            yes_no(execution.is_self_injection()),
            yes_no(execution.uses_indirect_syscalls()),
            yes_no(execution.supports_etw_patch()),
            yes_no(execution.supports_stack_spoof())
        );
    }
    println!("\nEncryption: xor, aes, uuid   Format: exe, dll");
}

fn yes_no(condition: bool) -> &'static str {
    if condition {
        "yes"
    } else {
        "no"
    }
}

/// Enforce the business rules that link options together.
fn validate_order(order: &Order) -> Result<()> {
    if order.proxy_dll.is_some() {
        if !matches!(order.format, Format::Dll) {
            return Err(anyhow!(
                "DLL proxying (-p) requires DLL output format (-f dll)"
            ));
        }
        if !order.execution.is_self_injection() {
            return Err(anyhow!(
                "DLL proxying (-p) only works with self-injection templates: ntapc, ntfiber, sysfiber, winfiber, ntstomp, ntwat, ntveh"
            ));
        }
    }

    require_template(
        order,
        order.etw_patch,
        |e| e.supports_etw_patch(),
        "ETW patching (--etw-patch)",
        "self-injection templates using indirect syscalls",
    )?;

    require_template(
        order,
        order.stack_spoof,
        |e| e.supports_stack_spoof(),
        "Stack spoofing (--stack-spoof)",
        "indirect-syscall templates",
    )?;

    Ok(())
}
