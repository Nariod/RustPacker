//! Command-line layer for RustPacker.
//!
//! Parses arguments into an [`Order`] and enforces the business rules
//! (e.g. DLL proxying requires DLL format + a self-injection template).
//! The domain types themselves live in [`crate::config`].

use crate::config::{Execution, Format, Order};
use crate::utils::absolute_path;
use anyhow::{anyhow, Context, Result};
use clap::Parser;

/// Parse command line arguments, resolve paths, and validate the order.
///
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
