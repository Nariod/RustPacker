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

    Ok(())
}
