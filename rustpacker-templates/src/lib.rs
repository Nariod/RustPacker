//! RustPacker Templates
//!
//! This crate provides access to all the injection templates for RustPacker.

use rustpacker_core::config::Execution;
use std::path::PathBuf;

/// Get the path to a template directory
///
/// # Arguments
/// * `execution` - The execution method
///
/// # Returns
/// Path to the template directory
pub fn get_template_path(execution: Execution) -> PathBuf {
    let template_name = execution.template_name();
    PathBuf::from(format!("templates/{}/.", template_name))
}

/// Get all available template names
pub fn get_all_template_names() -> Vec<&'static str> {
    vec![
        "ntAPC",
        "ntCRT",
        "sysCRT",
        "winCRT",
        "winFIBER",
        "ntFIBER",
        "sysFIBER",
        "ntEarlyCascade",
    ]
}

/// Check if a template uses self-injection
pub fn is_self_injection(execution: Execution) -> bool {
    execution.is_self_injection()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustpacker_core::config::Execution;

    #[test]
    fn test_get_template_path() {
        let path = get_template_path(Execution::NtCreateRemoteThread);
        assert!(path.to_string_lossy().contains("templates/ntCRT"));
    }

    #[test]
    fn test_get_all_template_names() {
        let names = get_all_template_names();
        assert_eq!(names.len(), 8);
        assert!(names.contains(&"ntCRT"));
        assert!(names.contains(&"sysCRT"));
    }

    #[test]
    fn test_is_self_injection() {
        assert!(!is_self_injection(Execution::NtCreateRemoteThread));
        assert!(is_self_injection(Execution::NtQueueUserAPC));
    }
}
