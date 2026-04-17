use crate::pe_parser::DllExport;

pub struct ProxyOutput {
    pub proxy_source: String,
    pub original_dll_name: String,
}

pub fn generate_proxy(exports: &[DllExport], original_stem: &str) -> ProxyOutput {
    let original_dll_name = format!("{}_orig", original_stem);
    let proxy_source = generate_proxy_source(exports, &original_dll_name);

    ProxyOutput {
        proxy_source,
        original_dll_name: format!("{}.dll", original_dll_name),
    }
}

fn generate_proxy_source(exports: &[DllExport], forward_target: &str) -> String {
    let named: Vec<(usize, &str)> = exports
        .iter()
        .filter_map(|e| e.name.as_deref())
        .enumerate()
        .collect();

    let dll_filename = format!("{}.dll", forward_target);
    let mut s = String::new();

    s.push_str("use std::arch::naked_asm;\n");
    s.push_str("use std::sync::atomic::{AtomicUsize, Ordering};\n\n");

    s.push_str("#[link(name = \"kernel32\")]\n");
    s.push_str("extern \"system\" {\n");
    s.push_str("    #[link_name = \"LoadLibraryA\"]\n");
    s.push_str("    fn rp_load_library(name: *const u8) -> isize;\n");
    s.push_str("    #[link_name = \"GetProcAddress\"]\n");
    s.push_str("    fn rp_get_proc_address(module: isize, name: *const u8) -> usize;\n");
    s.push_str("}\n\n");

    for (i, name) in &named {
        s.push_str(&format!(
            "static RP_ADDR_{}: AtomicUsize = AtomicUsize::new(0); // {}\n",
            i, name
        ));
    }
    if !named.is_empty() {
        s.push('\n');
    }

    s.push_str("pub unsafe fn init() {\n");
    s.push_str(&format!(
        "    let h = rp_load_library(b\"{}\\0\".as_ptr());\n",
        dll_filename
    ));
    s.push_str("    if h == 0 { return; }\n");
    for (i, name) in &named {
        s.push_str(&format!(
            "    RP_ADDR_{}.store(rp_get_proc_address(h, b\"{}\\0\".as_ptr()), Ordering::Release);\n",
            i, name
        ));
    }
    s.push_str("}\n\n");

    for (i, name) in &named {
        s.push_str("#[unsafe(naked)]\n");
        s.push_str(&format!("#[export_name = \"{}\"]\n", name));
        s.push_str(&format!(
            "pub unsafe extern \"system\" fn _rp_fwd_{}() {{\n",
            i
        ));
        s.push_str(&format!(
            "    naked_asm!(\"jmp qword ptr [rip + {{addr}}]\", addr = sym RP_ADDR_{});\n",
            i
        ));
        s.push_str("}\n\n");
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_parser::DllExport;

    #[test]
    fn test_proxy_source_named_exports() {
        let exports = vec![
            DllExport { name: Some("GetFileVersionInfoA".into()), ordinal: 1 },
            DllExport { name: Some("GetFileVersionInfoW".into()), ordinal: 2 },
        ];
        let src = generate_proxy_source(&exports, "version_orig");
        assert!(src.contains("static RP_ADDR_0: AtomicUsize"));
        assert!(src.contains("static RP_ADDR_1: AtomicUsize"));
        assert!(src.contains("#[export_name = \"GetFileVersionInfoA\"]"));
        assert!(src.contains("#[export_name = \"GetFileVersionInfoW\"]"));
        assert!(src.contains("#[unsafe(naked)]"));
        assert!(src.contains("b\"version_orig.dll\\0\""));
    }

    #[test]
    fn test_proxy_source_skips_ordinal_only() {
        let exports = vec![
            DllExport { name: Some("FuncA".into()), ordinal: 1 },
            DllExport { name: None, ordinal: 5 },
        ];
        let src = generate_proxy_source(&exports, "test_orig");
        assert!(src.contains("#[export_name = \"FuncA\"]"));
        assert!(src.contains("static RP_ADDR_0: AtomicUsize"));
        assert!(!src.contains("RP_ADDR_1"));
    }

    #[test]
    fn test_proxy_source_empty() {
        let src = generate_proxy_source(&[], "test_orig");
        assert!(src.contains("pub unsafe fn init()"));
        assert!(!src.contains("#[unsafe(naked)]"));
    }

    #[test]
    fn test_generate_proxy_output() {
        let exports = vec![
            DllExport { name: Some("Init".into()), ordinal: 1 },
        ];
        let output = generate_proxy(&exports, "mylib");
        assert_eq!(output.original_dll_name, "mylib_orig.dll");
        assert!(output.proxy_source.contains("#[export_name = \"Init\"]"));
        assert!(output.proxy_source.contains("b\"mylib_orig.dll\\0\""));
    }

    #[test]
    fn test_proxy_source_init_resolves_all() {
        let exports = vec![
            DllExport { name: Some("Alpha".into()), ordinal: 1 },
            DllExport { name: Some("Beta".into()), ordinal: 2 },
            DllExport { name: Some("Gamma".into()), ordinal: 3 },
        ];
        let src = generate_proxy_source(&exports, "lib_orig");
        assert!(src.contains("b\"Alpha\\0\""));
        assert!(src.contains("b\"Beta\\0\""));
        assert!(src.contains("b\"Gamma\\0\""));
        assert!(src.contains("RP_ADDR_0.store"));
        assert!(src.contains("RP_ADDR_1.store"));
        assert!(src.contains("RP_ADDR_2.store"));
    }
}
