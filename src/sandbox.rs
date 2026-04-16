use crate::tools::SandboxOutput;

pub fn build_sandbox(expected_domain: &str) -> SandboxOutput {
    if expected_domain.is_empty() {
        return SandboxOutput {
            sandbox_function: String::new(),
            sandbox_import: String::new(),
        };
    }

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
        fn sandbox() {{
            match get_domain_name() {{
                Some(domain) => {{
                    println!(\"Domain: {{}}\",domain);
                    if !domain.as_str().eq_ignore_ascii_case(\"{0}\") {{
                        panic!(\"Sandbox check failed\");
                    }}
                }}
                None => {{
                    panic!(\"Sandbox check failed\");
                }}
            }}
        }}
        sandbox();",
        expected_domain
    );

    let sandbox_import =
        "use winapi::um::sysinfoapi::{GetComputerNameExW, ComputerNameDnsDomain};\n".to_string();

    SandboxOutput {
        sandbox_function,
        sandbox_import,
    }
}
