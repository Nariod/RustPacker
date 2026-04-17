use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DllExport {
    pub name: Option<String>,
    pub ordinal: u16,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn rva_to_offset(sections: &[(u32, u32, u32)], rva: u32) -> Option<usize> {
    for &(vaddr, vsize, raw_offset) in sections {
        if rva >= vaddr && rva < vaddr + vsize {
            return Some((rva - vaddr + raw_offset) as usize);
        }
    }
    None
}

fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    let end = data[offset..].iter().position(|&b| b == 0)?;
    String::from_utf8(data[offset..offset + end].to_vec()).ok()
}

fn parse_sections(data: &[u8], pe_offset: usize, num_sections: u16) -> Vec<(u32, u32, u32)> {
    let opt_header_size = read_u16(data, pe_offset + 20) as usize;
    let section_start = pe_offset + 24 + opt_header_size;

    (0..num_sections as usize)
        .map(|i| {
            let base = section_start + i * 40;
            let vaddr = read_u32(data, base + 12);
            let vsize = read_u32(data, base + 8);
            let raw_offset = read_u32(data, base + 20);
            (vaddr, vsize, raw_offset)
        })
        .collect()
}

pub fn parse_exports(dll_path: &Path) -> Result<Vec<DllExport>, String> {
    let data = fs::read(dll_path).map_err(|e| format!("Failed to read DLL: {}", e))?;

    if data.len() < 64 || read_u16(&data, 0) != 0x5A4D {
        return Err("Not a valid PE file (bad MZ signature)".into());
    }

    let pe_offset = read_u32(&data, 0x3C) as usize;
    if data.len() < pe_offset + 4 || read_u32(&data, pe_offset) != 0x00004550 {
        return Err("Not a valid PE file (bad PE signature)".into());
    }

    let magic = read_u16(&data, pe_offset + 24);
    let export_dir_rva_offset = match magic {
        0x10b => pe_offset + 24 + 96,  // PE32
        0x20b => pe_offset + 24 + 112, // PE32+
        _ => return Err(format!("Unknown PE optional header magic: 0x{:04x}", magic)),
    };

    let num_sections = read_u16(&data, pe_offset + 6);
    let sections = parse_sections(&data, pe_offset, num_sections);

    let export_rva = read_u32(&data, export_dir_rva_offset);
    let export_size = read_u32(&data, export_dir_rva_offset + 4);

    if export_rva == 0 || export_size == 0 {
        return Ok(vec![]);
    }

    let export_offset =
        rva_to_offset(&sections, export_rva).ok_or("Cannot resolve export directory RVA")?;

    let num_functions = read_u32(&data, export_offset + 20) as usize;
    let num_names = read_u32(&data, export_offset + 24) as usize;
    let ordinal_base = read_u32(&data, export_offset + 16) as u16;

    let addr_table_rva = read_u32(&data, export_offset + 28);
    let name_ptr_rva = read_u32(&data, export_offset + 32);
    let ordinal_table_rva = read_u32(&data, export_offset + 36);

    let addr_table_off =
        rva_to_offset(&sections, addr_table_rva).ok_or("Cannot resolve address table RVA")?;
    let name_ptr_off =
        rva_to_offset(&sections, name_ptr_rva).ok_or("Cannot resolve name pointer RVA")?;
    let ordinal_off =
        rva_to_offset(&sections, ordinal_table_rva).ok_or("Cannot resolve ordinal table RVA")?;

    let mut name_for_index: Vec<Option<String>> = vec![None; num_functions];
    for i in 0..num_names {
        let name_rva = read_u32(&data, name_ptr_off + i * 4);
        let ord_index = read_u16(&data, ordinal_off + i * 2) as usize;
        if let Some(off) = rva_to_offset(&sections, name_rva) {
            if let Some(name) = read_cstring(&data, off) {
                if ord_index < num_functions {
                    name_for_index[ord_index] = Some(name);
                }
            }
        }
    }

    let export_end_rva = export_rva + export_size;
    let mut exports = Vec::new();

    for i in 0..num_functions {
        let func_rva = read_u32(&data, addr_table_off + i * 4);
        if func_rva == 0 {
            continue;
        }

        let is_forwarder = func_rva >= export_rva && func_rva < export_end_rva;
        if is_forwarder {
            continue;
        }

        exports.push(DllExport {
            name: name_for_index[i].clone(),
            ordinal: ordinal_base + i as u16,
        });
    }

    Ok(exports)
}

pub fn dll_stem(dll_path: &Path) -> String {
    dll_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("original")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_minimal_pe_dll(exports: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];

        buf[0] = 0x4D; // M
        buf[1] = 0x5A; // Z

        let pe_offset: u32 = 0x80;
        buf[0x3C] = pe_offset as u8;

        let pe = pe_offset as usize;
        buf[pe] = 0x50;     // P
        buf[pe + 1] = 0x45; // E
        buf[pe + 2] = 0x00;
        buf[pe + 3] = 0x00;

        // COFF header
        buf[pe + 4] = 0x64; buf[pe + 5] = 0x86; // Machine: x86_64
        buf[pe + 6] = 0x01; buf[pe + 7] = 0x00; // 1 section
        let opt_header_size: u16 = 112 + 16 * 16;
        buf[pe + 20] = (opt_header_size & 0xFF) as u8;
        buf[pe + 21] = (opt_header_size >> 8) as u8;
        buf[pe + 22] = 0x22; buf[pe + 23] = 0x20; // DLL characteristics

        // Optional header
        let opt = pe + 24;
        buf[opt] = 0x0B; buf[opt + 1] = 0x02; // PE32+ magic

        let section_rva: u32 = 0x1000;
        let section_raw: u32 = 0x400; // after all headers
        let section_size: u32 = 0x1000;

        // Export directory RVA at opt + 112
        let export_dir_offset = opt + 112;

        // Section header
        let sec = pe + 24 + opt_header_size as usize;
        buf[sec..sec + 8].copy_from_slice(b".edata\0\0");
        buf[sec + 8..sec + 12].copy_from_slice(&section_size.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&section_rva.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&section_size.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&section_raw.to_le_bytes());

        // Build export data at file offset section_raw, RVA section_rva
        let num_exports = exports.len();
        let export_data_start = section_raw as usize;
        let edt = export_data_start; // Export Directory Table

        // Export dir is 40 bytes
        // Then: AddressOfFunctions array, AddressOfNames array, AddressOfNameOrdinals array, then name strings

        let addr_table_off = 40usize;
        let name_ptr_off = addr_table_off + num_exports * 4;
        let ordinal_table_off = name_ptr_off + num_exports * 4;
        let strings_off = ordinal_table_off + num_exports * 2;

        // Write export directory
        let ordinal_base: u32 = 1;
        // NumberOfFunctions
        buf[edt + 20..edt + 24].copy_from_slice(&(num_exports as u32).to_le_bytes());
        // NumberOfNames
        buf[edt + 24..edt + 28].copy_from_slice(&(num_exports as u32).to_le_bytes());
        // OrdinalBase
        buf[edt + 16..edt + 20].copy_from_slice(&ordinal_base.to_le_bytes());
        // AddressOfFunctions RVA
        let addr_table_rva = section_rva + addr_table_off as u32;
        buf[edt + 28..edt + 32].copy_from_slice(&addr_table_rva.to_le_bytes());
        // AddressOfNames RVA
        let name_ptr_rva = section_rva + name_ptr_off as u32;
        buf[edt + 32..edt + 36].copy_from_slice(&name_ptr_rva.to_le_bytes());
        // AddressOfNameOrdinals RVA
        let ordinal_rva = section_rva + ordinal_table_off as u32;
        buf[edt + 36..edt + 40].copy_from_slice(&ordinal_rva.to_le_bytes());

        let mut string_cursor = strings_off;
        for (i, name) in exports.iter().enumerate() {
            // Address table: dummy non-zero RVA (points somewhere in section, not in export dir range)
            let func_rva: u32 = section_rva + 0xD00 + i as u32;
            buf[edt + addr_table_off + i * 4..edt + addr_table_off + i * 4 + 4]
                .copy_from_slice(&func_rva.to_le_bytes());

            // Name pointer table: RVA of string
            let name_string_rva = section_rva + string_cursor as u32;
            buf[edt + name_ptr_off + i * 4..edt + name_ptr_off + i * 4 + 4]
                .copy_from_slice(&name_string_rva.to_le_bytes());

            // Ordinal table
            buf[edt + ordinal_table_off + i * 2] = i as u8;
            buf[edt + ordinal_table_off + i * 2 + 1] = 0;

            // Write name string
            buf[edt + string_cursor..edt + string_cursor + name.len()]
                .copy_from_slice(name.as_bytes());
            buf[edt + string_cursor + name.len()] = 0;
            string_cursor += name.len() + 1;
        }

        // Export directory RVA and size
        let export_total_size = string_cursor as u32;
        buf[export_dir_offset..export_dir_offset + 4]
            .copy_from_slice(&section_rva.to_le_bytes());
        buf[export_dir_offset + 4..export_dir_offset + 8]
            .copy_from_slice(&export_total_size.to_le_bytes());

        buf
    }

    fn write_temp_dll(name: &str, data: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("rustpacker_test_pe_parser");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(data).unwrap();
        path
    }

    #[test]
    fn test_parse_named_exports() {
        let pe = build_minimal_pe_dll(&["GetFileVersionInfoA", "GetFileVersionInfoW", "VerQueryValueW"]);
        let path = write_temp_dll("named_exports.dll", &pe);
        let exports = parse_exports(&path).unwrap();

        assert_eq!(exports.len(), 3);
        assert_eq!(exports[0].name.as_deref(), Some("GetFileVersionInfoA"));
        assert_eq!(exports[1].name.as_deref(), Some("GetFileVersionInfoW"));
        assert_eq!(exports[2].name.as_deref(), Some("VerQueryValueW"));
        assert_eq!(exports[0].ordinal, 1);
        assert_eq!(exports[1].ordinal, 2);
        assert_eq!(exports[2].ordinal, 3);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_parse_no_exports() {
        let mut pe = build_minimal_pe_dll(&[]);
        // Zero out the export directory RVA
        let pe_offset = read_u32(&pe, 0x3C) as usize;
        let export_dir_off = pe_offset + 24 + 112;
        pe[export_dir_off..export_dir_off + 8].copy_from_slice(&[0; 8]);

        let path = write_temp_dll("no_exports.dll", &pe);
        let exports = parse_exports(&path).unwrap();
        assert!(exports.is_empty());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_parse_invalid_file() {
        let path = write_temp_dll("not_a_dll.bin", b"this is not a PE file");
        let result = parse_exports(&path);
        assert!(result.is_err());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_dll_stem() {
        assert_eq!(dll_stem(Path::new("C:\\Windows\\System32\\version.dll")), "version");
        assert_eq!(dll_stem(Path::new("/tmp/mylib.dll")), "mylib");
        assert_eq!(dll_stem(Path::new("test")), "test");
    }

    #[test]
    fn test_parse_single_export() {
        let pe = build_minimal_pe_dll(&["DllGetClassObject"]);
        let path = write_temp_dll("single_export.dll", &pe);
        let exports = parse_exports(&path).unwrap();

        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name.as_deref(), Some("DllGetClassObject"));
        assert_eq!(exports[0].ordinal, 1);

        fs::remove_file(&path).ok();
    }
}
