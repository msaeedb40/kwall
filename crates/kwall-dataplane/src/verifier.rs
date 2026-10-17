use kwall_common::{KwallError, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::info;

/// Linux eBPF ELF constants
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_BPF: u16 = 247; // 0xf7
pub const MAX_BPF_INSTRUCTIONS: u64 = 1_000_000;
pub const KWALL_MAX_RECOMMENDED_INSTRUCTIONS: u64 = 4_096;
pub const MAX_BPF_STACK_BYTES: u64 = 512;

/// Expected BPF programs in KWALL dataplane
pub const EXPECTED_BPF_PROGRAMS: &[&str] =
    &["kwall_xdp_ingress", "kwall_tc_ingress", "kwall_tc_egress"];

/// Expected BPF maps in KWALL dataplane
pub const EXPECTED_BPF_MAPS: &[&str] = &[
    "KW_CONNTRACK",
    "KW_ENDPOINTS",
    "KW_POLICIES",
    "KW_FLOW_EVENTS",
    "KW_IP_BLACKLIST",
    "KW_METRICS",
    "KW_SEC_EVENTS",
    "KW_RATE_LIMITS",
];

#[derive(Debug, Clone)]
pub struct BpfProgramInfo {
    pub name: String,
    pub section: String,
    pub size_bytes: u64,
    pub instruction_count: u64,
}

#[derive(Debug, Clone)]
pub struct BpfMapInfo {
    pub name: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct BpfVerifierReport {
    pub is_valid: bool,
    pub architecture: String,
    pub programs: Vec<BpfProgramInfo>,
    pub maps: Vec<BpfMapInfo>,
    pub total_instructions: u64,
    pub sections: Vec<String>,
    pub errors: Vec<String>,
}

/// Static and architectural verifier for KWALL eBPF bytecode.
pub struct BpfConformanceVerifier;

impl BpfConformanceVerifier {
    /// Verify an eBPF ELF binary from a byte slice.
    pub fn verify_bytes(bytes: &[u8]) -> Result<BpfVerifierReport> {
        let mut errors = Vec::new();

        if bytes.len() < 64 {
            return Err(KwallError::Dataplane(
                "ELF binary too small to contain a valid header".into(),
            ));
        }

        // 1. Verify Magic
        if bytes[0..4] != ELF_MAGIC {
            return Err(KwallError::Dataplane("Invalid ELF magic header".into()));
        }

        // 2. Verify 64-bit Architecture
        if bytes[4] != ELFCLASS64 {
            errors.push("Not an ELF64 binary".to_string());
        }

        // 3. Verify Little Endian
        if bytes[5] != ELFDATA2LSB {
            errors.push("Not little-endian (eBPF targets must be little-endian)".to_string());
        }

        // 4. Verify eBPF Machine Code
        let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        if e_machine != EM_BPF {
            errors.push(format!(
                "Invalid machine architecture: expected EM_BPF ({:#x}), found {:#x}",
                EM_BPF, e_machine
            ));
        }

        // 5. Parse Section Headers
        let e_shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes(bytes[58..60].try_into().unwrap()) as usize;
        let e_shnum = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
        let e_shstrndx = u16::from_le_bytes(bytes[62..64].try_into().unwrap()) as usize;

        if e_shoff + (e_shnum * e_shentsize) > bytes.len() {
            return Err(KwallError::Dataplane(
                "Malformed ELF: section headers extend beyond file bounds".into(),
            ));
        }

        // Read Section Header String Table
        let mut section_names = Vec::new();
        let mut section_headers = Vec::new();

        for i in 0..e_shnum {
            let offset = e_shoff + (i * e_shentsize);
            let sh_name = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            let sh_type = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
            let sh_flags = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
            let sh_addr = u64::from_le_bytes(bytes[offset + 16..offset + 24].try_into().unwrap());
            let sh_offset =
                u64::from_le_bytes(bytes[offset + 24..offset + 32].try_into().unwrap()) as usize;
            let sh_size =
                u64::from_le_bytes(bytes[offset + 32..offset + 40].try_into().unwrap()) as usize;
            let sh_link = u32::from_le_bytes(bytes[offset + 40..offset + 44].try_into().unwrap());
            let sh_info = u32::from_le_bytes(bytes[offset + 44..offset + 48].try_into().unwrap());
            let sh_entsize =
                u64::from_le_bytes(bytes[offset + 56..offset + 64].try_into().unwrap()) as usize;

            section_headers.push((
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info,
                sh_entsize,
            ));
        }

        if e_shstrndx >= section_headers.len() {
            return Err(KwallError::Dataplane(
                "Invalid section header string table index in ELF".into(),
            ));
        }

        let shstr_offset = section_headers[e_shstrndx].4;
        let shstr_size = section_headers[e_shstrndx].5;
        if shstr_offset + shstr_size > bytes.len() {
            return Err(KwallError::Dataplane(
                "Section header string table extends beyond file bounds".into(),
            ));
        }
        let shstr_slice = &bytes[shstr_offset..shstr_offset + shstr_size];

        let get_string = |str_slice: &[u8], offset: u32| -> String {
            let offset = offset as usize;
            if offset >= str_slice.len() {
                return String::new();
            }
            let end = str_slice[offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| offset + p)
                .unwrap_or(str_slice.len());
            String::from_utf8_lossy(&str_slice[offset..end]).to_string()
        };

        let mut symtab_idx = None;
        let mut strtab_idx = None;
        let mut section_map = HashMap::new();

        for (idx, header) in section_headers.iter().enumerate() {
            let name = get_string(shstr_slice, header.0);
            section_names.push(name.clone());
            section_map.insert(idx, name.clone());

            if header.1 == 2 {
                // SHT_SYMTAB
                symtab_idx = Some(idx);
            } else if header.1 == 3 && name == ".strtab" {
                // SHT_STRTAB
                strtab_idx = Some(idx);
            }
        }

        // 6. Verify required sections exist
        let section_set: HashSet<String> = section_names.iter().cloned().collect();
        if !section_set.contains("classifier") {
            errors.push("Missing required 'classifier' section for TC programs".to_string());
        }
        if !section_set.contains("xdp") {
            errors.push("Missing required 'xdp' section for XDP programs".to_string());
        }
        if !section_set.contains("maps") {
            errors.push("Missing required 'maps' section for BPF maps".to_string());
        }

        // 7. Parse Symbols and Validate Programs & Maps
        let mut programs = Vec::new();
        let mut maps = Vec::new();
        let mut total_instructions = 0;

        if let (Some(sym_idx), Some(str_idx)) = (symtab_idx, strtab_idx) {
            let sym_header = &section_headers[sym_idx];
            let str_header = &section_headers[str_idx];

            let str_slice = &bytes[str_header.4..str_header.4 + str_header.5];
            let entry_size = if sym_header.8 > 0 { sym_header.8 } else { 24 };
            let num_symbols = sym_header.5 / entry_size;

            for s in 0..num_symbols {
                let s_offset = sym_header.4 + (s * entry_size);
                let st_name = u32::from_le_bytes(bytes[s_offset..s_offset + 4].try_into().unwrap());
                let st_info = bytes[s_offset + 4];
                let st_shndx =
                    u16::from_le_bytes(bytes[s_offset + 6..s_offset + 8].try_into().unwrap());
                let st_size =
                    u64::from_le_bytes(bytes[s_offset + 16..s_offset + 24].try_into().unwrap());

                let sym_name = get_string(str_slice, st_name);
                let sym_type = st_info & 0x0f;

                if sym_type == 2 {
                    // STT_FUNC
                    let sec_name = section_map
                        .get(&(st_shndx as usize))
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    let insn_count = st_size / 8; // BPF instruction = 8 bytes

                    if EXPECTED_BPF_PROGRAMS.contains(&sym_name.as_str()) {
                        // Instruction limit check
                        if insn_count > MAX_BPF_INSTRUCTIONS {
                            errors.push(format!(
                                "Program {} exceeds kernel limit: {} instructions (max {})",
                                sym_name, insn_count, MAX_BPF_INSTRUCTIONS
                            ));
                        }
                        if insn_count > KWALL_MAX_RECOMMENDED_INSTRUCTIONS {
                            info!(
                                "Warning: Program {} has {} instructions (> {})",
                                sym_name, insn_count, KWALL_MAX_RECOMMENDED_INSTRUCTIONS
                            );
                        }

                        total_instructions += insn_count;
                        programs.push(BpfProgramInfo {
                            name: sym_name,
                            section: sec_name,
                            size_bytes: st_size,
                            instruction_count: insn_count,
                        });
                    }
                } else if sym_type == 1 {
                    // STT_OBJECT (Map)
                    if EXPECTED_BPF_MAPS.contains(&sym_name.as_str()) {
                        maps.push(BpfMapInfo {
                            name: sym_name,
                            size_bytes: st_size,
                        });
                    }
                }
            }
        }

        // Check for missing programs
        let found_progs: HashSet<&str> = programs.iter().map(|p| p.name.as_str()).collect();
        for &expected in EXPECTED_BPF_PROGRAMS {
            if !found_progs.contains(expected) {
                errors.push(format!("Missing expected BPF program: {}", expected));
            }
        }

        // Check for missing maps
        let found_maps: HashSet<&str> = maps.iter().map(|m| m.name.as_str()).collect();
        for &expected in EXPECTED_BPF_MAPS {
            if !found_maps.contains(expected) {
                errors.push(format!("Missing expected BPF map: {}", expected));
            }
        }

        let is_valid = errors.is_empty();

        Ok(BpfVerifierReport {
            is_valid,
            architecture: "eBPF (bpfel-unknown-none)".to_string(),
            programs,
            maps,
            total_instructions,
            sections: section_names,
            errors,
        })
    }

    /// Verify an eBPF ELF binary from a filesystem path.
    pub fn verify_file<P: AsRef<Path>>(path: P) -> Result<BpfVerifierReport> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| {
            KwallError::Dataplane(format!(
                "Failed to read eBPF binary at {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::verify_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_rejects_garbage() {
        let garbage = vec![0u8; 128];
        assert!(BpfConformanceVerifier::verify_bytes(&garbage).is_err());
    }

    #[test]
    fn test_verifier_rejects_non_bpf_elf() {
        // Construct minimal ELF header with x86_64 architecture (EM_X86_64 = 62)
        let mut header = vec![0u8; 64];
        header[0..4].copy_from_slice(&ELF_MAGIC);
        header[4] = ELFCLASS64;
        header[5] = ELFDATA2LSB;
        header[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64

        let report = BpfConformanceVerifier::verify_bytes(&header);
        assert!(report.is_err() || !report.unwrap().is_valid);
    }

    #[test]
    fn test_verify_real_kwall_ebpf_binary() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let candidate_paths = [
            format!(
                "{}/../../target/bpfel-unknown-none/release/kwall-ebpf",
                manifest_dir
            ),
            format!(
                "{}/../../target/bpfel-unknown-none/debug/kwall-ebpf",
                manifest_dir
            ),
        ];

        let found_path = candidate_paths.iter().find(|p| Path::new(p).exists());
        if let Some(path) = found_path {
            let report =
                BpfConformanceVerifier::verify_file(path).expect("Failed to parse KWALL eBPF ELF");

            assert!(report.is_valid, "Verifier errors: {:?}", report.errors);
            assert_eq!(report.programs.len(), 3);
            assert_eq!(report.maps.len(), 8);

            // Instructions per program must be well under 1,000,000
            for prog in &report.programs {
                assert!(prog.instruction_count > 0);
                assert!(prog.instruction_count < 1_000);
            }
        }
    }
}
