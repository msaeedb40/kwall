//! SBOM ingestion, CycloneDX and SPDX specification parsing, and in-memory workload cataloging.
//!
//! Extracts declared package components, binary filesystem locations, and cryptographic hashes
//! to construct the authoritative workload baseline.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors occurring during SBOM document ingestion and parsing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SbomParseError {
    #[error("Failed to parse JSON content: {0}")]
    JsonError(String),
    #[error("Unrecognized or unsupported SBOM format")]
    UnsupportedFormat,
    #[error("Empty or invalid components list")]
    EmptyComponents,
}

/// Supported SBOM standard formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

/// Extracted component/package definition from an SBOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomComponent {
    /// Package or binary name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Standard Package URL (PURL), if provided.
    pub purl: Option<String>,
    /// Associated executable or library filesystem paths.
    pub file_paths: Vec<String>,
    /// Cryptographic checksums (e.g. "SHA-256" -> "abcdef...").
    pub hashes: HashMap<String, String>,
}

/// Standardized in-memory representation of an ingested SBOM document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomDocument {
    pub format: SbomFormat,
    pub spec_version: String,
    pub serial_number: Option<String>,
    pub components: Vec<SbomComponent>,
}

/// CycloneDX JSON Schema structures.
#[derive(Deserialize)]
#[allow(dead_code)]
struct CycloneDxJson {
    #[serde(rename = "bomFormat")]
    bom_format: Option<String>,
    #[serde(rename = "specVersion")]
    spec_version: Option<String>,
    #[serde(rename = "serialNumber")]
    serial_number: Option<String>,
    components: Option<Vec<CycloneDxComponent>>,
}

#[derive(Deserialize)]
struct CycloneDxComponent {
    name: String,
    version: Option<String>,
    purl: Option<String>,
    properties: Option<Vec<CycloneDxProperty>>,
    hashes: Option<Vec<CycloneDxHash>>,
}

#[derive(Deserialize)]
struct CycloneDxProperty {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct CycloneDxHash {
    alg: String,
    content: String,
}

/// SPDX JSON Schema structures.
#[derive(Deserialize)]
struct SpdxJson {
    #[serde(rename = "spdxVersion")]
    spdx_version: Option<String>,
    packages: Option<Vec<SpdxPackage>>,
    files: Option<Vec<SpdxFile>>,
}

#[derive(Deserialize)]
struct SpdxPackage {
    name: String,
    #[serde(rename = "versionInfo")]
    version_info: Option<String>,
    #[serde(rename = "packageFileName")]
    package_file_name: Option<String>,
    checksums: Option<Vec<SpdxChecksum>>,
}

#[derive(Deserialize)]
struct SpdxFile {
    #[serde(rename = "fileName")]
    file_name: String,
    checksums: Option<Vec<SpdxChecksum>>,
}

#[derive(Deserialize)]
struct SpdxChecksum {
    algorithm: String,
    #[serde(rename = "checksumValue")]
    checksum_value: String,
}

/// Parser for CycloneDX and SPDX SBOM files.
pub struct SbomParser;

impl SbomParser {
    /// Automatically detects format and parses an SBOM string.
    pub fn parse(content: &str) -> Result<SbomDocument, SbomParseError> {
        let val: serde_json::Value =
            serde_json::from_str(content).map_err(|e| SbomParseError::JsonError(e.to_string()))?;

        if val.get("bomFormat").is_some() || val.get("components").is_some() {
            Self::parse_cyclonedx(content)
        } else if val.get("spdxVersion").is_some() || val.get("packages").is_some() {
            Self::parse_spdx(content)
        } else {
            Err(SbomParseError::UnsupportedFormat)
        }
    }

    /// Parses a CycloneDX JSON document.
    pub fn parse_cyclonedx(content: &str) -> Result<SbomDocument, SbomParseError> {
        let doc: CycloneDxJson =
            serde_json::from_str(content).map_err(|e| SbomParseError::JsonError(e.to_string()))?;

        let spec_version = doc.spec_version.unwrap_or_else(|| "1.5".to_string());
        let raw_components = doc.components.unwrap_or_default();
        let mut components = Vec::with_capacity(raw_components.len());

        for c in raw_components {
            let mut file_paths = Vec::new();
            if let Some(props) = c.properties {
                for p in props {
                    if p.name == "kwall:file_path"
                        || p.name.contains("path")
                        || p.name.contains("file")
                    {
                        file_paths.push(p.value);
                    }
                }
            }

            // Always add default standard binary paths matching the component name
            let comp_name = &c.name;
            file_paths.push(format!("/bin/{comp_name}"));
            file_paths.push(format!("/usr/bin/{comp_name}"));
            file_paths.push(format!("/usr/local/bin/{comp_name}"));

            let mut hashes = HashMap::new();
            if let Some(h_list) = c.hashes {
                for h in h_list {
                    hashes.insert(h.alg.to_ascii_uppercase(), h.content.to_ascii_lowercase());
                }
            }

            components.push(SbomComponent {
                name: c.name,
                version: c.version.unwrap_or_else(|| "unknown".to_string()),
                purl: c.purl,
                file_paths,
                hashes,
            });
        }

        Ok(SbomDocument {
            format: SbomFormat::CycloneDx,
            spec_version,
            serial_number: doc.serial_number,
            components,
        })
    }

    /// Parses an SPDX JSON document.
    pub fn parse_spdx(content: &str) -> Result<SbomDocument, SbomParseError> {
        let doc: SpdxJson =
            serde_json::from_str(content).map_err(|e| SbomParseError::JsonError(e.to_string()))?;

        let spec_version = doc.spdx_version.unwrap_or_else(|| "SPDX-2.3".to_string());
        let mut components = Vec::new();

        if let Some(packages) = doc.packages {
            for pkg in packages {
                let mut file_paths = Vec::new();
                if let Some(pfn) = pkg.package_file_name {
                    file_paths.push(pfn);
                }
                file_paths.push(format!("/bin/{}", pkg.name));
                file_paths.push(format!("/usr/bin/{}", pkg.name));

                let mut hashes = HashMap::new();
                if let Some(c_list) = pkg.checksums {
                    for c in c_list {
                        hashes.insert(
                            c.algorithm.to_ascii_uppercase(),
                            c.checksum_value.to_ascii_lowercase(),
                        );
                    }
                }

                components.push(SbomComponent {
                    name: pkg.name,
                    version: pkg.version_info.unwrap_or_else(|| "unknown".to_string()),
                    purl: None,
                    file_paths,
                    hashes,
                });
            }
        }

        if let Some(files) = doc.files {
            for f in files {
                let mut hashes = HashMap::new();
                if let Some(c_list) = f.checksums {
                    for c in c_list {
                        hashes.insert(
                            c.algorithm.to_ascii_uppercase(),
                            c.checksum_value.to_ascii_lowercase(),
                        );
                    }
                }
                components.push(SbomComponent {
                    name: f.file_name.clone(),
                    version: "1.0.0".to_string(),
                    purl: None,
                    file_paths: vec![f.file_name],
                    hashes,
                });
            }
        }

        Ok(SbomDocument {
            format: SbomFormat::Spdx,
            spec_version,
            serial_number: None,
            components,
        })
    }
}

/// Baseline profile cataloging approved executables for a container or workload.
#[derive(Debug, Clone, Default)]
pub struct WorkloadSbomProfile {
    pub approved_paths: HashSet<String>,
    pub approved_binary_names: HashSet<String>,
    pub path_to_hashes: HashMap<String, String>,
}

/// In-memory catalog maintaining approved workload SBOM baselines.
pub struct SbomCatalog {
    profiles: RwLock<HashMap<String, WorkloadSbomProfile>>,
}

impl Default for SbomCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomCatalog {
    /// Creates a new empty SbomCatalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: RwLock::new(HashMap::new()),
        }
    }

    /// Registers an ingested SBOM document for a workload/container ID.
    pub fn register_sbom(&self, workload_id: &str, sbom: &SbomDocument) {
        let mut profile = WorkloadSbomProfile::default();

        // Standard Linux runtime primitives always allowed in container execution
        const ESSENTIAL_PRIMITIVES: &[&str] = &[
            "/bin/sh",
            "/bin/bash",
            "/bin/dash",
            "/usr/bin/env",
            "/bin/busybox",
        ];
        for &prim in ESSENTIAL_PRIMITIVES {
            profile.approved_paths.insert(prim.to_string());
            if let Some(name) = prim.rsplit('/').next() {
                profile.approved_binary_names.insert(name.to_string());
            }
        }

        for comp in &sbom.components {
            profile.approved_binary_names.insert(comp.name.clone());
            for path in &comp.file_paths {
                profile.approved_paths.insert(path.clone());
                if let Some(hash) = comp
                    .hashes
                    .get("SHA-256")
                    .or_else(|| comp.hashes.get("SHA256"))
                {
                    profile.path_to_hashes.insert(path.clone(), hash.clone());
                }
            }
        }

        let mut profiles = self.profiles.write().unwrap();
        profiles.insert(workload_id.to_string(), profile);
    }

    /// Checks if a binary path is approved for a given workload.
    #[must_use]
    pub fn is_binary_approved(&self, workload_id: &str, path: &str) -> bool {
        let profiles = self.profiles.read().unwrap();
        if let Some(profile) = profiles.get(workload_id) {
            if profile.approved_paths.contains(path) {
                return true;
            }
            if let Some(base_name) = path.rsplit('/').next() {
                if profile.approved_binary_names.contains(base_name) {
                    return true;
                }
            }
            false
        } else {
            // If no SBOM profile is registered yet for this workload, fail-open to avoid false positives
            true
        }
    }

    /// Retrieves expected SHA-256 hash for a binary path, if declared in SBOM.
    #[must_use]
    pub fn get_expected_hash(&self, workload_id: &str, path: &str) -> Option<String> {
        let profiles = self.profiles.read().unwrap();
        profiles
            .get(workload_id)
            .and_then(|p| p.path_to_hashes.get(path).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cyclonedx_json() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "components": [
                {
                    "name": "curl",
                    "version": "7.88.1",
                    "purl": "pkg:apk/alpine/curl@7.88.1",
                    "properties": [
                        { "name": "kwall:file_path", "value": "/usr/bin/curl" }
                    ],
                    "hashes": [
                        { "alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
                    ]
                }
            ]
        }"#;

        let sbom = SbomParser::parse(json).expect("CycloneDX should parse cleanly");
        assert_eq!(sbom.format, SbomFormat::CycloneDx);
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "curl");
        assert!(sbom.components[0]
            .file_paths
            .contains(&"/usr/bin/curl".to_string()));

        let catalog = SbomCatalog::new();
        catalog.register_sbom("container-123", &sbom);

        assert!(catalog.is_binary_approved("container-123", "/usr/bin/curl"));
        assert!(catalog.is_binary_approved("container-123", "/bin/sh"));
        assert!(!catalog.is_binary_approved("container-123", "/tmp/xmrig"));
        assert_eq!(
            catalog
                .get_expected_hash("container-123", "/usr/bin/curl")
                .as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn test_parse_spdx_json() {
        let json = r#"{
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "openssl",
                    "versionInfo": "3.0.8",
                    "packageFileName": "/usr/bin/openssl",
                    "checksums": [
                        { "algorithm": "SHA256", "checksumValue": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
                    ]
                }
            ]
        }"#;

        let sbom = SbomParser::parse(json).expect("SPDX should parse cleanly");
        assert_eq!(sbom.format, SbomFormat::Spdx);
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "openssl");
    }
}
