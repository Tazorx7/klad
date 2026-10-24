//! Scanner orchestration: discover once, read once per file, dispatch in parallel.

use crate::models::report::Finding;
use rayon::prelude::*;
use std::fs;
use std::path::Path;

pub mod discovery;
pub mod dockerfile;
pub mod k8s;
pub mod secrets;

/// Files larger than this are skipped to avoid reading multi-megabyte build logs
/// or vendored dumps into memory. Secret and misconfiguration scanning still
/// applies to everything under the cap.
const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

/// Walk `target` once, scan files in parallel, and return every finding.
/// Order is undefined here; callers must `sort()` the report for stable output.
pub fn scan_path(target: &Path) -> Vec<Finding> {
    let files = discovery::discover(target);
    files
        .par_iter()
        .flat_map_iter(|path| scan_file(path))
        .collect()
}

fn scan_file(path: &Path) -> Vec<Finding> {
    let Ok(metadata) = fs::metadata(path) else {
        return Vec::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_SCAN_BYTES {
        return Vec::new();
    }

    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    if is_binary(&bytes) {
        return Vec::new();
    }

    let mut findings = Vec::new();

    if dockerfile::is_dockerfile(path) {
        // Dockerfiles are short and always worth parsing even if they contain
        // unusual bytes; use lossy conversion to be defensive.
        let text = String::from_utf8_lossy(&bytes);
        findings.extend(dockerfile::scan(path, &text));
    }

    if k8s::is_candidate(path) {
        let text = String::from_utf8_lossy(&bytes);
        findings.extend(k8s::scan(path, &text));
    }

    if secrets::is_candidate(path) {
        findings.extend(secrets::scan(path, &bytes));
    }

    findings
}

fn is_binary(bytes: &[u8]) -> bool {
    let probe_len = bytes.len().min(8192);
    bytes[..probe_len].contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_probe() {
        assert!(!is_binary(b"hello\nworld\n"));
        assert!(is_binary(b"ELF\0\x01\x02"));
    }
}
