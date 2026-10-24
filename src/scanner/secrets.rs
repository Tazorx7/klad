//! Hardcoded secret scanner.
//!
//! Rather than running three regexes against every line, a single
//! Aho-Corasick automaton finds candidate lines first. Regex confirmation only
//! runs for lines that contain a relevant literal, which is dramatically
//! cheaper on large repositories and avoids most false positives up front.

use crate::models::report::{Finding, Severity};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::bytes::Regex;
use std::path::Path;
use std::sync::OnceLock;

struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    /// Regex confirmation, applied to raw bytes (no UTF-8 requirement).
    pattern: Regex,
}

struct Ruleset {
    automaton: AhoCorasick,
    rules: Vec<Rule>,
    /// Aho-Corasick pattern index -> the rules it can trigger.
    pattern_rules: Vec<Vec<usize>>,
}

/// Lock files and minified bundles are full of high-entropy strings that are
/// not credentials.
const SKIP_NAMES: &[&str] = &[
    "cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "pipfile.lock",
    "poetry.lock",
    "composer.lock",
    "gemfile.lock",
];

pub fn is_candidate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();

    !SKIP_NAMES.contains(&name.as_str())
        && !name.ends_with(".lock")
        && !name.ends_with(".min.js")
        && !name.ends_with(".map")
}

/// Scan an already-read file.
pub fn scan(path: &Path, content: &[u8]) -> Vec<Finding> {
    let ruleset = ruleset();
    let file = path.to_string_lossy();
    let mut findings = Vec::new();

    for (line_index, line) in content.split(|&byte| byte == b'\n').enumerate() {
        let mut matched: u32 = 0;

        for occurrence in ruleset.automaton.find_iter(line) {
            let pattern = occurrence.pattern().as_usize();

            for &rule_index in &ruleset.pattern_rules[pattern] {
                let bit = 1u32 << rule_index;
                if matched & bit != 0 {
                    continue;
                }

                let rule = &ruleset.rules[rule_index];
                if rule.pattern.is_match(line) {
                    matched |= bit;
                    findings.push(Finding {
                        rule_id: rule.id.to_string(),
                        severity: rule.severity,
                        file_path: file.to_string(),
                        line_number: Some(line_index + 1),
                        title: rule.title.to_string(),
                        description: format!(
                            "Potential hardcoded secret detected on line {}.",
                            line_index + 1
                        ),
                        remediation: "Remove the secret, rotate it immediately, and load it from an environment variable or secret manager.".to_string(),
                    });
                }
            }

            // Every rule already fired on this line; nothing left to confirm.
            if matched.count_ones() as usize == ruleset.rules.len() {
                break;
            }
        }
    }

    findings
}

fn ruleset() -> &'static Ruleset {
    static RULESET: OnceLock<Ruleset> = OnceLock::new();
    RULESET.get_or_init(build_ruleset)
}

fn build_ruleset() -> Ruleset {
    // (id, title, severity, prefilter literals, confirming regex)
    //
    // Literals are matched case-insensitively; the regexes decide whether the
    // match is a real candidate.
    let definitions: &[(&str, &str, Severity, &[&str], &str)] = &[
        (
            "SEC-001",
            "AWS Access Key ID",
            Severity::Critical,
            &["AKIA", "ASIA"],
            r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        ),
        (
            "SEC-002",
            "Private Key",
            Severity::Critical,
            &["-----BEGIN "],
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY",
        ),
        (
            "SEC-003",
            "Generic API Token/Secret",
            Severity::High,
            &[
                "api_key",
                "api-key",
                "apikey",
                "access_token",
                "access-token",
                "secret_key",
                "secret-key",
                "client_secret",
                "auth_token",
            ],
            r#"(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-./+=]{16,}['"]?"#,
        ),
    ];

    let mut rules = Vec::with_capacity(definitions.len());
    let mut patterns = Vec::new();
    let mut pattern_rules = Vec::new();

    for (index, (id, title, severity, literals, regex)) in definitions.iter().enumerate() {
        let pattern = Regex::new(regex)
            .unwrap_or_else(|err| panic!("invalid secret rule {id}: {err}"));
        rules.push(Rule {
            id,
            title,
            severity: *severity,
            pattern,
        });

        for literal in *literals {
            patterns.push(*literal);
            pattern_rules.push(vec![index]);
        }
    }

    assert!(
        rules.len() <= 32,
        "the per-line bitmask only supports 32 rules"
    );

    let automaton = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(&patterns)
        .expect("failed to build secret prefilter");

    Ruleset {
        automaton,
        rules,
        pattern_rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn finds_aws_key_and_private_key() {
        let content = b"aws = AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\n";
        let findings = scan(Path::new("creds.txt"), content);
        assert!(ids(&findings).contains(&"SEC-001"), "{findings:?}");
        assert!(ids(&findings).contains(&"SEC-002"), "{findings:?}");
    }

    #[test]
    fn finds_generic_token_and_reports_line() {
        let content = b"line one\napi_key = \"abcdefghijklmnopqrstuvwxyz\"\n";
        let findings = scan(Path::new("config.py"), content);
        assert_eq!(ids(&findings), vec!["SEC-003"]);
        assert_eq!(findings[0].line_number, Some(2));
    }

    #[test]
    fn ignores_prose_and_short_values() {
        let content = b"documentation about api_key naming conventions\napi_key = short\n";
        assert!(scan(Path::new("README.md"), content).is_empty());
    }

    #[test]
    fn reports_each_rule_once_per_line() {
        let line = b"api_key = AKIAIOSFODNN7EXAMPLE";
        let findings = scan(Path::new("x"), line);
        assert_eq!(findings.len(), 2); // SEC-001 + SEC-003, not duplicated
    }

    #[test]
    fn skips_lockfiles() {
        assert!(!is_candidate(Path::new("Cargo.lock")));
        assert!(!is_candidate(Path::new("app.min.js")));
        assert!(is_candidate(Path::new(".env")));
        assert!(is_candidate(Path::new("config.yaml")));
    }
}
