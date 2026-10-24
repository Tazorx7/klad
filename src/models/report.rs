use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: Option<usize>,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub target_path: String,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(target_path: String) -> Self {
        Report {
            target_path,
            findings: Vec::new(),
        }
    }

    pub fn add_findings(&mut self, findings: impl IntoIterator<Item = Finding>) {
        self.findings.extend(findings);
    }

    /// Deterministic ordering: severity (highest first), then location.
    ///
    /// Findings are produced from a parallel scan, so without this the output
    /// order changes between runs and breaks CI diffing / baselines.
    pub fn sort(&mut self) {
        self.findings.sort_by(compare_findings);
    }

    #[allow(dead_code)]
    pub fn has_blockages(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= Severity::High)
    }
}

fn compare_findings(a: &Finding, b: &Finding) -> Ordering {
    b.severity
        .cmp(&a.severity)
        .then_with(|| a.file_path.cmp(&b.file_path))
        .then_with(|| {
            a.line_number
                .unwrap_or(usize::MAX)
                .cmp(&b.line_number.unwrap_or(usize::MAX))
        })
        .then_with(|| a.rule_id.cmp(&b.rule_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, severity: Severity, file: &str, line: Option<usize>) -> Finding {
        Finding {
            rule_id: rule.into(),
            severity,
            file_path: file.into(),
            line_number: line,
            title: String::new(),
            description: String::new(),
            remediation: String::new(),
        }
    }

    #[test]
    fn sorts_by_severity_then_location() {
        let mut report = Report::new(".".into());
        report.add_findings([
            finding("B", Severity::Low, "b.rs", Some(2)),
            finding("A", Severity::Critical, "b.rs", Some(9)),
            finding("C", Severity::High, "a.rs", None),
            finding("D", Severity::Critical, "a.rs", Some(4)),
        ]);
        report.sort();

        let order: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.file_path.as_str(), f.line_number))
            .collect();
        assert_eq!(
            order,
            vec![
                ("D", "a.rs", Some(4)),
                ("A", "b.rs", Some(9)),
                ("C", "a.rs", None),
                ("B", "b.rs", Some(2)),
            ]
        );
    }
}
