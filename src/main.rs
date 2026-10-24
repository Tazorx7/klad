// CLI entry point and coordination

mod models;
mod scanner;

use clap::{Parser, ValueEnum};
use comfy_table::{Cell, Color, Row, Table};
use models::report::{Finding, Report, Severity};
use scanner::scan_path;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "klad",
    version = "0.1.0",
    author = "Tazorx7",
    about = "A lightning-fast infrastructure and container security auditor.",
    long_about = None
)]
struct Args {
    /// Path to the target directory or file to scan
    #[arg(short, long, default_value = ".")]
    path: PathBuf,

    /// Output format (table, json, sarif)
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
    output: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long)]
    output_file: Option<PathBuf>,

    /// Minimum severity to fail on
    #[arg(long, value_enum)]
    severity_threshold: Option<SeverityThreshold>,

    /// Exit code to use when failures are found
    #[arg(long, default_value_t = 1)]
    exit_code: u8,

    /// Ignore file path (defaults to .kladignore if present)
    #[arg(long)]
    ignore_file: Option<PathBuf>,

    /// Baseline report (JSON) to diff against - only fail on new findings
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OutputFormat {
    Table,
    Json,
    Sarif,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SeverityThreshold {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityThreshold> for Severity {
    fn from(s: SeverityThreshold) -> Self {
        match s {
            SeverityThreshold::Info => Severity::Info,
            SeverityThreshold::Low => Severity::Low,
            SeverityThreshold::Medium => Severity::Medium,
            SeverityThreshold::High => Severity::High,
            SeverityThreshold::Critical => Severity::Critical,
        }
    }
}

#[derive(serde::Deserialize)]
struct BaselineReport {
    findings: Vec<Finding>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let mut report = Report::new(args.path.to_string_lossy().into_owned());

    // Single traversal + parallel scan
    report.add_findings(scan_path(&args.path));
    report.sort();

    // Apply ignore rules
    let ignore_path = args.ignore_file.clone().unwrap_or_else(|| PathBuf::from(".kladignore"));
    if ignore_path.exists() {
        if let Ok(content) = fs::read_to_string(&ignore_path) {
            let ignore_rules: Vec<String> = content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .map(|l| l.trim().to_string())
                .collect();
            report.findings.retain(|f| {
                for rule in &ignore_rules {
                    if let Some(rule_id) = rule.strip_prefix("rule:") {
                        if f.rule_id == rule_id.trim() {
                            return false;
                        }
                    } else if let Some(pattern) = rule.strip_prefix("file:") {
                        if f.file_path.contains(pattern.trim()) {
                            return false;
                        }
                    } else if f.file_path.contains(rule.as_str()) || f.rule_id == rule.as_str() {
                        return false;
                    }
                }
                true
            });
        }
    }

    // Apply baseline diff
    let mut findings_to_report = report.findings.clone();
    if let Some(baseline_path) = &args.baseline {
        if baseline_path.exists() {
            if let Ok(content) = fs::read_to_string(baseline_path) {
                if let Ok(baseline) = serde_json::from_str::<BaselineReport>(&content) {
                    let mut baseline_keys = HashSet::new();
                    for f in &baseline.findings {
                        let key = format!(
                            "{}:{}:{}:{}",
                            f.rule_id,
                            f.file_path,
                            f.line_number.unwrap_or(usize::MAX),
                            f.title
                        );
                        baseline_keys.insert(key);
                    }
                    findings_to_report.retain(|f| {
                        let key = format!(
                            "{}:{}:{}:{}",
                            f.rule_id,
                            f.file_path,
                            f.line_number.unwrap_or(usize::MAX),
                            f.title
                        );
                        !baseline_keys.contains(&key)
                    });
                }
            }
        }
    }

    let output = match args.output {
        OutputFormat::Table => format_table(&findings_to_report, !args.no_color),
        OutputFormat::Json => {
            let temp_report = Report {
                target_path: report.target_path.clone(),
                findings: findings_to_report.clone(),
            };
            match serde_json::to_string_pretty(&temp_report) {
                Ok(json) => json,
                Err(err) => {
                    eprintln!("klad: failed to serialize report: {err}");
                    return ExitCode::from(2);
                }
            }
        }
        OutputFormat::Sarif => generate_sarif(&findings_to_report, &report.target_path),
    };

    if let Some(out_path) = &args.output_file {
        if let Err(err) = fs::write(out_path, &output) {
            eprintln!("klad: failed to write output: {err}");
            return ExitCode::from(2);
        }
    } else {
        println!("{output}");
    }

    // Determine if we should fail
    let threshold = args
        .severity_threshold
        .clone()
        .map(Severity::from)
        .unwrap_or(Severity::High);

    let should_fail = findings_to_report
        .iter()
        .any(|f| f.severity >= threshold);

    if should_fail {
        ExitCode::from(args.exit_code)
    } else {
        ExitCode::SUCCESS
    }
}

fn format_table(findings: &[Finding], use_color: bool) -> String {
    if findings.is_empty() {
        return "\n[+] Success! No security findings detected.\n".to_string();
    }

    let mut output = format!("\n[!] Klad found {} security finding(s):\n\n", findings.len());

    let mut table = Table::new();
    table.set_header(vec![
        "Severity",
        "Rule ID",
        "File",
        "Line",
        "Title",
        "Remediation",
    ]);

    for finding in findings {
        let severity_cell = if use_color {
            match finding.severity {
                Severity::Critical => Cell::new(finding.severity.to_string()).fg(Color::Red),
                Severity::High => Cell::new(finding.severity.to_string()).fg(Color::Red),
                Severity::Medium => Cell::new(finding.severity.to_string()).fg(Color::Yellow),
                Severity::Low => Cell::new(finding.severity.to_string()).fg(Color::Blue),
                Severity::Info => Cell::new(finding.severity.to_string()).fg(Color::Cyan),
            }
        } else {
            Cell::new(finding.severity.to_string())
        };

        let line_str = finding
            .line_number
            .map_or("N/A".to_string(), |l| l.to_string());

        table.add_row(Row::from(vec![
            severity_cell,
            Cell::new(&finding.rule_id),
            Cell::new(&finding.file_path),
            Cell::new(line_str),
            Cell::new(&finding.title),
            Cell::new(&finding.remediation),
        ]));
    }

    output.push_str(&format!("{table}\n"));
    output
}

fn generate_sarif(findings: &[Finding], _target: &str) -> String {
    let mut results = Vec::new();
    for finding in findings {
        let level = match finding.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        };

        let line = finding.line_number.unwrap_or(1);
        let result = serde_json::json!({
            "ruleId": finding.rule_id,
            "level": level,
            "message": {
                "text": format!("{}: {}", finding.title, finding.description)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path
                    },
                    "region": {
                        "startLine": line
                    }
                }
            }],
            "fixes": [{
                "description": {
                    "text": finding.remediation
                }
            }]
        });
        results.push(result);
    }

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "klad",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/tazorx7/klad",
                    "rules": []
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}
