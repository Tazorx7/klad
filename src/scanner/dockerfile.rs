//! Dockerfile misconfiguration scanner.

use crate::models::report::{Finding, Severity};
use std::mem;
use std::path::Path;

/// Matches `Dockerfile`, `Dockerfile.prod`, `app.dockerfile`, `dev.Dockerfile`
/// and the Podman equivalent `Containerfile[.*]`.
pub fn is_dockerfile(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();

    // Never treat documentation as Dockerfiles.
    for ext in &[".md", ".txt", ".rst", ".adoc"] {
        if name.ends_with(ext) {
            return false;
        }
    }

    if name == "dockerfile" || name == "containerfile" {
        return true;
    }
    if name.ends_with(".dockerfile") || name.ends_with(".containerfile") {
        return true;
    }
    if let Some(rest) = name.strip_prefix("dockerfile.") {
        if rest.is_empty() {
            return false;
        }
        if let Some(ext) = rest.rsplit('.').next() {
            if ["md", "txt", "rst", "adoc", "json", "yaml", "yml"].contains(&ext) {
                return false;
            }
        }
        return rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    }
    if let Some(rest) = name.strip_prefix("containerfile.") {
        if rest.is_empty() {
            return false;
        }
        if let Some(ext) = rest.rsplit('.').next() {
            if ["md", "txt", "rst", "adoc", "json", "yaml", "yml"].contains(&ext) {
                return false;
            }
        }
        return rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    }

    false
}

/// Scan an already-read Dockerfile.
pub fn scan(path: &Path, content: &str) -> Vec<Finding> {
    let file = path.to_string_lossy().into_owned();
    let mut findings = Vec::new();

    // `USER` from an earlier build stage must not satisfy the final stage.
    let mut stage_has_user = false;

    for line in logical_lines(content) {
        let parts: Vec<&str> = line.text.split_whitespace().collect();
        let Some(command) = parts.first() else {
            continue;
        };

        match command.to_ascii_uppercase().as_str() {
            "FROM" => {
                stage_has_user = false;
                if let Some(f) = check_base_image(&parts, &file, line.number) {
                    findings.push(f);
                }
            }

            "USER" => {
                stage_has_user = true;
                if let Some(user) = parts.get(1) {
                    let account = user.split(':').next().unwrap_or(user);
                    if account.eq_ignore_ascii_case("root") || account == "0" {
                        findings.push(finding(
                            "DF-001",
                            Severity::High,
                            &file,
                            Some(line.number),
                            "This container runs as root user",
                            "Running containers as root can lead to privilege escalation and security vulnerabilities.",
                            "Use a non-root user in your Dockerfile by adding a USER instruction with a non-root user (e.g. USER app).",
                        ));
                    }
                }
            }

            "COPY" | "ADD" => {
                // Broad build-context copy: any source argument that is ".".
                // The last argument is the destination, so exclude it.
                let args: Vec<&str> = parts
                    .iter()
                    .skip(1)
                    .filter(|arg| !arg.starts_with("--"))
                    .copied()
                    .collect();

                if args.len() >= 2 {
                    let (sources, _destination) = args.split_at(args.len() - 1);
                    if sources.iter().any(|src| *src == ".") {
                        findings.push(finding(
                            "DF-003",
                            Severity::Low,
                            &file,
                            Some(line.number),
                            "Broad Build Context Copy",
                            "Using '.' as the source in COPY or ADD instructions pulls in the whole build context, which can accidentally include secrets or cache files.",
                            "Copy only the necessary files and add a strict .dockerignore.",
                        ));
                    }
                }
            }

            _ => {}
        }
    }

    if !stage_has_user {
        findings.push(finding(
            "DF-001",
            Severity::High,
            &file,
            None,
            "Missing Non-Root User Instruction",
            "No USER instruction found in the final build stage. The container runs as root by default.",
            "Add a non-root user near the end of the Dockerfile.",
        ));
    }

    findings
}

/// Analyse the `FROM` instruction of a logical line.
///
/// Kept separate from `scan` so the stage bookkeeping stays readable.
fn check_base_image(parts: &[&str], file: &str, line: usize) -> Option<Finding> {
    // Skip flags such as `--platform=linux/amd64`, then take the image.
    let image = parts.iter().skip(1).find(|arg| !arg.starts_with("--"))?;

    if is_pinned(image) {
        return None;
    }

    Some(finding(
        "DF-002",
        Severity::Medium,
        file,
        Some(line),
        "Using 'latest', 'edge' or an unpinned base image",
        &format!(
            "Image '{image}' is not pinned to an immutable reference. This can cause unpredictable builds and silently pull in vulnerable updates."
        ),
        "Pin the base image to a specific version and digest, e.g. `FROM ubuntu:24.04@sha256:...`.",
    ))
}

fn is_pinned(image: &str) -> bool {
    if image.contains('@') {
        return true; // digest-pinned
    }
    let image = image.split('@').next().unwrap_or(image);
    // `scratch` is a special minimal base image.
    let base = image.rsplit('/').next().unwrap_or(image);
    if base.eq_ignore_ascii_case("scratch") {
        return true;
    }
    // A tag is the last ':' that appears after the last '/'.
    let last_slash = image.rfind('/').map_or(0, |i| i + 1);
    match image[last_slash..].rfind(':') {
        Some(idx) => {
            let tag = &image[last_slash + idx + 1..];
            !tag.is_empty()
                && !tag.eq_ignore_ascii_case("latest")
                && !tag.eq_ignore_ascii_case("edge")
        }
        None => false,
    }
}

struct LogicalLine {
    /// 1-based line number where the instruction starts.
    number: usize,
    text: String,
}

/// Join backslash-continued lines and drop comments/blank lines, so
/// `RUN a \` + `&& b` is parsed as one instruction instead of three.
fn logical_lines(content: &str) -> Vec<LogicalLine> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 0;

    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if buf.is_empty() {
            start = idx + 1;
        }

        match line.strip_suffix('\\') {
            Some(rest) => {
                buf.push_str(rest.trim_end());
                buf.push(' ');
            }
            None => {
                buf.push_str(line);
                if !buf.trim().is_empty() {
                    out.push(LogicalLine {
                        number: start,
                        text: mem::take(&mut buf),
                    });
                } else {
                    buf.clear();
                }
            }
        }
    }

    if !buf.trim().is_empty() {
        out.push(LogicalLine {
            number: start,
            text: buf,
        });
    }

    out
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule_id: &str,
    severity: Severity,
    file: &str,
    line_number: Option<usize>,
    title: &str,
    description: &str,
    remediation: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        file_path: file.to_string(),
        line_number,
        title: title.to_string(),
        description: description.to_string(),
        remediation: remediation.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn matches_common_dockerfile_names() {
        for name in [
            "Dockerfile",
            "Dockerfile.prod",
            "Dockerfile.dev",
            "api.dockerfile",
            "dev.Dockerfile",
            "Containerfile",
        ] {
            assert!(
                is_dockerfile(Path::new("/repo").join(name).as_path()),
                "expected {name} to be scanned"
            );
        }
        assert!(!is_dockerfile(Path::new("docker-compose.yml")));
        assert!(!is_dockerfile(Path::new("Dockerfile.md")));
    }

    #[test]
    fn flags_unpinned_and_root() {
        let findings = scan(Path::new("Dockerfile"), "FROM ubuntu:latest\nUSER root:root\n");
        assert!(ids(&findings).contains(&"DF-002"));
        assert!(ids(&findings).contains(&"DF-001"));
        // explicit root + no missing-user finding duplicate
        assert_eq!(ids(&findings).iter().filter(|id| **id == "DF-001").count(), 1);
    }

    #[test]
    fn digest_pin_and_non_root_is_clean() {
        let content = "FROM ubuntu@sha256:abc123\nUSER app\n";
        assert!(scan(Path::new("Dockerfile"), content).is_empty());
    }

    #[test]
    fn only_the_final_stage_needs_a_user() {
        let content = "\
FROM rust:1 AS build
USER builder
RUN cargo build

FROM debian:bookworm
COPY --from=build /app /app
";
        let findings = scan(Path::new("Dockerfile"), content);
        assert_eq!(ids(&findings), vec!["DF-001"]);
        assert_eq!(findings[0].line_number, None);
    }

    #[test]
    fn ignores_root_copy_when_destination_only() {
        assert!(scan(Path::new("Dockerfile"), "FROM scratch\nUSER app\nCOPY app .\n").is_empty());
        assert_eq!(
            ids(&scan(
                Path::new("Dockerfile"),
                "FROM scratch\nUSER app\nCOPY . .\n"
            )),
            vec!["DF-003"]
        );
    }

    #[test]
    fn handles_line_continuations() {
        let content = "\
FROM debian:12
USER app
RUN apt-get update \\
    && apt-get install -y curl
";
        let findings = scan(Path::new("Dockerfile"), content);
        assert!(findings.is_empty(), "continuation produced bogus findings");
    }
}
