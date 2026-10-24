//! Kubernetes manifest scanner.
//!
//! Security context settings are inherited: a value on the container
//! overrides the pod-level value, which overrides the Kubernetes default.
//! Ignoring that inheritance was the source of the previous false negatives.

use crate::models::report::{Finding, Severity};
use serde::Deserialize;
use serde_yaml::Value;
use std::path::Path;

pub fn is_candidate(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    )
}

/// Scan an already-read manifest.
pub fn scan(path: &Path, content: &str) -> Vec<Finding> {
    // Cheap prefilter: parsing every YAML file in a repo is wasteful when most
    // of them are CI config, Helm values, or OpenAPI specs.
    if memchr::memmem::find(content.as_bytes(), b"apiVersion").is_none() {
        return Vec::new();
    }

    let file = path.to_string_lossy().into_owned();
    let mut findings = Vec::new();

    for document in serde_yaml::Deserializer::from_str(content) {
        let Ok(value) = Value::deserialize(document) else {
            continue;
        };

        if value.get("apiVersion").is_none() || value.get("kind").is_none() {
            continue;
        }

        audit_document(&value, &file, &mut findings);
    }

    findings
}

fn audit_document(value: &Value, file: &str, out: &mut Vec<Finding>) {
    let Some(spec) = pod_spec(value) else {
        return;
    };

    let kind = value.get("kind").and_then(Value::as_str).unwrap_or("Unknown");
    let name = value
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unnamed");

    let pod_context = spec.get("securityContext");

    // --- Pod-level settings -------------------------------------------------
    for (key, rule_id, severity, title) in [
        (
            "hostNetwork",
            "K8S-009",
            Severity::High,
            "hostNetwork Enabled",
        ),
        ("hostPID", "K8S-010", Severity::High, "hostPID Enabled"),
        ("hostIPC", "K8S-011", Severity::High, "hostIPC Enabled"),
    ] {
        if spec.get(key).and_then(Value::as_bool) == Some(true) {
            push(
                out,
                rule_id,
                severity,
                file,
                title,
                format!(
                    "{kind} '{name}' sets '{key}: true', exposing the container to the host namespace."
                ),
                format!("Remove '{key}: true' unless strictly required, and isolate the workload."),
            );
        }
    }

    if let Some(volumes) = spec.get("volumes").and_then(Value::as_sequence) {
        for volume in volumes {
            if volume.get("hostPath").is_some() {
                let volume_name = volume
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed");
                push(
                    out,
                    "K8S-008",
                    Severity::High,
                    file,
                    "hostPath Volume Mounted",
                    format!(
                        "{kind} '{name}' mounts host path '{volume_name}' from the node filesystem."
                    ),
                    "Avoid hostPath volumes. Use a PersistentVolume, ConfigMap, or emptyDir instead.",
                );
            }
        }
    }

    // --- Containers ---------------------------------------------------------
    for (container_name, container) in containers(spec) {
        let container_id = format!("{kind} '{name}' (container: {container_name})");
        let context = container.get("securityContext");

        let privileged = inherited(pod_context, context, "privileged").and_then(Value::as_bool);
        if privileged == Some(true) {
            push(
                out,
                "K8S-001",
                Severity::Critical,
                file,
                "Privileged Container Enabled",
                format!(
                    "{container_id} has 'securityContext.privileged: true'. This grants root-level access to the host kernel."
                ),
                "Remove 'privileged: true' unless strictly necessary and grant specific Linux capabilities instead.",
            );
        }

        // Explicit root, whether set on the container or inherited from the pod.
        let run_as_user = inherited(pod_context, context, "runAsUser").and_then(Value::as_i64);
        let explicit_root = run_as_user == Some(0);
        if explicit_root {
            push(
                out,
                "K8S-002",
                Severity::High,
                file,
                "Container Explicitly Set to Root User",
                format!("{container_id} resolves to 'runAsUser: 0'."),
                "Run as an unprivileged UID (e.g. runAsUser: 1000) and set runAsNonRoot: true.",
            );
        }

        // K8S-004: no assurance that the process is non-root.
        // (Kubernetes defaults runAsNonRoot to false.)
        let run_as_non_root =
            inherited(pod_context, context, "runAsNonRoot").and_then(Value::as_bool);
        if run_as_non_root != Some(true) && !explicit_root {
            push(
                out,
                "K8S-004",
                Severity::Medium,
                file,
                "runAsNonRoot Not Enforced",
                format!("{container_id} does not enforce 'runAsNonRoot: true', so the image may start as root."),
                "Set 'securityContext.runAsNonRoot: true' (and ideally an explicit non-zero runAsUser).",
            );
        }

        // K8S-005: allowPrivilegeEscalation defaults to true.
        let allow_escalation =
            inherited(pod_context, context, "allowPrivilegeEscalation").and_then(Value::as_bool);
        if allow_escalation != Some(false) {
            push(
                out,
                "K8S-005",
                Severity::Medium,
                file,
                "allowPrivilegeEscalation Not Disabled",
                format!(
                    "{container_id} does not set 'allowPrivilegeEscalation: false' (the default is true)."
                ),
                "Set 'securityContext.allowPrivilegeEscalation: false'.",
            );
        }

        // K8S-006: writable root filesystem.
        let read_only =
            inherited(pod_context, context, "readOnlyRootFilesystem").and_then(Value::as_bool);
        if read_only != Some(true) {
            push(
                out,
                "K8S-006",
                Severity::Low,
                file,
                "Root Filesystem is Writable",
                format!("{container_id} does not set 'readOnlyRootFilesystem: true'."),
                "Set 'securityContext.readOnlyRootFilesystem: true' and mount writable volumes where needed.",
            );
        }

        // K8S-007: capabilities must be dropped explicitly.
        let drops_all = context
            .and_then(|c| c.get("capabilities"))
            .and_then(|c| c.get("drop"))
            .and_then(Value::as_sequence)
            .is_some_and(|drops| {
                drops.iter().any(|cap| {
                    cap.as_str()
                        .is_some_and(|cap| cap.eq_ignore_ascii_case("ALL"))
                })
            });
        if !drops_all {
            push(
                out,
                "K8S-007",
                Severity::Low,
                file,
                "Linux Capabilities Not Dropped",
                format!("{container_id} does not drop all Linux capabilities."),
                "Set 'securityContext.capabilities.drop: [\"ALL\"]' and add back only what is required.",
            );
        }

        // K8S-003: resource limits.
        if container
            .get("resources")
            .and_then(|r| r.get("limits"))
            .is_none()
        {
            push(
                out,
                "K8S-003",
                Severity::Medium,
                file,
                "Missing Resource Limits",
                format!(
                    "{container_id} does not define CPU/Memory limits, leaving the cluster vulnerable to resource exhaustion."
                ),
                "Define explicit 'resources.limits' and 'resources.requests' for memory and CPU.",
            );
        }
    }
}

/// Resolve a securityContext field the way Kubernetes does: container first,
/// then pod, then the built-in default.
fn inherited<'a>(
    pod_context: Option<&'a Value>,
    container_context: Option<&'a Value>,
    key: &str,
) -> Option<&'a Value> {
    container_context
        .and_then(|ctx| ctx.get(key))
        .or_else(|| pod_context.and_then(|ctx| ctx.get(key)))
}

/// Return the pod spec for the workload kinds we understand.
fn pod_spec(value: &Value) -> Option<&Value> {
    let kind = value.get("kind")?.as_str()?;
    let spec = value.get("spec")?;

    match kind {
        "Pod" => Some(spec),
        "CronJob" => spec
            .get("jobTemplate")?
            .get("spec")?
            .get("template")?
            .get("spec"),
        "List" => None,
        // Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, ...
        _ => spec.get("template")?.get("spec"),
    }
}

fn containers(spec: &Value) -> impl Iterator<Item = (String, &Value)> {
    let regular = spec
        .get("containers")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .map(|c| (container_name(c), c));

    let init = spec
        .get("initContainers")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .map(|c| (format!("init-{}", container_name(c)), c));

    regular.chain(init)
}

fn container_name(container: &Value) -> String {
    container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unnamed")
        .to_string()
}

#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<Finding>,
    rule_id: &str,
    severity: Severity,
    file: &str,
    title: &str,
    description: String,
    remediation: impl Into<String>,
) {
    out.push(Finding {
        rule_id: rule_id.to_string(),
        severity,
        file_path: file.to_string(),
        line_number: None,
        title: title.to_string(),
        description,
        remediation: remediation.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_str(content: &str) -> Vec<Finding> {
        scan(Path::new("pod.yaml"), content)
    }

    fn rule_ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    const POD_HEADER: &str = "\
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  containers:
    - name: app
      image: nginx:1.27
";

    #[test]
    fn flags_run_as_non_root_false() {
        let findings = scan_str(&format!(
            "{POD_HEADER}      securityContext:\n        runAsNonRoot: false\n"
        ));
        assert!(
            rule_ids(&findings).contains(&"K8S-004"),
            "runAsNonRoot: false must be reported, got {:?}",
            rule_ids(&findings)
        );
    }

    #[test]
    fn flags_missing_security_context() {
        let findings = scan_str(POD_HEADER);
        assert!(rule_ids(&findings).contains(&"K8S-004"));
    }

    #[test]
    fn inherits_pod_level_security_context() {
        let content = "\
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - name: app
      image: nginx:1.27
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [\"ALL\"]
      resources:
        limits:
          memory: 128Mi
";
        let findings = scan_str(content);
        assert!(
            findings.is_empty(),
            "hardened pod should be clean, got {:?}",
            rule_ids(&findings)
        );
    }

    #[test]
    fn explicit_root_is_not_double_reported() {
        let findings = scan_str(&format!(
            "{POD_HEADER}      securityContext:\n        runAsUser: 0\n"
        ));
        let ids = rule_ids(&findings);
        assert!(ids.contains(&"K8S-002"));
        assert!(!ids.contains(&"K8S-004"), "root should not also be 'non-root missing'");
    }

    #[test]
    fn flags_host_path_and_host_namespaces() {
        let content = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      volumes:
        - name: host-root
          hostPath:
            path: /
      containers:
        - name: app
          image: nginx:1.27
";
        let findings = scan_str(content);
        let ids = rule_ids(&findings);
        assert!(ids.contains(&"K8S-008"), "{ids:?}");
        assert!(ids.contains(&"K8S-009"), "{ids:?}");
        assert!(ids.contains(&"K8S-010"), "{ids:?}");
    }

    #[test]
    fn skips_non_kubernetes_yaml_without_parsing() {
        assert!(scan_str("foo: bar\n").is_empty());
        assert!(scan_str("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n").is_empty());
    }
}
