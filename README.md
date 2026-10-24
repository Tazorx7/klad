# klad

A lightning-fast infrastructure and container security auditor. Built in Rust with a focus on speed and CI-first workflows.

## Features

- **Single-pass discovery**: Walks your repository once with `.gitignore` awareness, skips common vendor/build directories
- **Parallel scanning**: Scans files concurrently with Rayon for maximum speed
- **Dockerfile scanning**: Detects unpinned base images, running as root, broad COPY/ADD, missing USER instructions, and handles multi-stage builds
- **Kubernetes manifest scanning**: Checks for privileged containers, hostPath/hostNetwork/hostPID, missing security contexts, resource limits, dropped capabilities, and proper root/non-root enforcement
- **Secret detection**: Aho-Corasick prefiltered secret scanning for AWS keys, private keys, and common API tokens
- **Multiple output formats**: Table (human-readable), JSON, and SARIF (for GitHub Advanced Security, GitLab, etc.)
- **CI-friendly**: Configurable severity thresholds, custom exit codes, baseline diffs, and ignore files
- **Deterministic output**: Results sorted consistently for reliable diffs

## Installation

```bash
cargo build --release
./target/release/klad --version
```

## Usage

```bash
# Scan current directory
klad

# Scan a specific path
klad -p ./manifests

# JSON output
klad -o json

# SARIF output for CI
klad -o sarif --output-file results.sarif

# Fail only on critical findings
klad --severity-threshold critical --exit-code 1

# Use ignore file
klad --ignore-file .kladignore

# Diff against baseline (only fail on new findings)
klad --baseline baseline.json
```

## Ignore File Format

Create a `.kladignore` file:

```text
# Ignore specific rules
rule:DF-003

# Ignore files matching pattern
file:tests/

# Ignore specific rule in specific context
K8S-003
```

## Rules

### Dockerfile (DF-*)
- `DF-001`: Running as root / missing non-root user
- `DF-002`: Unpinned base image (`latest`, `edge`, or no tag)
- `DF-003`: Broad build context copy (`COPY . .`)

### Kubernetes (K8S-*)
- `K8S-001`: Privileged container
- `K8S-002`: Explicit `runAsUser: 0`
- `K8S-003`: Missing resource limits
- `K8S-004`: `runAsNonRoot` not enforced
- `K8S-005`: `allowPrivilegeEscalation` not disabled
- `K8S-006`: Writable root filesystem
- `K8S-007`: Linux capabilities not dropped
- `K8S-008`: hostPath volume mounted
- `K8S-009`: hostNetwork enabled
- `K8S-010`: hostPID enabled
- `K8S-011`: hostIPC enabled

### Secrets (SEC-*)
- `SEC-001`: AWS Access Key ID
- `SEC-002`: Private Key (RSA/EC/DSA/OPENSSH/PGP)
- `SEC-003`: Generic API tokens/secrets

## Performance

klad is designed for speed. It uses a single directory traversal with `.gitignore` support, reads files once, and uses Aho-Corasick for fast secret prefiltering. Parallel scanning across CPU cores ensures rapid results even on large repositories.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## License

See [LICENSE](LICENSE) for details.
