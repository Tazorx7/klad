# Security Policy

## Supported Versions

We currently support the latest version of klad with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in klad, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:
- GitHub Security Advisories: [Report a vulnerability](https://github.com/tazorx7/klad/security/advisories/new)

### What to Include

Please include as much information as possible:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Status Update**: At least every 7 days until resolved
- **Fix & Disclosure**: We aim to fix critical vulnerabilities within 30 days and coordinate disclosure

## Security Best Practices

When using klad:
- Always use the latest version
- Review ignore files carefully
- Don't commit scan results with sensitive findings to public repos
- Run klad in isolated CI environments
- Keep dependencies updated

## Scope

The following are in scope:
- Vulnerabilities in klad's scanning logic
- False negatives that could miss critical security issues
- Path traversal or arbitrary file read issues
- Command injection vulnerabilities
- Issues with ignore/baseline parsing

Out of scope:
- Vulnerabilities in dependencies (report to upstream)
- Social engineering attacks
- Denial of service through resource exhaustion (we have limits, but report if bypassable)

Thank you for helping keep klad and its users safe!
