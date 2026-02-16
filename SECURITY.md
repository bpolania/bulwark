# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Bulwark, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email the maintainers directly with:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Security Measures

Bulwark implements several security measures:

- **`#![forbid(unsafe_code)]`** in all crates
- **Content inspection** with secret detection and PII scanning
- **Hash-chained audit log** for tamper detection
- **Session-scoped credential injection** (secrets never exposed to agents)
- **Policy engine** with default-deny semantics
- **Header stripping** to prevent credential leakage to upstream servers
- **cargo-deny** for dependency auditing

## Scope

The following are in scope for security reports:

- Authentication/authorization bypasses
- Credential leakage through the proxy
- Policy engine bypasses
- Audit log tampering
- TLS/MITM implementation flaws
- Injection attacks through configuration
