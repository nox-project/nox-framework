# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active  |

## Reporting a Vulnerability

Report security vulnerabilities **privately** — do not open a public issue.

**Contact:** open a [GitHub Security Advisory](https://github.com/nox-project/nox-framework/security/advisories/new)

Include:
- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 48 hours. Critical vulnerabilities are patched within 7 days.

## Scope

In-scope:
- Remote code execution via crafted source plugin or API response
- Credential leakage from the vault or apikeys.json
- OPSEC bypass (real IP exposure when proxy/Tor is configured)
- Dependency vulnerabilities with a direct exploit path

Out of scope:
- Issues requiring physical access to the machine
- Social engineering
- Vulnerabilities in third-party APIs queried by NOX
