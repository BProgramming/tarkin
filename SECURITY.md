# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | YES       |

## Database Superuser

Many of Tarkin's operations require a specified database owner with
superuser access. Tarkin populates this automatically from the active user
running it,vbut if that user is not the database owner then the
specification yaml needs to be changed accordingly.

All other users/roles will have access restricted based on specified
clearances.

## Reporting a Vulnerability

Please do not report security vulnerabilities via public GitHub issues.

Open a GitHub Security Advisory instead:
https://github.com/BProgramming/tarkin/security/advisories/new

You can expect acknowledgment within 48 hours and a resolution
timeline within 7 days for critical issues.

## Release Integrity

All Tarkin releases are published via GitHub Actions using PyPI trusted
publishing (Sigstore OIDC). Every release is cryptographically tied to
a specific workflow run in this repository — a stolen token alone is
not sufficient to publish a malicious version.

Release provenance can be verified at:
https://pypi.org/project/tarkin/#history

An SBOM (Software Bill of Materials) is attached to every GitHub release.
