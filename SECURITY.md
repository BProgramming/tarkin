# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Tarkin, please report it via GitHub Security Advisories rather than opening a public issue. We aim to respond within 72 hours.

## Release Integrity

All Tarkin releases are published to PyPI via GitHub Actions using OIDC trusted publishing — no long-lived API tokens are involved. Each release is built from a tagged commit with `SOURCE_DATE_EPOCH` set for reproducible builds.

A Software Bill of Materials (SBOM) in CycloneDX format is attached to each GitHub release and generated from `uv.lock` to reflect the exact dependency tree at build time.

To verify a release:

```bash
pip download tarkin==<version> --no-deps -d /tmp/tarkin-dist
sha256sum /tmp/tarkin-dist/tarkin-<version>*.whl
```

Compare against the checksums in the GitHub release notes.

## Governance YAML Security Model

Tarkin's governance YAML is a declaration of intent, not a capability boundary. It describes what the database should look like; the actual enforcement happens via PostgreSQL's native permission system (GRANT/REVOKE, column-level privileges, pgaudit).

The YAML itself should be treated as sensitive configuration. It contains clearance levels, role definitions, masking strategies, and the full schema topology. Do not store it in public repositories or expose it to untrusted parties.

### Shadow Schema Model

During `tarkin attach`, existing schemas are renamed to `tk_<schema>` (shadow schemas). The public-facing schemas are recreated with views and triggers that implement the governance model. The shadow schemas hold the actual data and are inaccessible to non-owner roles.

On `tarkin detach`, the process is reversed: views and triggers are dropped, shadow schemas are renamed back to their original names, and all previously revoked grants are restored. The goal of detach is to return the database to exactly the state it was in before attach.

### pgcrypto Extension

If Tarkin enables the `pgcrypto` extension for SHA or HMAC column hashing, a record is written to `__META__.tarkin_builds` indicating this. On `tarkin detach`, a warning is printed if Tarkin was responsible for enabling it, noting that the extension can be dropped manually if it is not otherwise in use:

```sql
DROP EXTENSION IF EXISTS pgcrypto;
```

Tarkin does not drop `pgcrypto` automatically, as it may have been in use before attach.

### HMAC Key Management

Tarkin supports HMAC256 column hashing, which requires a secret key. This key is handled as follows:

- The key is **never stored in the governance YAML**. It is sourced from `credentials.toml` as `hmac_key` in the relevant profile section.
- During `tarkin attach`, the key is written to the database as a GUC (Grand Unified Configuration parameter): `ALTER DATABASE <db> SET tarkin.hmac_key = '...'`.
- At query time, view definitions retrieve the key via `current_setting('tarkin.hmac_key')`.
- The GUC is **visible to superusers** via `pg_settings`. Treat it as a database secret with the same care as other credentials.
- During `tarkin detach`, the GUC is reset: `ALTER DATABASE <db> RESET tarkin.hmac_key`.
- **Rotating the key** invalidates all existing HMAC-hashed values. If you rotate the key and re-attach, any stored HMAC values from the previous key will no longer match. Plan key rotation carefully.
- The key is never written to `__META__` or included in build artifacts.

### Column Masking Security Notes

#### Non-Cryptographic Hashing (xxhash)

The `xxhash` strategy uses `hashtextextended`, which is fast but non-cryptographic. Given knowledge of the source data distribution (e.g. a list of SSNs or postcodes), hash values are trivially reversible. Use `sha256`, `sha512`, or `hmac256` for sensitive columns.

#### Cryptographic Hashing Without a Key (sha256, sha512)

SHA256 and SHA512 are cryptographic hash functions but are still vulnerable to dictionary attacks on low-entropy data. An attacker with a list of candidate values (e.g. all valid postal codes) can hash each one and compare. Use `hmac256` with a strong secret key for maximum protection.

#### Sensitive Columns

The `sensitive: true` flag restricts column access to roles with `can_access_sensitive: true`, enforced via column-level `REVOKE`/`GRANT SELECT` on views. This is PostgreSQL-native enforcement, and is not dependent on Tarkin's trigger layer.

Sensitive columns that also have `masking_strategy: none` will emit a build-time warning. Roles with `can_access_sensitive: true` will see the raw value.

### pgaudit Configuration

When `audit_enabled: true` is set in the governance YAML, Tarkin configures pgaudit additively: existing audit settings are merged rather than overwritten. On attach, Tarkin captures the pre-existing `pgaudit.log`, `pgaudit.log_catalog`, and `pgaudit.log_relation` values and stores them in `__META__`. These are restored on detach.

## Known Limitations

- Tarkin does not implement Row-Level Security (RLS). Governance is enforced at the column and table level.
- Per-table audit exclusion is noted in comments in the generated SQL but is not yet implemented at the pgaudit object-level audit layer.
- The `__META__` schema is protected from PUBLIC access but is readable by the database owner. It contains the full governance YAML, including masking strategies and role definitions.
