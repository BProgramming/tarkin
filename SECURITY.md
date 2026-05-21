# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately via GitHub's Security Advisory feature:
**[Report a vulnerability](../../security/advisories/new)**

Include as much of the following as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions
- Any suggested mitigations

You can expect an acknowledgement within **5 business days** and a status update within **14 days**.

## Release integrity

All Tarkin releases are published to PyPI via GitHub Actions using OIDC trusted publishing — no long-lived API tokens are involved. Each release is built from a tagged commit with `SOURCE_DATE_EPOCH` set for reproducible builds.

Two assets are attached to every GitHub release:

- `SHA256SUMS.txt` — SHA-256 checksums of each built wheel and sdist.
- `sbom.json` — a Software Bill of Materials in CycloneDX format, generated from `uv.lock` to reflect the exact dependency tree at build time.

To verify a downloaded release:

```bash
pip download tarkin==<version> --no-deps -d /tmp/tarkin-dist
cd /tmp/tarkin-dist
sha256sum tarkin-<version>*
```

Compare the output against the matching lines in `SHA256SUMS.txt` attached to the corresponding GitHub release. (`SHA256SUMS.txt` records paths relative to the build's `dist/` directory, so the file names will match the downloaded artifacts.)

### Audit trail and tamper evidence

When `audit_enabled: true` is configured, Tarkin sets `pgaudit.log = write`, which causes PostgreSQL to log every INSERT, UPDATE, and DELETE against the shadow tables. These log entries are written to the OS-level log infrastructure (syslog, journald, CloudWatch Logs, or equivalent) which is not accessible to database users. A database superuser can modify or delete rows in `__META__`, but cannot retroactively edit what pgaudit has already written to the system log.

This means that while `__META__` itself is not tamper-proof (see Known Limitations), the audit trail of any tampering is, provided the OS log infrastructure is appropriately secured and retained.
In practice this means:
- Restrict OS-level access to the PostgreSQL log destination independently of database access
- Ensure logs are shipped to an external system (e.g. CloudWatch, a SIEM) in near-real-time so that local log deletion does not erase the record
- The `tarkin_audit` role created by Tarkin is granted object-level SELECT/INSERT/UPDATE/DELETE on audited shadow tables, so pgaudit can attribute log entries correctly

Tarkin does not provide log retention, shipping, or alerting; those are the operator's responsibility. The guarantee Tarkin provides is that the instrumentation is in place.

## Governance YAML security model

Tarkin's governance YAML is a declaration of intent, not a capability boundary: it describes what the database should look like, and the actual enforcement happens via PostgreSQL's native permission system (GRANT/REVOKE, column-level privileges, pgaudit).

The YAML itself should be treated as sensitive configuration. It contains clearance levels, role definitions, masking strategies, and the full schema topology. Do not store it in public repositories or expose it to untrusted parties.

### Shadow schema model

During `tarkin attach`, existing schemas are renamed to `tk_<schema>` (shadow schemas). The public-facing schemas are recreated with views and triggers that implement the governance model. The shadow schemas hold the actual data.

To keep the shadow data reachable only through the governed view layer, Tarkin revokes **all** privileges on each shadow schema and its tables from `PUBLIC`, then re-grants full access only to the database owner (`database.owner` in the YAML — this is why a build fails if no owner is set). Every role declared in the YAML is also explicitly revoked from the shadow schemas.

**Important caveat**: This protects against access inherited via `PUBLIC`. It does **not** retroactively remove a *direct, role-specific* grant on the underlying tables that was issued outside Tarkin to a role that is **not** declared in the governance YAML — Tarkin only revokes from roles it knows about. For the shadow-schema boundary to be complete, the governance YAML must enumerate every role that holds access to the governed schemas. After attach, audit `tk_<schema>` grants (e.g. via `\dp tk_<schema>.*`) to confirm no unexpected role retains direct access.

On `tarkin detach`, the process is reversed: views and triggers are dropped, shadow schemas are renamed back to their original names, and all previously revoked grants are restored. The goal of detach is to return the database to exactly the state it was in before attach.

### pgcrypto extension

If Tarkin enables the `pgcrypto` extension for SHA or HMAC column hashing, a record is written to `__META__.tarkin_builds` indicating this. On `tarkin detach`, a warning is printed if Tarkin was responsible for enabling it, noting that the extension can be dropped manually if it is not otherwise in use:

```sql
DROP EXTENSION IF EXISTS pgcrypto;
```

Tarkin does not drop `pgcrypto` automatically, as it may have been in use before attach.

### HMAC key management

Tarkin supports HMAC256 column hashing, which requires a secret key. This key is handled as follows:

- The key is **never stored in the governance YAML**. It is sourced from `credentials.toml` as `hmac_key` in the relevant profile section.
- During `tarkin attach`, the key is written to the database as a GUC (Grand Unified Configuration parameter): `ALTER DATABASE <db> SET tarkin.hmac_key = '...'`.
- At query time, view definitions retrieve the key via `current_setting('tarkin.hmac_key')`.
- The GUC is **visible to superusers** via `pg_settings`. Treat it as a database secret with the same care as other credentials.
- During `tarkin detach`, the GUC is reset: `ALTER DATABASE <db> RESET tarkin.hmac_key`.
- **Rotating the key** invalidates all existing HMAC-hashed values. If you rotate the key and re-attach, any stored HMAC values from the previous key will no longer match. Plan key rotation carefully.
- The key is never written to `__META__` or included in build artifacts.

### Column masking security notes

#### Non-cryptographic hashing (xxhash)

The `xxhash` strategy uses `hashtextextended`, which is fast but non-cryptographic. Given knowledge of the source data distribution (e.g. a list of SSNs or postcodes), hash values are trivially reversible. Use `sha256`, `sha512`, or `hmac256` for sensitive columns.

#### Cryptographic hashing without a key (sha256, sha512)

SHA256 and SHA512 are cryptographic hash functions but are still vulnerable to dictionary attacks on low-entropy data. An attacker with a list of candidate values (e.g. all valid postal codes) can hash each one and compare. Use `hmac256` with a strong secret key for maximum protection.

#### Sensitive columns

The `sensitive: true` flag restricts column access to roles with `can_access_sensitive: true`, enforced via column-level `REVOKE`/`GRANT SELECT` on views. This is PostgreSQL-native enforcement, and is not dependent on Tarkin's trigger layer.

Sensitive columns that also have `masking_strategy: none` will emit a build-time warning. Roles with `can_access_sensitive: true` will see the raw value.

### pgaudit configuration

When `audit_enabled: true` is set in the governance YAML, Tarkin configures pgaudit additively: existing audit settings are merged rather than overwritten. On attach, Tarkin captures the pre-existing `pgaudit.log`, `pgaudit.log_catalog`, and `pgaudit.log_relation` values and stores them in `__META__`. These are restored on detach.

## Known limitations

- The `__META__` schema is protected from PUBLIC access but is readable by the database owner. It contains the full governance YAML, including masking strategies and role definitions.
- The shadow-schema boundary depends on the governance YAML enumerating every role with access to the governed schemas (see *Shadow Schema Model* above).

## Out of scope

- Vulnerabilities in PostgreSQL itself.
- Issues requiring an attacker to already have write access to the governed database. This must be controlled via secure access to your RDS of choice.
