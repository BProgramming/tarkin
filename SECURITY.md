# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | YES       |

## Database Superuser

Many of Tarkin's operations require a specified database owner with
superuser access. Tarkin populates this automatically from the active user
running it, but if that user is not the database owner then the
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

## Shadow Schema Access

Tarkin renames your existing schemas to `tk_{schema_name}` and creates
new public-facing schemas in their place. All application roles are
explicitly revoked from shadow schemas — they must access data through
the views Tarkin creates, not directly.

The database owner retains full access to shadow schemas. Bulk loads and
ETL operations should target shadow schemas directly using owner
credentials, bypassing the view layer entirely. This is intentional and
does not compromise governance — the view layer is designed for
application-level access, not bulk ingestion.

Note that writes directly to shadow tables bypass Tarkin's immutability
checks and versioning logic. If writing to a versioned shadow table
directly, you are responsible for populating `__valid_from__` and
`__valid_to__` correctly.

## __META__ Schema

Tarkin creates a `__META__` schema containing the full governance
specification, role definitions, clearance levels, and masking
configuration for your database. Access is restricted to the database
owner. Do not grant access to `__META__` to application roles.

## Hashing and Masking

Tarkin's masking strategies obscure data in views but do not prevent
the database owner or sufficiently privileged roles from reading the
underlying shadow tables directly.

Hash masking algorithms carry the following caveats:

- **xxhash**: Non-cryptographic. Trivially reversible given knowledge
  of the source data distribution. Do not use for sensitive data.
- **sha256 / sha512**: Cryptographic but vulnerable to dictionary
  attacks on low-entropy data (SSNs, postcodes, phone numbers). An
  attacker with the hash output and knowledge of the value space can
  recover the original value by brute force.
- **hmac256**: Cryptographically strong when the HMAC key is kept
  secret. Resistance depends entirely on key secrecy — a leaked key
  allows full reversal of all hashed values.

None of these strategies constitute encryption. They are pseudonymisation
mechanisms suitable for access control and compliance documentation, not
for protecting data against a compromised database owner.

## HMAC Key Management

When using `hmac256` hashing, the HMAC key is stored as a
database-level setting (`tarkin.hmac_key`) set during `tarkin attach`.
This value is visible to superusers via `SHOW tarkin.hmac_key` and
`pg_db_role_setting`. Treat it as a secret.

The key is sourced from your `credentials.toml` file and never written
to the governance YAML or the Tarkin build artifact.

**Key rotation**: Changing the HMAC key invalidates all existing
hashed values. Any joins, comparisons, or lookups against previously
hashed columns will silently return no results after rotation. Rotate
only when necessary and ensure downstream consumers are updated.

## pgaudit Configuration

When `audit_enabled: true`, Tarkin configures pgaudit additively —
it merges its required log levels with any existing configuration
rather than overwriting it. However, `log_catalog` will be set to
`off` if it is not already explicitly enabled, which may reduce audit
coverage compared to your existing configuration. Review the generated
SQL before applying if pgaudit is already configured on your database.

## Credentials File

Tarkin credentials (`~/.tarkin/credentials.toml` by default) contain
database passwords and optionally HMAC keys. This file should be:

- Readable only by the owning user (`chmod 600`)
- Excluded from version control
- Never committed to the governance YAML repository

Credentials never appear in governance YAMLs, build artifacts, or
`__META__` tables. Only the profile name is stored.

## Bulk Operations and the View Layer

Application roles interact with data exclusively through Tarkin-managed
views. These views enforce column-level access control based on
clearance and sensitivity settings. The owner bypasses this layer when
writing directly to shadow schemas — this is expected behaviour for
administrative and bulk operations, and assumes the owner is trusted.

Tarkin does not implement row-level security. All rows in an accessible
table are visible to any role with sufficient column clearance.
