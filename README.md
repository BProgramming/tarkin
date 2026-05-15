# Tarkin

**Governance compiler for PostgreSQL.** Tarkin takes a YAML specification of your database's access model: schemas, tables, columns, clearance levels, masking strategies, roles, and audit settings, and compiles it into a live PostgreSQL governance layer.

## How it works

`tarkin attach` renames your existing schemas to shadow schemas (`tk_<schema>`), creates fresh public-facing schemas with views and INSTEAD OF triggers implementing your governance model, and populates a `__META__` schema with full build metadata. `tarkin detach` reverses all of this, restoring the database to exactly the state it was in before attach.

## Installation

```bash
pip install tarkin
```

Requires Python 3.11+ and PostgreSQL 14+.

## Quick start

```bash
# Inspect a live database and generate a governance YAML
tarkin inspect --profile mydb

# Edit out/mydb_model.yaml to configure governance

# Compile and validate
tarkin validate out/mydb_model.yaml
tarkin build out/mydb_model.yaml --profile mydb

# Apply
tarkin attach --profile mydb

# Remove
tarkin detach --profile mydb --keep-versioning
```

Run `tarkin help` or `tarkin --help` for the full command reference.

## Credentials

Tarkin uses a `credentials.toml` file (default: `~/.tarkin/credentials.toml`) to store connection profiles:

```toml
[mydb]
host     = "localhost"
port     = 5432
database = "myapp"
username = "postgres"
password = "secret"

# Optional: HMAC key for HMAC256 column hashing
# hmac_key = "your-strong-secret-key"
```

## Versioning columns

When a column has `versioned: true`, Tarkin adds `__valid_from__` and `__valid_to__` columns to the shadow table to maintain a full history of changes. These columns are intentionally **not exposed through the public-facing view** — the view layer presents only the declared columns. The `_current` view variant (e.g. `users_current`) is created automatically and filters to live records (`__valid_to__ = 'infinity'`).

On `tarkin detach`:
- With `--keep-versioning`: the `__valid_from__` and `__valid_to__` columns are retained in the restored table, along with all historical records. This is the safe default when history is valuable.
- With `--drop-versioning`: only current records (`__valid_to__ = 'infinity'`) are retained and the versioning columns are dropped. **This operation is destructive and irreversible.**

The versioning index (`idx_<table>_current`) is dropped when `--drop-versioning` is used, and retained otherwise.

## Security

See [SECURITY.md](SECURITY.md) for:
- Release integrity and SBOM verification
- HMAC key management and rotation
- Shadow schema model and detach guarantees
- Column masking security notes (xxhash vs SHA vs HMAC)
- Sensitive column enforcement
- pgaudit configuration and restoration
- Known limitations

## License

Apache 2.0. See [LICENSE](LICENSE).
