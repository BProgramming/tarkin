# Tarkin: govern your data

An open source governance compiler for PostgreSQL.

![Careful, Princess. Disclosing the Rebellion's location like that is strictly in violation of GDPR.](./tarkin.jpg)

## Why?

Data governance is tough. Regulations aren't made with implementation in mind, and data engineers often aren't the ones making those decisions anyway.

The result:
- A lot of ad-hoc work in triggers, functions, and manual grants
- Constant required fixes
- Limited documentation (or a ton of work to write it all)
Or, you take an off-the-shelf solution that's a complete black-box.

But it's not rocket science, just a lot of work. I made this to help. And also so that I don't have to write out column GRANTs ever again.

## How it works

By design, Tarkin is an open book: open source, fully accessible code, fully human-readable output. The point of data governance is to keep things secure, so having any aspect of the process live in a black-box is counterintuitive.

Tarkin is run through a Command Line Interface (CLI) tool built in Python with Typer. Some commands generate YAMLs for you to view and modify, or SQL scripts for you to validate, and others apply those scripts once you've decided they're ready. Nothing happens without your direct approval. And don't just take my word for it — check [the GitHub repo](https://github.com/BProgramming/tarkin) yourself.

## Installation

```bash
pip install tarkin
pip install tarkin[query] # optional extension as of v0.2.0
```

Requires Python 3.11+ and PostgreSQL 14+, PostgreSQL 15+ for Row-Level Security (RLS), or PostgreSQL 16+ for MAINTAIN privileges.

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

Because a versioned table keeps historical rows that reuse the same key values, its original single-row primary key is replaced with a partial unique index covering only the live row (`__valid_to__ = 'infinity'`). As a consequence, **a versioned table cannot be the target of a foreign key**; `tarkin validate` rejects any configuration that does this.

On `tarkin detach`:
- With `--keep-versioning`: the `__valid_from__` and `__valid_to__` columns are retained in the restored table, along with all historical records. This is the safe default when history is valuable.
- With `--drop-versioning`: only current records (`__valid_to__ = 'infinity'`) are retained and the versioning columns are dropped. **This operation is destructive and irreversible.**

The versioning index (`idx_<table>_current`) is dropped when `--drop-versioning` is used, and retained otherwise.

## Retention columns

When a table has `retention_days` set, Tarkin adds `__expires_at__` and `__erase_on_expiry__` columns to the shadow table to support time-based data expiry. These columns are intentionally **not exposed through the public-facing view** — the view layer presents only the declared columns.

`__expires_at__` is a `timestamptz` column with a default of `now() + interval '<retention_days> days'`, computed at INSERT time. `__erase_on_expiry__` is a `bool` column defaulting to `true`. A partial index on `__expires_at__ WHERE __erase_on_expiry__ = true` is created to keep the scheduled sweep performant.

Setting `__erase_on_expiry__ = false` on any individual row exempts it from scheduled deletion — this is the mechanism for legal holds when a record must be retained beyond its normal expiry.

When `retention_schedule` is configured on the database, Tarkin registers a pg_cron job named `tarkin_retention_<database>` that calls `__META__.tarkin_erase_expired_records()` on the configured cron schedule. That function sweeps all tables registered in `__META__.tarkin_retention`, finds rows where `__expires_at__ <= now() AND __erase_on_expiry__ = true`, and applies the table's `erase_strategy` (`delete`, `nullify`, or `obfuscate`). Each sweep is logged to `__META__.tarkin_erasures` with `was_scheduled = true`.

On `tarkin detach`:
- The pg_cron job is unscheduled (guarded by a check that pg_cron is installed, since it may have been removed independently)
- The partial index `idx_<table>_expires_at` is dropped
- The `__expires_at__` and `__erase_on_expiry__` columns are dropped from the shadow table before the schema rename

Unlike versioning, there is no keep/drop flag — retention columns are always removed on detach. Any records that had not yet expired are restored to the table without expiry metadata, and the operator is responsible for any cleanup.

## Security

See [SECURITY.md](SECURITY.md) for:
- Release integrity and SBOM verification
- HMAC key management and rotation
- Shadow schema model and detach guarantees
- Column masking security notes (xxhash vs SHA vs HMAC)
- Sensitive column enforcement
- pgaudit configuration and restoration
- Known limitations

## Reference

See [REFERENCE.md](REFERENCE.md) for an overview of all available CLI commands.

## License

Apache 2.0. See [LICENSE](LICENSE).
