# CLI Reference

All commands are run as `tarkin <command> [options]`.

## tarkin help
Alias for `tarkin --help`. Prints the top-level command list.

## tarkin version
Prints the installed Tarkin version and exits.

## tarkin auth
Aliases: `tarkin authorize`, `tarkin authorise`

Authenticates an IAM profile via AWS SSO login and verifies that a valid RDS auth token can be generated. Only applicable to profiles with `iam_auth = true`.

Options:
- `--profile` | `-p` (required): credentials profile to authorize
- `--credentials` | `-c`: path to credentials.toml (defaults to `~/.tarkin/credentials.toml`)

What it does:
- Verifies the profile uses IAM auth
- Invokes `aws sso login` (with `--profile` if `aws_profile` is set), opening a browser session
- Verifies that boto3 can generate a valid RDS auth token with the refreshed session
- Caches the token on the profile for the duration of the process

Dependency requirement:
- Requires that the AWS Command Line Interface (CLI) is installed on the user's PC (not included as part of Tarkin)

## tarkin connect
Tests that one or more credential profiles can reach their configured databases.

Options:
- `--profile` | `-p`: test a specific profile (omit to test all profiles in the credentials file)
- `--credentials` | `-c`: path to credentials.toml (defaults to `~/.tarkin/credentials.toml`)
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying

What it does:
- Opens a connection
- Runs a minimal probe query
- Prints PASS or FAIL for each profile along with the PostgreSQL server version and connected user

## tarkin inspect
Inspects a live PostgreSQL database and writes a Tarkin governance YAML describing its current state.

Options:
- `--profile` | `-p` (required): credentials profile to connect with
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--output` | `-o`: output path (defaults to `out/<database>_model.yaml`)
- `--validate` | `--no-validate`: run semantic validation on the inspected model before writing (default: validate)

What it does:
- Captures the following:
  - schemas
  - tables
  - columns (with types, nullability, defaults, uniqueness)
  - indexes (including primary keys, partial filters, index types)
  - foreign keys
  - sequences
  - views
  - materialized views
  - functions
  - trigger functions
  - procedures
  - aggregates
  - types
  - domains
  - collations
  - operators
  - foreign tables
  - text search configurations, dictionaries, parsers, and templates
  - roles (with login/superuser/write flags, membership, schema and table grants)
  - existing RLS policies (non-Tarkin policies only, as `rls_enabled`, `rls_force`, and `rls_policies` on each table)
- Detects whether pgaudit and pg_cron are installed
- Writes a YAML that can be edited and passed to `tarkin build`

## tarkin validate
Parses and semantically validates a governance YAML without connecting to a database.

Arguments:
- `config` (required): path to governance YAML

What it does:
- Runs the full suite of semantic validation rules, collecting all errors before raising so the operator sees the complete list at once

Validates:
- At least one schema and one role exist
- Audit configuration consistency (table-level audit requires database-level audit; `audit_logged` must be non-empty if `audit_enabled`)
- Erasure configuration consistency: `is_subject_identifier` columns require `erase_strategy`; `erase_strategy` without identifier columns is unreachable; OBFUSCATE on non-nullable non-text columns; FKs pointing at subject-identified tables require a strategy on the referencing table
- RLS configuration: `rls_policies` without `rls_enabled`; `rls_force` and/or `rls_security_barrier` without `rls_enabled`; empty `using_expr`; empty roles list; undefined role names; emits a warning (not error) when `rls_enabled` is set and the configured database version is pre-PG15 (where `security_invoker` is unavailable)
- Retention configuration consistency: `retention_days` requires `erase_strategy`; must be a positive integer; `__expires_at__` and `__erase_on_expiry__` must not already exist as column names; warns when `retention_schedule` is set but no tables have `retention_days`, and vice versa
- Schema uniqueness and non-emptiness
- Table uniqueness, non-emptiness, at least one primary key and no more than one (two separate checks)
- Column uniqueness; `generated_expression` and `default` are mutually exclusive; `versioned` and `immutable` are mutually exclusive; `versioned` and `generated_expression` are mutually exclusive
- Masking strategy/config consistency (each strategy requires the matching config type)
- Cross-references: index columns, FK local columns, FK referenced schemas/tables/columns all exist
- Clearance rules: column clearance must meet table and schema minimums; role clearance range must span the database clearance range
- Role rules: unique names; each role has at least one schema or `member_of`; referenced schemas exist; `member_of` parents exist; at least one login role

## tarkin build
Compiles a governance YAML into a build artifact by connecting to the live database.

Arguments:
- `config` (required): path to governance YAML

Options:
- `--profile` | `-p`: credentials profile (overrides the profile field in the YAML)
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--output` | `-o`: output directory (defaults to `out/`)

What it does:
- Validates the YAML
- Inspects the live database to capture its current state
- Checks pre-conditions: no existing Tarkin shadow schemas; pgaudit installed and preloaded if `audit_enabled: true`; pg_cron installed and preloaded if any retention is configured
- Generates the full SQL build artifact, which includes:
  - Renames existing schemas to `tk_<schema>` (shadow schemas)
  - Creates fresh public-facing schemas
  - Moves existing schema objects (sequences, functions, trigger functions, procedures, aggregates, types, domains, collations, views, materialized views, operators, foreign tables, FTS objects) to the new public schemas
  - Adds versioning columns (`__valid_from__`, `__valid_to__`) to versioned tables
  - Adds new generated columns not present in the live database
  - Adds new FK constraints not present in the live database
  - Creates `CREATE VIEW` statements with column-level masking expressions; views use `security_invoker = true` on PG15+ when `rls_enabled`, and `security_barrier = true` when `rls_security_barrier` is set
  - Creates `INSTEAD OF` trigger functions and trigger attachments for all views (handling INSERT/UPDATE/DELETE with immutability checks and versioning patterns)
  - Creates roles (`CREATE` or `ALTER`) and membership grants
  - Applies schema and table-level `GRANT`/`REVOKE` statements, with column-level SELECT/UPDATE/REFERENCES restriction based on clearance and sensitivity
  - Configures pgaudit (merging with existing settings, snapshotting pre-existing values for restoration on detach)
  - Grants pgaudit privileges to `tarkin_audit` role for audited tables
  - Enables Row Level Security and creates `tarkin_rls_<table>_<i>` policies on shadow tables
  - Creates per-column btree indexes for `is_subject_identifier` columns
  - Adds `__expires_at__` and `__erase_on_expiry__` columns with defaults to retained tables, plus a partial index on `__expires_at__` WHERE `__erase_on_expiry__ = true`
  - Creates `__META__.tarkin_erase_check()` and `__META__.tarkin_erase_apply()` functions for on-demand erasure
  - Creates `__META__.tarkin_erase_expired_records()` sweep function and schedules it via pg_cron if `retention_schedule` is configured
  - Populates all `__META__` tables (builds, schemas, tables, columns, indexes, FKs, roles, grants, moved objects, added FKs, added generated columns, subject identifiers, retention config)
  - Enables pgcrypto extension if any column uses SHA256/SHA512/HMAC256 masking or OBFUSCATE erasure
- Writes `out/tarkin_build_<timestamp>.zip` containing `tarkin_build.json` (metadata including `artifact_type: "build"`, checksums, schema list, audit config) and `tarkin_build.sql`

## tarkin attach
Applies a build or migration artifact to a live database.

Options:
- `--profile` | `-p`: credentials profile (read from the artifact metadata if omitted)
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--build` | `-b`: path to artifact zip (defaults to the most recent `tarkin_build_*.zip` or `tarkin_migrate_*.zip` in `out/`)

What it does:
- Reads `artifact_type` from the artifact metadata and routes accordingly:
  - `artifact_type = "build"`:
    - Verifies no `tk_` shadow schemas exist (no existing build attached)
    - Verifies the live database checksum matches the artifact's `db_checksum`
    - Executes the SQL in a single transaction
  - `artifact_type = "migrate"`:
    - Verifies `tk_` shadow schemas are present (a build must be attached)
    - Reads the current build's checksum from `__META__.tarkin_builds` and verifies it matches the artifact's `source_checksum`
    - Verifies the database name matches
    - Executes the SQL in a single transaction
- On any failure the transaction is rolled back
- Prints a clear message distinguishing "build" from "migration" throughout

## tarkin detach
Removes a Tarkin governance model from a live database, restoring the original schema state.

Options:
- `--profile` | `-p` (required): credentials profile
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--keep-versioning` | `-k`: retain `__valid_from__` and `__valid_to__` columns, and all historical rows
- `--drop-versioning` | `-d`: drop versioning columns, keeping only current rows (`__valid_to__ = 'infinity'`)
- `--no-warn` | `-n`: suppress the confirmation prompt when dropping versioning data
- `--no-restore-grants` | `-g`: skip restoring pre-attach grants (use if `__META__` is unavailable)

What it does:
- Inspects the live database to find `tk_` shadow schemas
- Reads `__META__` to recover:
  - Tarkin-created roles
  - Revoked grants to restore
  - pgaudit settings to restore
  - Added FK constraints
  - Added generated columns
  - Moved schema objects
  - Subject identifier indexes
  - Retention tables
- Drops `INSTEAD OF` triggers and trigger functions
- Drops public-facing views (and `_current` versioned views)
- Optionally drops versioning columns and historical rows
- Drops added FK constraints
- Drops added generated columns
- Drops subject identifier indexes (`tarkin_subject_<table>_<col>`)
- Unschedules the pg_cron retention job (guarded by a check that pg_cron is installed), drops retention partial indexes, drops `__expires_at__` and `__erase_on_expiry__` columns
- Moves schema objects (sequences, functions, aggregates, FTS objects, etc.) back to shadow schemas
- Drops Tarkin-created roles (`REASSIGN OWNED`, `DROP OWNED`, `DROP ROLE`)
- Runs `DROP SCHEMA ... CASCADE` on the public-facing schemas; renames `tk_<schema>` back to `<schema>`
- Drops `tarkin_rls_*` policies via `pg_policies` query; disables RLS and `NO FORCE` on restored tables
- Restores pre-attach grants (schema-level first, then table-level, including `PUBLIC` pseudo-role grants)
- Drops `__META__ CASCADE`
- Restores pgaudit settings (`log`, `log_catalog`, `log_relation`, `role`) to pre-attach values
- Resets `tarkin.hmac_key` GUC
- Prints a note if pgcrypto was enabled by Tarkin (it is not dropped automatically as it may be used by other objects)

## tarkin diff
Compares two governance YAMLs and produces a structured Markdown diff report.

Arguments:
- `before` (required): path to the baseline governance YAML
- `after` (required): path to the target governance YAML

Options:
- `--output` | `-o`: output path (defaults to `out/diff_<before>_<after>.md`)

What it does:
- Loads and validates both YAMLs
- Runs `diff_projects()`
- Writes a Markdown report with a summary line and per-object-type tables showing:
  - Each change (ADDED/REMOVED/MODIFIED)
  - The path, field, before/after values, and migration notes associated with each change

Covers:
- Database fields (including `retention_schedule`)
- Schemas
- Tables (including `erase_strategy`, `rls_enabled`, `rls_force`, `rls_security_barrier`, `retention_days`, and RLS policies by position)
- Columns (including `is_subject_identifier`)
- Indexes
- Foreign keys
- Roles
- Permissions

## tarkin migrate
Generates a migration artifact from the current live build to a new governance YAML.

Arguments:
- `config` (required): path to the target governance YAML

Options:
- `--profile` | `-p`: credentials profile (overrides the YAML's profile field)
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--output` | `-o`: output directory (defaults to `out/`)
- `--force` | `-f`: generate an artifact even when the model has not changed

What it does:
- Validates the target YAML
- Reads the current build's YAML from `__META__.tarkin_builds` (most recent build)
- Diffs the stored before-YAML against the target after-YAML
- Raises `MigrateError` if no differences are detected
- Generates ordered, transactional migration SQL in 14 sections:
  - Drop FK constraints for removed or modified FKs
  - Drop all `tarkin_rls_*` policies and disable RLS on tables whose RLS config changed
  - Drop indexes (for removed or modified non-PK indexes only; PK changes emit a `-- WARNING` manual intervention stub)
  - Drop views and triggers for all tables in affected schemas
  - Schema changes: `CREATE` for added schemas (both public and `tk_`); `DROP CASCADE` with warning for removed schemas
  - Table changes: `CREATE` in shadow schema with column definitions and indexes for added tables; `DROP` with warning for removed tables
  - Column changes: `ADD COLUMN` for new columns; `DROP COLUMN` with warning; `ALTER COLUMN TYPE` with `USING` cast and warning; `SET`/`DROP NOT NULL` (NOT NULL addition has warning); `SET`/`DROP DEFAULT`; view-layer-only changes (masking, clearance, etc.) are deferred to view recreation
  - Recreate views for all affected schemas using the after-state, including masking expressions, `security_invoker`, and `security_barrier`
  - Recreate `INSTEAD OF` trigger functions and trigger attachments
  - Recreate removed/modified indexes (PK changes emit a warning stub)
  - Recreate removed/modified FKs referencing shadow tables
  - Recreate RLS enable/force and `tarkin_rls_*` policies for changed tables
  - Revoke existing grants for affected roles, then regenerate roles and grants from the after-state
  - Insert a new `__META__.tarkin_builds` row with the after-YAML and target checksum
- Writes `out/tarkin_migrate_<timestamp>.zip` with `tarkin_build.json` (metadata including `artifact_type: "migrate"`, `source_checksum`, `target_checksum`, `change_count`, and the full serialised change list) and `tarkin_build.sql`
- Prints the artifact path and the exact `tarkin attach` command to apply it (the artifact is identical in structure to a build artifact and is applied with `tarkin attach`)

Without `--force`, an empty changeset is an error. Parts of a migration are regenerated wholesale rather than diffed (the `__META__` update, the discovery functions, and the object comments carrying the YAML descriptions) so a database whose governance model is unchanged can still lag behind the codegen of the installed Tarkin version. `--force` is how it catches up without a detach and rebuild. The artifact is written for review and applied with `tarkin attach` like any other.

A forced migration writes a new `tarkin_builds` row, so `build_id` advances and `__META__.get_build()` reports the change even though the checksum is unchanged.

## tarkin erase
Erases data subject records from a Tarkin-attached database.

Options:
- `--profile` | `-p` (required): credentials profile
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--column` | `-col` (required, repeatable): identifier column name to match on
- `--value` | `-val` (required, repeatable): value corresponding to each `--column`, in the same order
- `--check`: preview which rows would be affected without modifying any data
- `--apply`: execute the erasure
- `--output` | `-o`: directory for the result JSON (defaults to `out/`)

Exactly one of `--check` or `--apply` must be specified.

What it does:
- With `--check`:
  - Calls `__META__.tarkin_erase_check(p_columns, p_values)`, which iterates `tarkin_subject_identifiers`, builds a WHERE clause matching the provided identifier columns (cast to their stored types via `EXECUTE ... USING` for safe parameterisation), counts matching rows in each shadow table, and returns `(schema_name, table_name, erase_strategy, rows_matched)` per table
  - Writes results to a timestamped `out/tarkin_erase_check_<timestamp>.json`
- With `--apply`:
  - Calls `__META__.tarkin_erase_apply(p_columns, p_values)`, which performs the same lookup then applies the table's `erase_strategy`:
    - `DELETE`: deletes matching rows
    - `NULLIFY`: sets all non-identifier columns to NULL (non-nullable columns receive `'[ERASED]'` cast to the column type)
    - `OBFUSCATE`: replaces values with deterministic SHA-256-derived values cast to each column's type (text → hex string; UUID → formatted UUID; integers → bigint derived from hash; bool → parity of first hash byte; other types → `'[ERASED]'`)
  - Logs each operation to `__META__.tarkin_erasures` with `was_scheduled = false`
  - Returns `(schema_name, table_name, erase_strategy, rows_affected)` per table
  - Writes results to a timestamped `out/tarkin_erase_apply_<timestamp>.json`
- Both functions operate on shadow tables directly (bypassing views and `INSTEAD OF` triggers) and use bound parameters throughout
  - Column names come from `tarkin_subject_identifiers` (Tarkin-controlled); values are always `USING` parameters

The `was_scheduled` field on `__META__.tarkin_erasures` distinguishes ad-hoc erasures (`false`) from those triggered by the retention cron job (`true`).

The function `__META__.tarkin_erase_expired_records()` can also be called manually at any time to process expired retention records without waiting for the scheduled cron job.

## tarkin purge
Deletes all build artifacts and output files from the `out/` directory.

Options:
- `--no-warn` | `-n`: skip the confirmation prompt

What it does:
- Prompts for confirmation (unless `--no-warn`)
- Removes and recreates the `out/` directory

## tarkin update
Applies idempotent schema patches to an attached database's `__META__` tables.

Arguments: none

Options:
- `--profile` | `-p` (required): credentials profile
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying

What it does:
- Connects to the live database
- Applies every `__META__` patch for the installed Tarkin version, in order, within a single transaction
- Prints each patch description as it is applied
- Does not compare installed Tarkin versions and does not track which patches have run before

Every patch is idempotent by contract, so `tarkin update` converges a database to the schema that the installed version expects regardless of the version it was attached under, and re-running it has no further effect. It reports the patches it applied, not the ones that changed something.

Patches run in list order, because some are preconditions for others: the `__META__` tables must exist before the discovery functions that read them can be created, as PostgreSQL validates `LANGUAGE sql` function bodies at creation time.

## tarkin query
Generates a SQL query from a natural language prompt using schema metadata from `__META__`, and optionally executes it.

Arguments: none (prompt is collected interactively)

Options:
- `--profile` | `-p` (required): credentials profile
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--build` | `-b`: print the generated SQL and exit without executing
- `--execute` | `--exec` | `-e`: execute the query and return an AI interpretation of the results
At most one of `--build` or `--execute` may be specified.

What it does:
- Connects to the live database
- Reads governance context from `__META__` (build identity, schemas, tables, columns, roles, retention configuration, erasure counts, and row-level security policies) limited to what the connected role can see, with no direct data access
- Prompts the user for a natural language question interactively
- If neither `--build` nor `--execute` is specified, prompts the user to choose whether to execute the query afterwards
- Sends the schema context and question to the AI provider configured in the `[ai]` section of credentials.toml
- Receives a generated SQL query in return
- With `--build`: prints the generated SQL and exits
- With `--execute` (or confirmed interactively): executes the query against the live database under the connected role's permissions, then sends the results back to the AI for interpretation and prints the answer
- Without `--execute`: prints the generated SQL only

Requires an `[ai]` section in credentials.toml with `provider`, `api_key`, and `model` fields.

The identifier-bearing erasure log is not included in query context. The `erasures` key holds `__META__.get_erasure_counts()` output, which reports only the count of rows that were removed without reporting which ones.

## tarkin discover
Reads governed metadata from `__META__` through the discovery functions and prints it as JSON.

Arguments: none

Options:
- `--profile` | `-p` (required): credentials profile
- `--credentials` | `-c`: path to credentials.toml
- `--reauth` | `-r`: if the connection fails on an IAM profile, prompt to re-authorize via AWS SSO before retrying
- `--object` | `-obj`: object to discover, repeatable (or omit to return everything), values are `build`, `schemas`, `tables`, `columns`, `roles`, `retention`, `erasures`, `erasure_counts`, `rls`
- `--schema` | `-s`: restrict to a single schema, applies to `tables`, `columns`, `retention`, `rls`
- `--table` | `-t`: restrict to a single table, applies to `columns`, `retention`, `rls`
- `--since`: lower-bound timestamp for `erasures` and `erasure_counts`
- `--output` | `-o`: directory to also write the result into as `tarkin_discover_<timestamp>.json`, omit to print only to the console

What it does:
- Connects to the live database
- Opens a read-only transaction, calls the requested `__META__` discovery functions, and rolls back
- Prints the combined result as JSON, keyed by object name
- Writes the same JSON to `--output` when specified

Every function returns only what the connected role is cleared to see. Filtering happens inside the function body against `session_user`, not in Tarkin, so the same results come back regardless of which client calls them. `SET ROLE` does not change the result: connect as the role you want to inspect.

## Discovery functions
These are `SECURITY DEFINER` functions in `__META__` with `EXECUTE` granted to `PUBLIC`. They are the supported read interface for third-party tooling, including AI agents: any client with a PostgreSQL connection can call them directly and receives exactly what its role is entitled to.

All return `json`. When there is nothing visible, they return an object with a single `message` field naming the function and the parameters it was called with, rather than an empty array or NULL.

| Function | Returns | Visibility rule                                                                                                                          |
|---|---|------------------------------------------------------------------------------------------------------------------------------------------|
| `get_build()` | `build_id`, `built_at`, `tarkin_version`, `database_name`, `checksum` for the latest build | Any role present in the latest build. The stored governance YAML and profile name are never returned.                                    |
| `get_schemas()` | name, clearance, audit_enabled, description | Schemas the role holds USAGE on.                                                                                                         |
| `get_tables(schema)` | schema, name, clearance, audit_enabled, description | Tables the role holds SELECT on, at or below its clearance.                                                                              |
| `get_columns(schema, table)` | schema, table, name, type, clearance, nullable, sensitive, masking_strategy, description | As `get_tables`, and sensitive columns only when the role has `can_access_sensitive`.                                                    |
| `get_roles()` | name, clearance, capability flags, member_of, description | All roles when the caller has `can_admin`, otherwise only the caller's own record.                                                       |
| `get_retention(schema, table)` | schema, table, erase_strategy, retention_days | As `get_tables`. Only tables enrolled in retention management appear.                                                                    |
| `get_erasures(since)` | erasure_id, erased_at, erased_by, schema, table, column_names, strategy, rows_affected, was_scheduled | `can_admin` only. `column_values` is never returned.                                                                                     |
| `get_erasure_counts(since)` | schema, table, strategy, operations, rows_affected, first_erasure, last_erasure | As `get_tables`. No identifiers, erased values, or actor names .                                                                         |
| `get_rls_policies(schema, table)` | schema, table, policy, permissive, command, roles, using_expr, check_expr | As `get_tables`. Read from `pg_policies` against shadow tables, with shadow schema names mapped back to their public-facing equivalents. |

Notes:
- All functions except `get_erasures` scope to `__META__.tarkin_latest_build_id()`. The erasure log is an append-only audit record spanning builds and carries no `build_id`.
- `get_erasure_counts` joins to the latest build's grants, so erasures on a table since removed from the governance model do not appear. The counts are a compliance signal, not a complete history.
- `get_retention` reports declared configuration only. It does not count rows currently past `__expires_at__`: doing so would require reading shadow tables as the definer, bypassing any RLS policy that constrains the caller's own view of those rows.
- `get_rls_policies` reports live policies from the catalog rather than declared intent from the YAML, so a policy altered outside Tarkin appears as it actually exists.
- These functions are created by `tarkin attach` (as part of every build artifact), refreshed by `tarkin migrate`, and re-applied by `tarkin update`. A database attached under an earlier Tarkin version gains new discovery functions by running `tarkin update`, without a rebuild.
- Each function carries a `COMMENT ON FUNCTION` describing what it returns and how visibility is filtered, so a client listing `pg_catalog.pg_proc` finds a self-describing surface without knowing Tarkin exists.

## __META__.tarkin_governance

A view flattening the discovery functions into one row per visible column, so a client that enumerates tables finds the governance model without knowing the functions exist or how to call them. `SELECT` is granted to `PUBLIC`; the rows are whatever the calling role is cleared to see, because the view reads the same `session_user`-filtered functions.

| Column | Meaning |
|---|---|
| `build_id` | the governance build these rows describe |
| `schema_name`, `table_name`, `column_name` | the column being described |
| `data_type`, `nullable` | declared type and nullability |
| `sensitive` | restricted to roles with `can_access_sensitive` |
| `masking_strategy` | anything other than `none` means the value read through the view layer is transformed, not stored |
| `column_clearance`, `table_clearance` | clearance required |
| `column_description`, `table_description` | the governance YAML descriptions |
| `audit_enabled` | whether pgaudit covers the table |
| `retention_days`, `erase_strategy` | null unless the table is enrolled in retention management |
| `rls_policy_count` | above zero means a query returns a filtered subset of rows |
| `rls_predicates` | the `using_expr` of each policy, joined with `AND` |

```sql
SELECT * FROM __META__.tarkin_governance WHERE sensitive OR masking_strategy <> 'none';
```

The view is created alongside the discovery functions, so `tarkin attach`, `tarkin migrate`, and `tarkin update` all install and refresh it. It carries a `COMMENT ON VIEW` explaining what the masking, sensitivity, and RLS columns mean, so a client reading `pg_description` gets the interpretation with the data.

It is dropped and recreated rather than replaced in place, because replacing a view cannot change its column list and a future column addition would otherwise fail against an existing install.

Note that `__META__.tarkin_governance` and the discovery functions report the governance model as of the attached build, not the live state of the PostgreSQL catalog. Visibility is filtered against `__META__.tarkin_role_tables`, which is written at build time. If a grant is changed outside Tarkin after attach, the discovery surface will continue to describe the model as declared, and an agent reading it may believe it has access it no longer has or miss access that it has gained. Run `tarkin inspect` and `tarkin migrate` to bring the two back into agreement.

## Object comments

Descriptions from the governance YAML are written to the database as `COMMENT ON` statements as well as being stored in `__META__`:

- `COMMENT ON SCHEMA` for each schema description
- `COMMENT ON VIEW` for each table description, including the `_current` view of a versioned table
- `COMMENT ON COLUMN` for each column description

Comments land on the Tarkin-created schema and views, never on the shadow tables. The view layer is dropped by `tarkin detach`, so the comments go with it and the original objects' own comments are never overwritten.

`tarkin migrate` replays every comment rather than diffing them, since `COMMENT ON` is a set operation. Descriptions removed from the YAML are emitted as `COMMENT ON ... IS NULL` so that the database converges.

`tarkin update` does not apply object comments, as it has no governance YAML to read them from. It does apply the `__META__` schema comment and the discovery function comments.

To get object comments onto a database attached under an earlier version, run `tarkin migrate --force` with the current YAML. A version upgrade changes no part of the governance model, so an ordinary migrate finds no differences and refuses; `--force` generates the artifact anyway, carrying the sections that are regenerated rather than diffed.
