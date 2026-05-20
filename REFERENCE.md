# CLI Reference

All commands are run as tarkin <command> [options].

## tarkin help
Alias for tarkin --help. Prints the top-level command list.

## tarkin version
Prints the installed Tarkin version and exits.

## tarkin connect
Tests that one or more credential profiles can reach their configured databases.

Options:
--profile \\/ -p:     test a specific profile (omit to test all profiles in the credentials file)
--credentials \\/ -c: path to credentials.toml (defaults to ~\/.tarkin\/credentials.toml)

What it does:
- Opens a connection
- Runs a minimal probe query
- Prints PASS\/FAIL for each profile along with the PostgreSQL server version and connected user

## tarkin inspect
Inspects a live PostgreSQL database and writes a Tarkin governance YAML describing its current state.

Options:
--profile \/ -p (required):  credentials profile to connect with
--credentials \/ -c:         path to credentials.toml
--output \/ -o:              output path (defaults to out\/<database>_model.yaml)
--validate \/ --no-validate: run semantic validation on the inspected model before writing (default: validate)

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
  - types
  - domains
  - collations
  - operators
  - foreign tables
  - roles (with login\/superuser\/write flags, membership, schema and table grants)
  - existing RLS policies (non-Tarkin policies only, as rls_enabled, rls_force, and rls_policies on each table)
- Detects whether pgaudit and pg_cron are installed
- Writes a YAML that can be edited and passed to tarkin build

## tarkin validate
Parses and semantically validates a governance YAML without connecting to a database.

Arguments:
- config (required): path to governance YAML

What it does:
- Runs the full suite of semantic validation rules, collecting all errors before raising so the operator sees the complete list at once

Validates:
- At least one schema and one role exist
- Audit configuration consistency (table-level audit requires database-level audit; audit_logged must be non-empty if audit_enabled)
- Erasure configuration consistency: is_subject_identifier columns require erase_strategy; erase_strategy without identifier columns is unreachable; OBFUSCATE on non-nullable non-text columns; FKs pointing at subject-identified tables require a strategy on the referencing table
- RLS configuration: rls_policies without rls_enabled; rls_force \/ rls_security_barrier without rls_enabled; empty using_expr; empty roles list; undefined role names; emits a warning (not error) when rls_enabled is set and the configured database version is pre-PG15 (where security_invoker is unavailable)
- Retention configuration consistency: retention_days requires erase_strategy; must be a positive integer; __expires_at__ and __erase_on_expiry__ must not already exist as column names; warns when retention_schedule is set but no tables have retention_days, and vice versa
- Schema uniqueness and non-emptiness
- Table uniqueness, non-emptiness, at least one primary key and no more than one (two separate checks)
- Column uniqueness; generated_expression and default are mutually exclusive; versioned and immutable are mutually exclusive; versioned and generated_expression are mutually exclusive
- Masking strategy\/config consistency (each strategy requires the matching config type)
- Cross-references: index columns, FK local columns, FK referenced schemas\/tables\/columns all exist
- Clearance rules: column clearance must meet table and schema minimums; role clearance range must span the database clearance range
- Role rules: unique names; each role has at least one schema or member_of; referenced schemas exist; member_of parents exist; at least one login role

## tarkin build
Compiles a governance YAML into a build artifact by connecting to the live database.

Arguments:
- config (required): path to governance YAML

Options:
--profile \/ -p:     credentials profile (overrides the profile field in the YAML)
--credentials \/ -c: path to credentials.toml
--output \/ -o:      output directory (defaults to out\/)

What it does:
- Validates the YAML
- Inspects the live database to capture its current state
- Checks pre-conditions: no existing Tarkin shadow schemas; pgaudit installed and preloaded if audit_enabled: true; pg_cron installed and preloaded if any retention is configured
- Generates the full SQL build artifact, which includes:
  - Renames existing schemas to tk_<schema> (shadow schemas)
  - Creates fresh public-facing schemas
  - Moves existing schema objects (sequences, functions, trigger functions, procedures, types, domains, collations, views, materialized views, operators, foreign tables) to the new public schemas
  - Adds versioning columns (__valid_from__, __valid_to__) to versioned tables
  - Adds new generated columns not present in the live database
  - Adds new FK constraints not present in the live database
  - Creates CREATE VIEW statements with column-level masking expressions; views use security_invoker = true on PG15+ when rls_enabled, and security_barrier = true when rls_security_barrier is set
  - Creates INSTEAD OF trigger functions and trigger attachments for all views (handling INSERT\/UPDATE\/DELETE with immutability checks and versioning patterns)
  - Creates roles (CREATE or ALTER) and membership grants
  - Applies schema and table-level GRANT\/REVOKE statements, with column-level SELECT\/UPDATE\/REFERENCES restriction based on clearance and sensitivity
  - Configures pgaudit (merging with existing settings, snapshotting pre-existing values for restoration on detach)
  - Grants pgaudit privileges to tarkin_audit role for audited tables
  - Enables Row Level Security and creates tarkin_rls_<table>_<i> policies on shadow tables
  - Creates per-column btree indexes for is_subject_identifier columns
  - Adds __expires_at__ and __erase_on_expiry__ columns with defaults to retained tables, plus a partial index on __expires_at__ WHERE __erase_on_expiry__ = true
  - Creates __META__.tarkin_erase_check() and __META__.tarkin_erase_apply() functions for on-demand erasure
  - Creates __META__.tarkin_erase_expired_records() sweep function and schedules it via pg_cron if retention_schedule is configured
  - Populates all __META__ tables (builds, schemas, tables, columns, indexes, FKs, roles, grants, moved objects, added FKs, added generated columns, subject identifiers, retention config)
  - Enables pgcrypto extension if any column uses SHA256\/SHA512\/HMAC256 masking or OBFUSCATE erasure
- Writes out\/tarkin_build_<timestamp>.zip containing tarkin_build.json (metadata including artifact_type: "build", checksums, schema list, audit config) and tarkin_build.sql

## tarkin attach
Applies a build or migration artifact to a live database.

Options:
--build \/ -b:       path to artifact zip (defaults to the most recent tarkin_build_*.zip or tarkin_migrate_*.zip in out\/)
--profile \/ -p:     credentials profile (read from the artifact metadata if omitted)
--credentials \/ -c: path to credentials.toml

What it does:
- Reads artifact_type from the artifact metadata and routes accordingly:
  - artifact_type = "build":
    - Verifies no tk_ shadow schemas exist (no existing build attached)
    - Verifies the live database checksum matches the artifact's db_checksum
    - Executes the SQL in a single transaction
  - artifact_type = "migrate"
    - Verifies tk_ shadow schemas are present (a build must be attached)
    - Reads the current build's checksum from __META__.tarkin_builds and verifies it matches the artifact's source_checksum
    - Verifies the database name matches
    - Executes the SQL in a single transaction
- On any failure the transaction is rolled back
- Prints a clear message distinguishing "build" from "migration" throughout

## tarkin detach
Removes a Tarkin governance model from a live database, restoring the original schema state.

Options:
--profile \/ -p (required): credentials profile
--credentials \/ -c:        path to credentials.toml
--keep-versioning \/ -k:    retain __valid_from__ \/ __valid_to__ columns and all historical rows
--drop-versioning \/ -d:    drop versioning columns, keeping only current rows (__valid_to__ = 'infinity')
--no-warn \/ -n:            suppress the confirmation prompt when dropping versioning data
--no-restore-grants \/ -g:  skip restoring pre-attach grants (use if __META__ is unavailable)

What it does:
- Inspects the live database to find tk_ shadow schemas
- Reads __META__ to recover:
  - Tarkin-created roles
  - Revoked grants to restore
  - pgaudit settings to restore
  - Added FK constraints
  - Added generated columns
  - Moved schema objects
  - Subject identifier indexes
  - Retention tables
- Drops INSTEAD OF triggers and trigger functions
- Drops public-facing views (and _current versioned views)
- Optionally drops versioning columns and historical rows
- Drops added FK constraints
- Drops added generated columns
- Drops subject identifier indexes (tarkin_subject_<table>_<col>)
- Unschedules the pg_cron retention job (guarded by a check that pg_cron is installed), drops retention partial indexes, drops __expires_at__ and __erase_on_expiry__ columns
- Moves schema objects (sequences, functions, etc.) back to shadow schemas
- Drops Tarkin-created roles (REASSIGN OWNED, DROP OWNED, DROP ROLE)
- Runs DROP SCHEMA ... CASCADE on the public-facing schemas; renames tk_<schema> back to <schema>
- Drops tarkin_rls_* policies via pg_policies query; disables RLS and NO FORCE on restored tables
- Restores pre-attach grants (schema-level first, then table-level)
- Drops __META__ CASCADE
- Restores pgaudit settings (log, log_catalog, log_relation, role) to pre-attach values
- Resets tarkin.hmac_key GUC
- Prints a note if pgcrypto was enabled by Tarkin (it is not dropped automatically as it may be used by other objects)

## tarkin diff
Compares two governance YAMLs and produces a structured Markdown diff report.

Arguments:
- before (required): path to the baseline governance YAML
- after (required):  path to the target governance YAML

Options:
--output \/ -o: output path (defaults to out\/diff_<before>_<after>.md)

What it does:
- Loads and validates both YAMLs
- Runs diff_projects()
- Writes a Markdown report with a summary line and per-object-type tables showing:
  - Each change (ADDED\/REMOVED\/MODIFIED)
  - The path, field, before\/after values, and migration notes associated with each change

Covers:
- Database fields (including retention_schedule)
- Schemas
- Tables (including erase_strategy, rls_enabled, rls_force, rls_security_barrier, retention_days, and RLS policies by position)
- Columns (including is_subject_identifier)
- Indexes
- Foreign keys
- Roles
- Permissions

## tarkin migrate
Generates a migration artifact from the current live build to a new governance YAML.

Arguments:
- config (required): path to the target governance YAML

Options:
--profile \/ -p:     credentials profile (overrides the YAML's profile field)
--credentials \/ -c: path to credentials.toml
--output \/ -o:      output directory (defaults to out\/)

What it does:
- Validates the target YAML
- Reads the current build's YAML from __META__.tarkin_builds (most recent build)
- Diffs the stored before-YAML against the target after-YAML
- Raises MigrateError if no differences are detected
- Generates ordered, transactional migration SQL in 14 sections:
  - Drop FK constraints for removed or modified FKs
  - Drop all tarkin_rls_* policies and disables RLS on tables whose RLS config changed
  - Drop indexes (for removed or modified non-PK indexes only, PK changes emit a -- WARNING manual intervention stub)
  - Drop views and triggers for all tables in affected schemas
  - Schema changes: CREATE for added schemas (both public and tk_); DROP CASCADE with warning for removed schemas
  - Table changes: CREATE in shadow schema with column definitions and indexes for added tables; DROP with warning for removed tables
  - Column changes: ADD COLUMN for new columns; DROP COLUMN with warning; ALTER COLUMN TYPE with USING cast and warning; SET\/DROP NOT NULL (NOT NULL addition has warning); SET\/DROP DEFAULT; view-layer-only changes (masking, clearance, etc.) are deferred to view recreation
  - Recreate views for all affected schemas using the after-state, including masking expressions, security_invoker, and security_barrier
  - Recreate INSTEAD OF trigger functions and trigger attachments
  - Recreate removed\/modified indexes (PK changes emit a warning stub)
  - Recreate removed\/modified FKs referencing shadow tables
  - Recreate RLS enable\/force and tarkin_rls_* policies for changed tables
  - Revoke existing grants for affected roles, then regenerate roles and grants from the after-state
  - Insert a new __META__.tarkin_builds row with the after-YAML and target checksum
- Writes out\/tarkin_migrate_<timestamp>.zip with tarkin_build.json (metadata including artifact_type: "migrate", source_checksum, target_checksum, change_count, and the full serialised change list) and tarkin_build.sql
- Prints the artifact path and the exact tarkin attach command to apply it (the artifact is identical in structure to a build artifact and is applied with tarkin attach)

## tarkin erase
Erases data subject records from a Tarkin-attached database.

Options:
--profile \/ -p (required):              credentials profile
--credentials \/ -c:                     path to credentials.toml
--column \/ -col (required, repeatable): identifier column name to match on
--value \/ -val (required, repeatable):  value corresponding to each --column, in the same order
--check:                                preview which rows would be affected without modifying any data
--apply:                                execute the erasure
--output \/ -o:                          directory for the result JSON (defaults to out\/)
Exactly one of --check or --apply must be specified.

What it does:
- With option --check
  - Calls __META__.tarkin_erase_check(p_columns, p_values), which iterates tarkin_subject_identifiers, builds a WHERE clause matching the provided identifier columns (cast to their stored types via EXECUTE ... USING for safe parameterisation), counts matching rows in each shadow table, and returns (schema_name, table_name, erase_strategy, rows_matched) per table
  - Writes results to a timestamped out\/tarkin_erase_check_<timestamp>.json
- With option --apply
  - Calls __META__.tarkin_erase_apply(p_columns, p_values), which performs the same lookup then applies the table's erase_strategy:
    - DELETE: deletes matching rows
    - NULLIFY: sets all non-identifier columns to NULL (non-nullable columns receive '[ERASED]' cast to the column type)
    - OBFUSCATE: replaces values with deterministic SHA-256-derived values cast to each column's type (text → hex string; UUID → formatted UUID; integers → bigint derived from hash; bool → parity of first hash byte; other types → '[ERASED]')
  - Logs each operation to __META__.tarkin_erasures with was_scheduled = false
  - Returns (schema_name, table_name, erase_strategy, rows_affected) per table
  - Writes results to a timestamped out\/tarkin_erase_apply_<timestamp>.json
- Both functions operate on shadow tables directly (bypassing views and INSTEAD OF triggers) and use bound parameters throughout
  - Column names come from tarkin_subject_identifiers (Tarkin-controlled), values are always USING parameters

The was_scheduled field on __META__.tarkin_erasures distinguishes ad-hoc erasures (false) from those triggered by the retention cron job (true)
The function __META__.tarkin_erase_expired_records() can also be called manually at any time to process expired retention records without waiting for the scheduled cron job

## tarkin purge
Deletes all build artifacts and output files from the out\/ directory.

Options:
--no-warn \/ -n: skip the confirmation prompt

What it does:
- Prompts for confirmation (unless --no-warn)
- Removes and recreates the out\/ directory

