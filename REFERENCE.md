# CLI Reference

All commands are run as tarkin <command> [options].

## tarkin help
Alias for tarkin --help. Prints the top-level command list.

## tarkin version
Prints the installed Tarkin version and exits.

## tarkin connect
Tests that one or more credential profiles can reach their configured databases.

Options:
--profile | -p:     test a specific profile (omit to test all profiles in the credentials file)
--credentials | -c: path to credentials.toml (defaults to ~/.tarkin/credentials.toml)

What it does:
- Opens a connection
- Runs a minimal probe query
- Prints PASS or FAIL for each profile along with the PostgreSQL server version and connected user

## tarkin inspect
Inspects a live PostgreSQL database and writes a Tarkin governance YAML describing its current state.

Options:
--profile | -p (required):  credentials profile to connect with
--credentials | -c:         path to credentials.toml
--output | -o:              output path (defaults to out/<database>\_model.yaml)
--validate | --no-validate: run semantic validation on the inspected model before writing (default: validate)

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
  - roles (with login/superuser/write flags, membership, schema and table grants)
  - existing RLS policies (non-Tarkin policies only, as rls\_enabled, rls\_force, and rls\_policies on each table)
- Detects whether pgaudit and pg\_cron are installed
- Writes a YAML that can be edited and passed to tarkin build

## tarkin validate
Parses and semantically validates a governance YAML without connecting to a database.

Arguments:
- config (required): path to governance YAML

What it does:
- Runs the full suite of semantic validation rules, collecting all errors before raising so the operator sees the complete list at once

Validates:
- At least one schema and one role exist
- Audit configuration consistency (table-level audit requires database-level audit; audit\_logged must be non-empty if audit\_enabled)
- Erasure configuration consistency: is\_subject\_identifier columns require erase\_strategy; erase\_strategy without identifier columns is unreachable; OBFUSCATE on non-nullable non-text columns; FKs pointing at subject-identified tables require a strategy on the referencing table
- RLS configuration: rls\_policies without rls\_enabled; rls\_force and/or rls\_security\_barrier without rls\_enabled; empty using\_expr; empty roles list; undefined role names; emits a warning (not error) when rls\_enabled is set and the configured database version is pre-PG15 (where security\_invoker is unavailable)
- Retention configuration consistency: retention\_days requires erase\_strategy; must be a positive integer; \_\_expires\_at\_\_ and \_\_erase\_on\_expiry\_\_ must not already exist as column names; warns when retention\_schedule is set but no tables have retention\_days, and vice versa
- Schema uniqueness and non-emptiness
- Table uniqueness, non-emptiness, at least one primary key and no more than one (two separate checks)
- Column uniqueness; generated\_expression and default are mutually exclusive; versioned and immutable are mutually exclusive; versioned and generated\_expression are mutually exclusive
- Masking strategy/config consistency (each strategy requires the matching config type)
- Cross-references: index columns, FK local columns, FK referenced schemas/tables/columns all exist
- Clearance rules: column clearance must meet table and schema minimums; role clearance range must span the database clearance range
- Role rules: unique names; each role has at least one schema or member\_of; referenced schemas exist; member\_of parents exist; at least one login role

## tarkin build
Compiles a governance YAML into a build artifact by connecting to the live database.

Arguments:
- config (required): path to governance YAML

Options:
--profile | -p:     credentials profile (overrides the profile field in the YAML)
--credentials | -c: path to credentials.toml
--output | -o:      output directory (defaults to out/)

What it does:
- Validates the YAML
- Inspects the live database to capture its current state
- Checks pre-conditions: no existing Tarkin shadow schemas; pgaudit installed and preloaded if audit\_enabled: true; pg\_cron installed and preloaded if any retention is configured
- Generates the full SQL build artifact, which includes:
  - Renames existing schemas to tk\_<schema> (shadow schemas)
  - Creates fresh public-facing schemas
  - Moves existing schema objects (sequences, functions, trigger functions, procedures, types, domains, collations, views, materialized views, operators, foreign tables) to the new public schemas
  - Adds versioning columns (\_\_valid\_from\_\_, \_\_valid\_to\_\_) to versioned tables
  - Adds new generated columns not present in the live database
  - Adds new FK constraints not present in the live database
  - Creates CREATE VIEW statements with column-level masking expressions; views use security\_invoker = true on PG15+ when rls\_enabled, and security\_barrier = true when rls\_security\_barrier is set
  - Creates INSTEAD OF trigger functions and trigger attachments for all views (handling INSERT/UPDATE/DELETE with immutability checks and versioning patterns)
  - Creates roles (CREATE or ALTER) and membership grants
  - Applies schema and table-level GRANT/REVOKE statements, with column-level SELECT/UPDATE/REFERENCES restriction based on clearance and sensitivity
  - Configures pgaudit (merging with existing settings, snapshotting pre-existing values for restoration on detach)
  - Grants pgaudit privileges to tarkin\_audit role for audited tables
  - Enables Row Level Security and creates tarkin\_rls\_<table>\_<i> policies on shadow tables
  - Creates per-column btree indexes for is\_subject\_identifier columns
  - Adds \_\_expires\_at\_\_ and \_\_erase\_on\_expiry\_\_ columns with defaults to retained tables, plus a partial index on \_\_expires\_at\_\_ WHERE \_\_erase\_on\_expiry\_\_ = true
  - Creates \_\_META\_\_.tarkin\_erase\_check() and \_\_META\_\_.tarkin\_erase\_apply() functions for on-demand erasure
  - Creates \_\_META\_\_.tarkin\_erase\_expired\_records() sweep function and schedules it via pg\_cron if retention\_schedule is configured
  - Populates all \_\_META\_\_ tables (builds, schemas, tables, columns, indexes, FKs, roles, grants, moved objects, added FKs, added generated columns, subject identifiers, retention config)
  - Enables pgcrypto extension if any column uses SHA256/SHA512/HMAC256 masking or OBFUSCATE erasure
- Writes out/tarkin\_build\_<timestamp>.zip containing tarkin\_build.json (metadata including artifact\_type: "build", checksums, schema list, audit config) and tarkin\_build.sql

## tarkin attach
Applies a build or migration artifact to a live database.

Options:
--build | -b:       path to artifact zip (defaults to the most recent tarkin\_build\_\*.zip or tarkin\_migrate\_\*.zip in out/)
--profile | -p:     credentials profile (read from the artifact metadata if omitted)
--credentials | -c: path to credentials.toml

What it does:
- Reads artifact\_type from the artifact metadata and routes accordingly:
  - artifact\_type = "build":
    - Verifies no tk\_ shadow schemas exist (no existing build attached)
    - Verifies the live database checksum matches the artifact's db\_checksum
    - Executes the SQL in a single transaction
  - artifact\_type = "migrate"
    - Verifies tk\_ shadow schemas are present (a build must be attached)
    - Reads the current build's checksum from \_\_META\_\_.tarkin\_builds and verifies it matches the artifact's source\_checksum
    - Verifies the database name matches
    - Executes the SQL in a single transaction
- On any failure the transaction is rolled back
- Prints a clear message distinguishing "build" from "migration" throughout

## tarkin detach
Removes a Tarkin governance model from a live database, restoring the original schema state.

Options:
--profile | -p (required): credentials profile
--credentials | -c:        path to credentials.toml
--keep-versioning | -k:    retain \_\_valid\_from\_\_ and \_\_valid\_to\_\_ columns, and all historical rows
--drop-versioning | -d:    drop versioning columns, keeping only current rows (\_\_valid\_to\_\_ = 'infinity')
--no-warn | -n:            suppress the confirmation prompt when dropping versioning data
--no-restore-grants | -g:  skip restoring pre-attach grants (use if \_\_META\_\_ is unavailable)

What it does:
- Inspects the live database to find tk\_ shadow schemas
- Reads \_\_META\_\_ to recover:
  - Tarkin-created roles
  - Revoked grants to restore
  - pgaudit settings to restore
  - Added FK constraints
  - Added generated columns
  - Moved schema objects
  - Subject identifier indexes
  - Retention tables
- Drops INSTEAD OF triggers and trigger functions
- Drops public-facing views (and \_current versioned views)
- Optionally drops versioning columns and historical rows
- Drops added FK constraints
- Drops added generated columns
- Drops subject identifier indexes (tarkin\_subject\_<table>\_<col>)
- Unschedules the pg\_cron retention job (guarded by a check that pg\_cron is installed), drops retention partial indexes, drops \_\_expires\_at\_\_ and \_\_erase\_on\_expiry\_\_ columns
- Moves schema objects (sequences, functions, etc.) back to shadow schemas
- Drops Tarkin-created roles (REASSIGN OWNED, DROP OWNED, DROP ROLE)
- Runs DROP SCHEMA ... CASCADE on the public-facing schemas; renames tk\_<schema> back to <schema>
- Drops tarkin\_rls\_\* policies via pg\_policies query; disables RLS and NO FORCE on restored tables
- Restores pre-attach grants (schema-level first, then table-level)
- Drops \_\_META\_\_ CASCADE
- Restores pgaudit settings (log, log\_catalog, log\_relation, role) to pre-attach values
- Resets tarkin.hmac\_key GUC
- Prints a note if pgcrypto was enabled by Tarkin (it is not dropped automatically as it may be used by other objects)

## tarkin diff
Compares two governance YAMLs and produces a structured Markdown diff report.

Arguments:
- before (required): path to the baseline governance YAML
- after (required):  path to the target governance YAML

Options:
--output | -o: output path (defaults to out/diff\_<before>\_<after>.md)

What it does:
- Loads and validates both YAMLs
- Runs diff\_projects()
- Writes a Markdown report with a summary line and per-object-type tables showing:
  - Each change (ADDED/REMOVED/MODIFIED)
  - The path, field, before/after values, and migration notes associated with each change

Covers:
- Database fields (including retention\_schedule)
- Schemas
- Tables (including erase\_strategy, rls\_enabled, rls\_force, rls\_security\_barrier, retention\_days, and RLS policies by position)
- Columns (including is\_subject\_identifier)
- Indexes
- Foreign keys
- Roles
- Permissions

## tarkin migrate
Generates a migration artifact from the current live build to a new governance YAML.

Arguments:
- config (required): path to the target governance YAML

Options:
--profile | -p:     credentials profile (overrides the YAML's profile field)
--credentials | -c: path to credentials.toml
--output | -o:      output directory (defaults to out/)

What it does:
- Validates the target YAML
- Reads the current build's YAML from \_\_META\_\_.tarkin\_builds (most recent build)
- Diffs the stored before-YAML against the target after-YAML
- Raises MigrateError if no differences are detected
- Generates ordered, transactional migration SQL in 14 sections:
  - Drop FK constraints for removed or modified FKs
  - Drop all tarkin\_rls\_\* policies and disables RLS on tables whose RLS config changed
  - Drop indexes (for removed or modified non-PK indexes only, PK changes emit a -- WARNING manual intervention stub)
  - Drop views and triggers for all tables in affected schemas
  - Schema changes: CREATE for added schemas (both public and tk\_); DROP CASCADE with warning for removed schemas
  - Table changes: CREATE in shadow schema with column definitions and indexes for added tables; DROP with warning for removed tables
  - Column changes: ADD COLUMN for new columns; DROP COLUMN with warning; ALTER COLUMN TYPE with USING cast and warning; SET/DROP NOT NULL (NOT NULL addition has warning); SET/DROP DEFAULT; view-layer-only changes (masking, clearance, etc.) are deferred to view recreation
  - Recreate views for all affected schemas using the after-state, including masking expressions, security\_invoker, and security\_barrier
  - Recreate INSTEAD OF trigger functions and trigger attachments
  - Recreate removed/modified indexes (PK changes emit a warning stub)
  - Recreate removed/modified FKs referencing shadow tables
  - Recreate RLS enable/force and tarkin\_rls\_\* policies for changed tables
  - Revoke existing grants for affected roles, then regenerate roles and grants from the after-state
  - Insert a new \_\_META\_\_.tarkin\_builds row with the after-YAML and target checksum
- Writes out/tarkin\_migrate\_<timestamp>.zip with tarkin\_build.json (metadata including artifact\_type: "migrate", source\_checksum, target\_checksum, change\_count, and the full serialised change list) and tarkin\_build.sql
- Prints the artifact path and the exact tarkin attach command to apply it (the artifact is identical in structure to a build artifact and is applied with tarkin attach)

## tarkin erase
Erases data subject records from a Tarkin-attached database.

Options:
--profile | -p (required):              credentials profile
--credentials | -c:                     path to credentials.toml
--column | -col (required, repeatable): identifier column name to match on
--value | -val (required, repeatable):  value corresponding to each --column, in the same order
--check:                                preview which rows would be affected without modifying any data
--apply:                                execute the erasure
--output | -o:                          directory for the result JSON (defaults to out/)
Exactly one of --check or --apply must be specified.

What it does:
- With option --check
  - Calls \_\_META\_\_.tarkin\_erase\_check(p\_columns, p\_values), which iterates tarkin\_subject\_identifiers, builds a WHERE clause matching the provided identifier columns (cast to their stored types via EXECUTE ... USING for safe parameterisation), counts matching rows in each shadow table, and returns (schema\_name, table\_name, erase\_strategy, rows\_matched) per table
  - Writes results to a timestamped out/tarkin\_erase\_check\_<timestamp>.json
- With option --apply
  - Calls \_\_META\_\_.tarkin\_erase\_apply(p\_columns, p\_values), which performs the same lookup then applies the table's erase\_strategy:
    - DELETE: deletes matching rows
    - NULLIFY: sets all non-identifier columns to NULL (non-nullable columns receive '[ERASED]' cast to the column type)
    - OBFUSCATE: replaces values with deterministic SHA-256-derived values cast to each column's type (text → hex string; UUID → formatted UUID; integers → bigint derived from hash; bool → parity of first hash byte; other types → '[ERASED]')
  - Logs each operation to \_\_META\_\_.tarkin\_erasures with was\_scheduled = false
  - Returns (schema\_name, table\_name, erase\_strategy, rows\_affected) per table
  - Writes results to a timestamped out/tarkin\_erase\_apply\_<timestamp>.json
- Both functions operate on shadow tables directly (bypassing views and INSTEAD OF triggers) and use bound parameters throughout
  - Column names come from tarkin\_subject\_identifiers (Tarkin-controlled), values are always USING parameters

The was\_scheduled field on \_\_META\_\_.tarkin\_erasures distinguishes ad-hoc erasures (false) from those triggered by the retention cron job (true)
The function \_\_META\_\_.tarkin\_erase\_expired\_records() can also be called manually at any time to process expired retention records without waiting for the scheduled cron job

## tarkin purge
Deletes all build artifacts and output files from the out/ directory.

Options:
--no-warn / -n: skip the confirmation prompt

What it does:
- Prompts for confirmation (unless --no-warn)
- Removes and recreates the out/ directory

