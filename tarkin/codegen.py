"""Generate the code for Tarkin model builds."""
from __future__ import annotations
import hashlib
import json
import warnings
from datetime import datetime, UTC
from importlib.metadata import version as pkg_version

from .credentials import ConnectionProfile
from .model import (
    ColumnConfig,
    CreditCardMaskConfig,
    EmailMaskConfig,
    ErasureStrategy,
    FullMaskConfig,
    GeneratedColumnStorage,
    GovernanceProject,
    HashAlgorithm,
    HashMaskConfig,
    IpAddressMaskConfig,
    MaskingStrategy,
    MaskConfig,
    NameMaskConfig,
    PartialMaskConfig,
    PartialMaskVisibleSide,
    PhoneMaskConfig,
    SchemaConfig,
    TableConfig,
)
from .serialize import Serializer
from .utils import (
    project_checksum,
    sql_comment_block_section,
    sql_safe_dollar_quote,
    sql_safe_double_quote,
    sql_safe_escape_string,
)


def generate_sql(project: GovernanceProject, current: GovernanceProject, profile: ConnectionProfile) -> str:
    """Generate the full SQL build artifact for a governance project."""
    sections = [
        sql_comment_block_section("TARKIN BUILD", f"Generated at {datetime.now(UTC).isoformat()}"),
        sql_comment_block_section("TRANSACTION START"),
        "BEGIN;\n",
        sql_comment_block_section("HMAC KEY"),
        _generate_hmac_key(project, profile),
        sql_comment_block_section("EXTENSIONS"),
        _generate_extensions(project),
        sql_comment_block_section("META SCHEMA"),
        _generate_meta_schema(),
        sql_comment_block_section("SHADOW SCHEMAS"),
        _generate_shadow_schemas(project),
        sql_comment_block_section("SCHEMA OBJECTS"),
        _generate_schema_objects(project, current),
        sql_comment_block_section("VERSIONING COLUMNS"),
        _generate_versioning_columns(project, current),
        sql_comment_block_section("GENERATED COLUMNS"),
        _generate_new_generated_columns(project, current),
        sql_comment_block_section("FOREIGN KEY CONSTRAINTS"),
        _generate_new_foreign_keys(project, current),
        sql_comment_block_section("VIEWS"),
        _generate_views(project),
        sql_comment_block_section("TRIGGERS"),
        _generate_triggers(project),
        sql_comment_block_section("ROLES"),
        _generate_roles(project, current),
        sql_comment_block_section("GRANTS"),
        _generate_grants(project),
        sql_comment_block_section("AUDIT"),
        _generate_audit(project),
        sql_comment_block_section("AUDIT GRANTS"),
        _generate_audit_grants(project),
        sql_comment_block_section("ROW LEVEL SECURITY"),
        _generate_rls(project),
        sql_comment_block_section("SUBJECT IDENTIFIER INDEXES"),
        _generate_subject_identifier_indexes(project),
        sql_comment_block_section("RETENTION COLUMNS"),
        _generate_retention_columns(project, current),
        sql_comment_block_section("ERASURE FUNCTIONS"),
        _generate_erase_functions(project),
        sql_comment_block_section("RETENTION"),
        _generate_retention(project),
        sql_comment_block_section("META POPULATION"),
        _generate_meta_population(project, current, needs_pgcrypto=_needs_pgcrypto(project)),
        sql_comment_block_section("TRANSACTION END"),
        "COMMIT;\n",
    ]
    return "\n".join(sections)


def _tarkin_view_names_for_schema(schema: SchemaConfig) -> set[str]:
    """Return the set of view names that Tarkin manages for a schema."""
    return {t.name for t in schema.tables} | {f"{t.name}_current" for t in schema.tables if any(c.versioned for c in t.columns)}


def _generate_meta_schema() -> str:
    """Generate DDL for the ``__META__`` schema and all governance tables."""
    return r"""
CREATE SCHEMA IF NOT EXISTS __META__;
REVOKE ALL ON SCHEMA __META__ FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA __META__ FROM PUBLIC;

CREATE TABLE IF NOT EXISTS __META__.tarkin_builds (
    build_id                    bigserial PRIMARY KEY,
    built_at                    timestamptz NOT NULL DEFAULT now(),
    tarkin_version              text NOT NULL,
    profile                     text NOT NULL,
    database_name               text NOT NULL,
    checksum                    text NOT NULL,
    yaml                        text NOT NULL,
    -- Extension tracking
    pgcrypto_enabled_by_tarkin  bool NOT NULL,
    -- pgaudit snapshot: values before Tarkin modified them, for restoration on detach
    pgaudit_log_before          text,
    pgaudit_log_catalog_before  text,
    pgaudit_log_relation_before text,
    pgaudit_role_before         text
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_migrations (
    migration_id    bigserial PRIMARY KEY,
    build_id        bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    migrated_at     timestamptz NOT NULL DEFAULT now(),
    object_type     text NOT NULL,
    object_schema   text,
    object_table    text,
    object_name     text NOT NULL,
    change_type     text NOT NULL,
    checksum_before text,
    checksum_after  text NOT NULL
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_schemas (
    schema_id       bigserial PRIMARY KEY,
    build_id        bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    name            text NOT NULL,
    shadow_name     text NOT NULL,
    clearance       int NOT NULL DEFAULT 0,
    audit_enabled   bool NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_tables (
    table_id        bigserial PRIMARY KEY,
    build_id        bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    schema_name     text NOT NULL,
    name            text NOT NULL,
    clearance       int NOT NULL DEFAULT 0,
    audit_enabled   bool NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_columns (
    column_id            bigserial PRIMARY KEY,
    build_id             bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    schema_name          text NOT NULL,
    table_name           text NOT NULL,
    name                 text NOT NULL,
    type                 text NOT NULL,
    clearance            int NOT NULL DEFAULT 0,
    nullable             bool NOT NULL DEFAULT true,
    "unique"             bool NOT NULL DEFAULT false,
    immutable            bool NOT NULL DEFAULT false,
    versioned            bool NOT NULL DEFAULT false,
    sensitive            bool NOT NULL DEFAULT false,
    masking_strategy     text NOT NULL DEFAULT 'none',
    default_value        text,
    generated_expression text,
    generated_storage    text
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_indexes (
    index_id        bigserial PRIMARY KEY,
    build_id        bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    schema_name     text NOT NULL,
    table_name      text NOT NULL,
    name            text NOT NULL,
    columns         text[] NOT NULL,
    index_type      text NOT NULL DEFAULT 'btree',
    "unique"        bool NOT NULL DEFAULT false,
    primary_key     bool NOT NULL DEFAULT false,
    partial_filter  text
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_foreign_keys (
    fk_id               bigserial PRIMARY KEY,
    build_id            bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    schema_name         text NOT NULL,
    table_name          text NOT NULL,
    name                text NOT NULL,
    column_name         text NOT NULL,
    referenced_schema   text NOT NULL,
    referenced_table    text NOT NULL,
    referenced_column   text NOT NULL
);

-- Tracks FK constraints added by Tarkin (not present before attach) for removal on detach.
CREATE TABLE IF NOT EXISTS __META__.tarkin_added_fks (
    added_fk_id     bigserial PRIMARY KEY,
    build_id        bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    shadow_schema   text NOT NULL,
    table_name      text NOT NULL,
    constraint_name text NOT NULL
);

-- Tracks generated columns added by Tarkin (not present before attach) for removal on detach.
CREATE TABLE IF NOT EXISTS __META__.tarkin_added_generated_cols (
    added_col_id  bigserial PRIMARY KEY,
    build_id      bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    shadow_schema text NOT NULL,
    table_name    text NOT NULL,
    column_name   text NOT NULL
);

-- Tracks schema objects moved to the public schema by Tarkin for reversal on detach.
-- object_kind: 'sequence', 'function', 'trigger_function', 'type', 'domain',
--              'collation', 'view', 'materialized_view', 'procedure'
CREATE TABLE IF NOT EXISTS __META__.tarkin_moved_objects (
    moved_id        bigserial PRIMARY KEY,
    build_id        bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    schema_name     text NOT NULL,   -- public-facing schema name
    shadow_name     text NOT NULL,   -- tk_ schema name
    object_kind     text NOT NULL,
    object_name     text NOT NULL
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_roles (
    role_id               bigserial PRIMARY KEY,
    build_id              bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    name                  text NOT NULL,
    clearance             int NOT NULL DEFAULT 0,
    can_login             bool NOT NULL DEFAULT false,
    can_admin             bool NOT NULL DEFAULT false,
    can_write             bool NOT NULL DEFAULT false,
    can_maintain          bool NOT NULL DEFAULT false,
    can_access_sensitive  bool NOT NULL DEFAULT false,
    added_by_tarkin       bool NOT NULL DEFAULT false,
    member_of             text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_role_schemas (
    rs_id       bigserial PRIMARY KEY,
    build_id    bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    role_name   text NOT NULL,
    schema_name text NOT NULL,
    "usage"     bool NOT NULL DEFAULT true,
    "create"    bool NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS __META__.tarkin_role_tables (
    rt_id        bigserial PRIMARY KEY,
    build_id     bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    role_name    text NOT NULL,
    schema_name  text NOT NULL,
    table_name   text NOT NULL,
    "select"     bool NOT NULL DEFAULT false,
    "insert"     bool NOT NULL DEFAULT false,
    "update"     bool NOT NULL DEFAULT false,
    "delete"     bool NOT NULL DEFAULT false,
    "truncate"   bool NOT NULL DEFAULT false,
    "references" bool NOT NULL DEFAULT false,
    "trigger"    bool NOT NULL DEFAULT false,
    "maintain"   bool NOT NULL DEFAULT false
);

-- Stores grants that Tarkin revoked so they can be restored on detach.
-- schema_name refers to the original (public-facing) schema name.
CREATE TABLE IF NOT EXISTS __META__.tarkin_revoked_grants (
    grant_id    bigserial PRIMARY KEY,
    build_id    bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    role_name   text NOT NULL,
    schema_name text NOT NULL,
    table_name  text,          -- NULL means schema-level grant
    grant_type  text NOT NULL  -- e.g. 'SELECT', 'INSERT', 'USAGE', 'CREATE'
);

-- Tracks tables with subject-identifier columns and their erasure strategy.
-- The erase functions query this table at runtime to discover what to do per table.
CREATE TABLE IF NOT EXISTS __META__.tarkin_subject_identifiers (
    subject_id       bigserial PRIMARY KEY,
    build_id         bigint    NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    schema_name      text      NOT NULL,   -- public-facing schema name
    table_name       text      NOT NULL,   -- public-facing table name
    shadow_schema    text      NOT NULL,   -- tk_ schema where operations execute
    shadow_table     text      NOT NULL,   -- shadow table name (same as table_name)
    identifier_cols  text[]    NOT NULL,   -- columns marked is_subject_identifier
    identifier_types text[]    NOT NULL,   -- corresponding PostgreSQL types
    erase_strategy   text      NOT NULL    -- 'delete', 'nullify', or 'obfuscate'
);

-- Audit log of erasure operations.  Populated by tarkin_erase_apply() and tarkin_erase_expired_records().
CREATE TABLE IF NOT EXISTS __META__.tarkin_erasures (
    erasure_id    bigserial   PRIMARY KEY,
    erased_at     timestamptz NOT NULL DEFAULT now(),
    erased_by     text        NOT NULL DEFAULT current_user,
    schema_name   text        NOT NULL,   -- public-facing schema name
    table_name    text        NOT NULL,   -- public-facing table name
    column_names  text[]      NOT NULL,   -- identifier columns matched
    column_values text[]      NOT NULL,   -- values provided by caller
    strategy      text        NOT NULL,
    rows_affected bigint      NOT NULL,
    was_scheduled bool        NOT NULL DEFAULT false  -- true when run by the retention cron job
);

-- Tracks tables enrolled in retention management.
-- Queried at runtime by tarkin_erase_expired_records().
CREATE TABLE IF NOT EXISTS __META__.tarkin_retention (
    retention_id   bigserial   PRIMARY KEY,
    build_id       bigint      NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    schema_name    text        NOT NULL,  -- public-facing schema name
    table_name     text        NOT NULL,  -- public-facing table name
    erase_strategy text        NOT NULL,  -- strategy to apply on expiry
    retention_days int         NOT NULL
);
""".strip()


def _generate_shadow_schemas(project: GovernanceProject) -> str:
    """Generate SQL to rename existing schemas to shadow names and create fresh public schemas."""
    lines = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        lines.append(f"-- Rename {schema.name} -> {shadow}")
        lines.append(f"ALTER SCHEMA {sql_safe_double_quote(schema.name)} RENAME TO {sql_safe_double_quote(shadow)};")
        lines.append(f"CREATE SCHEMA {sql_safe_double_quote(schema.name)};")
        lines.append("")
    return "\n".join(lines)


def _generate_schema_objects(project: GovernanceProject, current: GovernanceProject) -> str:
    """Move schema objects from shadow schemas to the new public-facing schemas."""
    lines = []

    current_schema_map = {s.name: s for s in current.schemas}

    for schema in project.schemas:
        shadow         = f"tk_{schema.name}"
        current_schema = current_schema_map.get(schema.name)
        if not current_schema:
            continue

        tarkin_view_names = _tarkin_view_names_for_schema(schema)

        for seq_entry in current_schema.sequences:
            seq_name = seq_entry.split()[0]
            lines.append(f"ALTER SEQUENCE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(seq_name)} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for fn_sig in current_schema.functions:
            lines.append(f"ALTER FUNCTION {sql_safe_double_quote(shadow)}.{fn_sig} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for fn_sig in current_schema.trigger_functions:
            lines.append(f"ALTER FUNCTION {sql_safe_double_quote(shadow)}.{fn_sig} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for proc_sig in current_schema.procedures:
            lines.append(f"ALTER PROCEDURE {sql_safe_double_quote(shadow)}.{proc_sig} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for type_entry in current_schema.types:
            parts     = type_entry.split()
            type_name = parts[1] if len(parts) >= 2 else parts[0]
            lines.append(f"ALTER TYPE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(type_name)} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for domain_entry in current_schema.domains:
            domain_name = domain_entry.split()[0]
            lines.append(f"ALTER DOMAIN {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(domain_name)} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for coll_name in current_schema.collations:
            lines.append(f"ALTER COLLATION {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(coll_name)} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for view_name in current_schema.views:
            if view_name not in tarkin_view_names:
                lines.append(f"ALTER VIEW {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(view_name)} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for mv_name in current_schema.materialized_views:
            if mv_name not in tarkin_view_names:
                lines.append(f"ALTER MATERIALIZED VIEW {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(mv_name)} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for op_sig in current_schema.operators:
            lines.append(f"ALTER OPERATOR {sql_safe_double_quote(shadow)}.{op_sig} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        for ft_name in current_schema.foreign_tables:
            lines.append(f"ALTER FOREIGN TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(ft_name)} SET SCHEMA {sql_safe_double_quote(schema.name)};")

        if lines:
            lines.append("")

    return "\n".join(lines)


def _generate_versioning_columns(project: GovernanceProject, current: GovernanceProject) -> str:
    """Generate ALTER TABLE statements to add versioning columns to shadow tables."""
    lines = []
    current_col_map = {(s.name, t.name): {c.name for c in t.columns} for s in current.schemas for t in s.tables}

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            if not any(c.versioned for c in table.columns):
                continue

            existing = current_col_map.get((schema.name, table.name), set())
            has_from = "__valid_from__" in existing
            has_to   = "__valid_to__"   in existing

            if has_from or has_to:
                lines.append(
                    f"-- WARNING: {shadow}.{table.name} already has "
                    f"__valid_from__/__valid_to__ columns. "
                    f"Existing data in these columns will be overwritten by Tarkin versioning."
                )
            if not has_from:
                lines.append(
                    f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} "
                    f"ADD COLUMN __valid_from__ timestamptz NOT NULL DEFAULT now();"
                )
            if not has_to:
                lines.append(
                    f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} "
                    f"ADD COLUMN __valid_to__ timestamptz NOT NULL DEFAULT 'infinity'::timestamptz;"
                )
            lines.append(
                f"CREATE INDEX {sql_safe_double_quote('idx_' + table.name + '_current')} "
                f"ON {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} (__valid_to__) "
                f"WHERE __valid_to__ = 'infinity'::timestamptz;"
            )
            lines.append("")

    return "\n".join(lines)


def _generate_new_generated_columns(project: GovernanceProject, current: GovernanceProject) -> str:
    """
    Add generated columns to shadow tables that are declared in the YAML but absent in the live DB.

    Only STORED generated columns are supported — VIRTUAL storage is a PostgreSQL
    syntax element that is not yet implemented in the PostgreSQL engine itself
    (as of PG16; the keyword is reserved but raises an error if used).  Any column
    with generated_storage='virtual' is skipped with a warning.

    Generated columns that already exist in the live database are left untouched;
    they were preserved when the schema was renamed to its shadow name.
    """
    lines = []

    current_col_map = {
        (s.name, t.name): {c.name for c in t.columns}
        for s in current.schemas
        for t in s.tables
    }

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            existing_cols = current_col_map.get((schema.name, table.name), set())
            for col in table.columns:
                if not col.is_generated:
                    continue
                if col.name in existing_cols:
                    continue

                if col.generated_storage == GeneratedColumnStorage.VIRTUAL:
                    warnings.warn(
                        f"Column '{schema.name}.{table.name}.{col.name}' uses "
                        f"generated_storage='virtual', which is not yet supported by "
                        f"PostgreSQL. The column will be skipped. Use 'stored' instead.",
                        UserWarning,
                        stacklevel=2,
                    )
                    continue

                expr = sql_safe_escape_string(col.generated_expression or "")
                lines.append(
                    f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} "
                    f"ADD COLUMN {sql_safe_double_quote(col.name)} {col.type} "
                    f"GENERATED ALWAYS AS ({expr}) STORED;"
                )

    if lines:
        lines.append("")

    return "\n".join(lines)


def _generate_new_foreign_keys(project: GovernanceProject, current: GovernanceProject) -> str:
    """Add FK constraints to shadow tables that are declared in the YAML but absent in the live DB."""
    lines = []

    current_fk_map = {}
    for s in current.schemas:
        for t in s.tables:
            current_fk_map[(s.name, t.name)] = {fk.name for fk in t.foreign_keys}

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            existing_fks = current_fk_map.get((schema.name, table.name), set())
            for fk in table.foreign_keys:
                if fk.name in existing_fks:
                    continue
                ref_shadow = f"tk_{fk.referenced_schema}"
                lines.append(
                    f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} "
                    f"ADD CONSTRAINT {sql_safe_double_quote(fk.name)} "
                    f"FOREIGN KEY ({sql_safe_double_quote(fk.column)}) "
                    f"REFERENCES {sql_safe_double_quote(ref_shadow)}.{sql_safe_double_quote(fk.referenced_table)} ({sql_safe_double_quote(fk.referenced_column)});"
                )

    if lines:
        lines.append("")

    return "\n".join(lines)


def _generate_extensions(project: GovernanceProject) -> str:
    """Emit CREATE EXTENSION statements for any extensions required by the project."""
    if not _needs_pgcrypto(project):
        return "-- No pgcrypto-dependent features in use.\n"
    return "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"


def _generate_views(project: GovernanceProject) -> str:
    """Generate CREATE VIEW statements for all tables in the project."""
    lines = []
    db_version = 0
    if project.database.version:
        try:
            db_version = int(project.database.version.split(".")[0].split()[0])
        except (ValueError, IndexError):
            pass

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            is_versioned = any(c.versioned for c in table.columns)

            selectable_cols = [
                c for c in table.columns
                if not c.is_generated or c.generated_storage == GeneratedColumnStorage.STORED
            ]

            col_exprs = [_mask_expression(c, shadow, table.name) for c in selectable_cols]
            col_list  = ",\n    ".join(col_exprs)

            with_opts: list[str] = []
            if table.rls_enabled and db_version >= 15:
                with_opts.append("security_invoker = true")
            if table.rls_security_barrier:
                with_opts.append("security_barrier = true")
            with_clause = f" WITH ({', '.join(with_opts)})" if with_opts else ""

            lines.append(
                f"CREATE VIEW {sql_safe_double_quote(schema.name)}.{sql_safe_double_quote(table.name)}{with_clause} AS\n"
                f"    SELECT\n    {col_list}\n"
                f"    FROM {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)};"
            )

            if is_versioned:
                lines.append(
                    f"CREATE VIEW {sql_safe_double_quote(schema.name)}.{sql_safe_double_quote(table.name + '_current')}{with_clause} AS\n"
                    f"    SELECT\n    {col_list}\n"
                    f"    FROM {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)}\n"
                    f"    WHERE __valid_to__ = 'infinity'::timestamptz;"
                )

            lines.append("")

    return "\n".join(lines)


def _generate_hmac_key(project: GovernanceProject, profile: ConnectionProfile) -> str:
    """Generate an ALTER DATABASE statement to set the HMAC key for HMAC256 masking."""
    needs_hmac = any(
        isinstance(col.mask_config, HashMaskConfig)
        and col.mask_config.algorithm == HashAlgorithm.HMAC256
        for schema in project.schemas
        for table in schema.tables
        for col in table.columns
    )
    if not needs_hmac:
        return "-- No HMAC256 columns, skipping hmac_key configuration.\n"

    if not profile.hmac_key:
        raise ValueError(
            "One or more columns use HMAC256 hashing, but no hmac_key is set "
            "in the credentials profile. Add 'hmac_key = \"your-secret\"' to "
            f"the [{profile.profile}] section of your credentials.toml."
        )

    key     = sql_safe_escape_string(profile.hmac_key.get_secret_value())
    db_name = sql_safe_double_quote(project.database.name)
    return (
        f"-- Set HMAC key for HMAC256 masking.\n"
        f"-- This value is stored as a database-level GUC and is visible to superusers.\n"
        f"-- Treat it as a secret and rotate it via credentials.toml if compromised.\n"
        f"-- WARNING: Rotating the key will invalidate all existing HMAC-hashed values.\n"
        f"ALTER DATABASE {db_name} SET tarkin.hmac_key = '{key}';\n"
    )


def _mask_expression(col: ColumnConfig, shadow: str, table_name: str) -> str:
    """Return a SQL expression for a column in a view, applying masking if configured."""
    _default_mask_char = "X"

    strategy = MaskingStrategy(col.masking_strategy)
    ref      = f"{sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)}.{sql_safe_double_quote(col.name)}"
    cfg      = col.mask_config
    expr     = None

    if strategy == MaskingStrategy.NONE:
        return sql_safe_double_quote(col.name)

    def _wrap_null(exp: str, hn: bool) -> str:
        if hn:
            return f"COALESCE({exp}, {_mask_null_literal(strategy, cfg)}) AS {sql_safe_double_quote(col.name)}"
        return f"CASE WHEN {ref} IS NULL THEN NULL ELSE {exp} END AS {sql_safe_double_quote(col.name)}"

    match strategy:
        case MaskingStrategy.FULL:
            if not isinstance(cfg, FullMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'full' requires FullMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
            expr      = f"regexp_replace({ref}::text, '.', '{mask_char}', 'g')"
        case MaskingStrategy.PARTIAL:
            if not isinstance(cfg, PartialMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'partial' requires PartialMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
            length    = cfg.visible_length
            side      = cfg.visible_side
            if side == PartialMaskVisibleSide.RIGHT:
                expr = (
                    f"repeat('{mask_char}', greatest(0, length({ref}::text) - {length})) || "
                    f"right({ref}::text, {length})"
                )
            else:
                expr = (
                    f"left({ref}::text, {length}) || "
                    f"repeat('{mask_char}', greatest(0, length({ref}::text) - {length}))"
                )
        case MaskingStrategy.HASH:
            if not isinstance(cfg, HashMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'hash' requires HashMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            algorithm = cfg.algorithm
            match algorithm:
                case HashAlgorithm.XXHASH:
                    warnings.warn(
                        f"Column '{col.name}': hash algorithm 'xxhash' is non-cryptographic. "
                        f"Hash values are trivially reversible given knowledge of the source "
                        f"data distribution. Use sha256, sha512, or hmac256 for sensitive data.",
                        UserWarning,
                        stacklevel=2,
                    )
                    expr = f"hashtextextended({ref}::text, 0)::text"
                case HashAlgorithm.SHA256:
                    warnings.warn(
                        f"Column '{col.name}': hash algorithm 'sha256' is cryptographic but "
                        f"may be vulnerable to dictionary attacks on low-entropy data "
                        f"(e.g. SSNs, postcodes). Consider hmac256 for stronger protection.",
                        UserWarning,
                        stacklevel=2,
                    )
                    expr = f"encode(digest({ref}::text, 'sha256'), 'hex')"
                case HashAlgorithm.SHA512:
                    warnings.warn(
                        f"Column '{col.name}': hash algorithm 'sha512' is cryptographic but "
                        f"may be vulnerable to dictionary attacks on low-entropy data "
                        f"(e.g. SSNs, postcodes). Consider hmac256 for stronger protection.",
                        UserWarning,
                        stacklevel=2,
                    )
                    expr = f"encode(digest({ref}::text, 'sha512'), 'hex')"
                case HashAlgorithm.HMAC256:
                    expr = f"encode(hmac({ref}::text, {_escape_hmac_key()}, 'sha256'), 'hex')"
                case _:
                    raise ValueError(
                        f"Column '{col.name}': unhandled hash algorithm '{algorithm}'. "
                        f"This is a Tarkin bug. Please file a bug report."
                    )
        case MaskingStrategy.EMAIL:
            if not isinstance(cfg, EmailMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'email' requires EmailMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
            expr = (
                f"left({ref}::text, 1) || "
                f"repeat('{mask_char}', greatest(0, position('@' IN {ref}::text) - 2)) || "
                f"substring({ref}::text FROM position('@' IN {ref}::text))"
            )
        case MaskingStrategy.PHONE:
            if not isinstance(cfg, PhoneMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'phone' requires PhoneMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            visible   = cfg.visible_digits
            mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
            expr = (
                f"repeat('{mask_char}', greatest(0, length(regexp_replace({ref}::text, "
                f"'[^0-9]', '', 'g')) - {visible})) || "
                f"right(regexp_replace({ref}::text, '[^0-9]', '', 'g'), {visible})"
            )
        case MaskingStrategy.CREDIT_CARD:
            if not isinstance(cfg, CreditCardMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'credit_card' requires CreditCardMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
            expr = (
                f"repeat('{mask_char}', 4) || '-' || repeat('{mask_char}', 4) || '-' || "
                f"repeat('{mask_char}', 4) || '-' || "
                f"right(regexp_replace({ref}::text, '[^0-9]', '', 'g'), 4)"
            )
        case MaskingStrategy.IP_ADDRESS:
            if not isinstance(cfg, IpAddressMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'ip_address' requires IpAddressMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            visible   = cfg.visible_octets
            mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
            match visible:
                case 1:
                    expr = (
                        f"'{mask_char}.' || '{mask_char}.' || '{mask_char}.' || "
                        f"split_part({ref}::text, '.', 4)"
                    )
                case 2:
                    expr = (
                        f"'{mask_char}.' || '{mask_char}.' || "
                        f"split_part({ref}::text, '.', 3) || '.' || "
                        f"split_part({ref}::text, '.', 4)"
                    )
                case 3:
                    expr = (
                        f"'{mask_char}.' || "
                        f"split_part({ref}::text, '.', 2) || '.' || "
                        f"split_part({ref}::text, '.', 3) || '.' || "
                        f"split_part({ref}::text, '.', 4)"
                    )
                case _:
                    expr = f"{ref}::text"
        case MaskingStrategy.NAME:
            if not isinstance(cfg, NameMaskConfig):
                raise ValueError(
                    f"Column '{col.name}': strategy 'name' requires NameMaskConfig, "
                    f"got {type(cfg).__name__}"
                )
            mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
            expr = (
                f"array_to_string(ARRAY("
                f"SELECT left(word, 1) || repeat('{mask_char}', 3) "
                f"FROM regexp_split_to_table({ref}::text, '\\s+') AS word"
                f"), ' ')"
            )

    if not expr or cfg is None:
        raise ValueError(
            f"Column '{col.name}': unhandled masking strategy '{strategy}'. "
            f"This is a Tarkin bug. Please file a bug report."
        )

    return _wrap_null(expr, cfg.hide_null)


def _mask_null_literal(strategy: MaskingStrategy, cfg: MaskConfig | None) -> str:
    """Return a SQL literal to use when hide_null=True and the value is NULL."""
    if strategy == MaskingStrategy.HASH:
        if isinstance(cfg, HashMaskConfig):
            match cfg.algorithm:
                case HashAlgorithm.XXHASH:
                    return "hashtextextended('', 0)::text"
                case HashAlgorithm.HMAC256:
                    return "encode(hmac('', current_setting('tarkin.hmac_key'), 'sha256'), 'hex')"
                case _:
                    return f"encode(digest('', '{cfg.algorithm.value}'), 'hex')"
        return "hashtextextended('', 0)::text"

    if cfg and hasattr(cfg, "mask_char") and cfg.mask_char:
        mask_char = cfg.mask_char
    else:
        mask_char = "X"
    return f"'{mask_char}'"


def _generate_triggers(project: GovernanceProject) -> str:
    """Generate INSTEAD OF trigger functions and trigger attachments for all views."""
    lines = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            lines.append(_generate_trigger_function(shadow, table))
            lines.append(_attach_trigger(schema.name, table.name))
            lines.append("")
    return "\n".join(lines)


def _generate_trigger_function(shadow: str, table: TableConfig) -> str:
    """Generate the PL/pgSQL trigger function body for a table."""
    writable_cols = [c.name for c in table.columns if not c.is_generated]

    insert_cols = ", ".join(sql_safe_double_quote(c) for c in writable_cols)
    insert_vals = ", ".join(f"NEW.{sql_safe_double_quote(c)}" for c in writable_cols)

    immutable_checks = _generate_immutable_checks(table) if any(c.immutable for c in table.columns) else ""
    sensitive_stubs  = _generate_sensitive_stubs(table) if any(
        c.sensitive or c.masking_strategy != MaskingStrategy.NONE
        for c in table.columns
    ) else ""

    fn_name     = sql_safe_double_quote("tr_" + table.name)
    tbl_ref     = f"{sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)}"
    pk_filt     = _pk_filter(table, row="NEW")
    pk_filt_old = _pk_filter(table, row="OLD")

    if any(c.versioned for c in table.columns):
        v_insert_cols = insert_cols + ", __valid_from__, __valid_to__"
        v_insert_vals = insert_vals + ", now(), 'infinity'::timestamptz"

        return f"""
CREATE OR REPLACE FUNCTION {sql_safe_double_quote(shadow)}.{fn_name}()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
{sensitive_stubs}
        INSERT INTO {tbl_ref} ({v_insert_cols})
        VALUES ({v_insert_vals});
        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
{immutable_checks}{sensitive_stubs}
        UPDATE {tbl_ref}
        SET __valid_to__ = now()
        WHERE {pk_filt} AND __valid_to__ = 'infinity'::timestamptz;

        INSERT INTO {tbl_ref} ({v_insert_cols})
        VALUES ({v_insert_vals});
        RETURN NEW;

    ELSIF TG_OP = 'DELETE' THEN
        UPDATE {tbl_ref}
        SET __valid_to__ = now()
        WHERE {pk_filt_old} AND __valid_to__ = 'infinity'::timestamptz;
        RETURN OLD;
    END IF;
END;
$$;
""".strip()

    else:
        update_set = ", ".join(f"{sql_safe_double_quote(c)} = NEW.{sql_safe_double_quote(c)}" for c in writable_cols)

        return f"""
CREATE OR REPLACE FUNCTION {sql_safe_double_quote(shadow)}.{fn_name}()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
{sensitive_stubs}
        INSERT INTO {tbl_ref} ({insert_cols})
        VALUES ({insert_vals});
        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
{immutable_checks}{sensitive_stubs}
        UPDATE {tbl_ref}
        SET {update_set}
        WHERE {pk_filt};
        RETURN NEW;

    ELSIF TG_OP = 'DELETE' THEN
        DELETE FROM {tbl_ref}
        WHERE {pk_filt_old};
        RETURN OLD;
    END IF;
END;
$$;
""".strip()


def _generate_immutable_checks(table: TableConfig) -> str:
    """Generate PL/pgSQL checks that raise exceptions on immutable column updates."""
    lines = []
    for col in table.columns:
        if col.immutable:
            lines.append(
                f"        IF OLD.{sql_safe_double_quote(col.name)} IS DISTINCT FROM NEW.{sql_safe_double_quote(col.name)} THEN\n"
                f"            RAISE EXCEPTION 'Column {col.name} is immutable and cannot be updated.';\n"
                f"        END IF;"
            )
    return "\n".join(lines) + "\n" if lines else ""


def _generate_sensitive_stubs(table: TableConfig) -> str:
    """Generate comment stubs for sensitive columns."""
    lines = []
    for col in table.columns:
        if col.sensitive:
            lines.append(
                f"        -- NOTE: '{col.name}' is sensitive. Access is enforced via "
                f"column-level grants on the view layer, not here."
            )
        if col.masking_strategy != MaskingStrategy.NONE:
            lines.append(
                f"        -- NOTE: '{col.name}' uses masking strategy "
                f"'{col.masking_strategy}' in the view layer."
            )
    return "\n".join(lines) + "\n" if lines else ""


def _attach_trigger(schema_name: str, table_name: str) -> str:
    """Generate the CREATE TRIGGER statement attaching a trigger to a view."""
    shadow = f"tk_{schema_name}"
    return (
        f"CREATE TRIGGER {sql_safe_double_quote('tr_' + table_name)}\n"
        f"INSTEAD OF INSERT OR UPDATE OR DELETE\n"
        f"ON {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(table_name)}\n"
        f"FOR EACH ROW EXECUTE FUNCTION {sql_safe_double_quote(shadow)}.{sql_safe_double_quote('tr_' + table_name)}();"
    )


def _pk_filter(table: TableConfig, row: str = "NEW") -> str:
    """Return a WHERE clause fragment matching the primary key columns."""
    pk_cols = [col for idx in table.indexes if idx.primary_key for col in idx.columns]
    if not pk_cols:
        raise ValueError(
            f"Table '{table.name}' has no primary key defined. "
            f"Tarkin requires a primary key to generate safe trigger functions. "
            f"This should have been caught by validation. Please file a bug report."
        )
    return " AND ".join(f"{sql_safe_double_quote(col)} = {row}.{sql_safe_double_quote(col)}" for col in pk_cols)


def _generate_roles(project: GovernanceProject, current: GovernanceProject) -> str:
    """Generate CREATE/ALTER ROLE statements and membership grants."""
    lines = []

    existing_role_names = {r.name for r in current.roles}

    for role in project.roles:
        if role.name in existing_role_names:
            parts = [f"ALTER ROLE {sql_safe_double_quote(role.name)}"]
        else:
            parts = [f"CREATE ROLE {sql_safe_double_quote(role.name)}"]

        parts.append("LOGIN"     if role.can_login  else "NOLOGIN")
        parts.append("SUPERUSER" if role.can_admin  else "NOSUPERUSER")
        parts.append("CREATEDB CREATEROLE" if role.can_write else "NOCREATEDB NOCREATEROLE")

        lines.append(" ".join(parts) + ";")

        for parent in role.member_of:
            lines.append(f"GRANT {sql_safe_double_quote(parent)} TO {sql_safe_double_quote(role.name)};")

        lines.append("")

    if project.database.audit_enabled:
        db_name = sql_safe_double_quote(project.database.name)
        lines.append("CREATE ROLE tarkin_audit NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;")
        lines.append(f"ALTER DATABASE {db_name} SET pgaudit.role = 'tarkin_audit';")
        lines.append("")

    return "\n".join(lines)


def _generate_grants(project: GovernanceProject) -> str:
    """Generate GRANT and REVOKE statements for all roles and schemas."""
    lines = []

    schema_map     = {s.name: s for s in project.schemas}
    table_map      = {(s.name, t.name): t for s in project.schemas for t in s.tables}
    shadow_schemas = [f"tk_{s.name}" for s in project.schemas]

    maintain_grants = []

    for schema in project.schemas:
        for table in schema.tables:
            for col in table.columns:
                if col.sensitive and col.masking_strategy == MaskingStrategy.NONE:
                    warnings.warn(
                        f"Column '{schema.name}.{table.name}.{col.name}' is marked "
                        f"sensitive but has no masking strategy. Roles with "
                        f"can_access_sensitive=True will see the raw value.",
                        UserWarning,
                        stacklevel=2,
                    )

    has_sensitive_cols = any(
        col.sensitive
        for schema in project.schemas
        for table in schema.tables
        for col in table.columns
    )
    if has_sensitive_cols and project.roles and all(r.can_access_sensitive for r in project.roles):
        warnings.warn(
            "All roles have can_access_sensitive=True. Sensitive column restrictions "
            "have no effect. Consider restricting at least one role.",
            UserWarning,
            stacklevel=2,
        )

    for role in project.roles:
        if role.name == project.database.owner:
            continue
        for shadow in shadow_schemas:
            lines.append(f"REVOKE ALL ON SCHEMA {sql_safe_double_quote(shadow)} FROM {sql_safe_double_quote(role.name)};")
            lines.append(f"REVOKE ALL ON ALL TABLES IN SCHEMA {sql_safe_double_quote(shadow)} FROM {sql_safe_double_quote(role.name)};")

    if lines:
        lines.append("")

    for role in project.roles:
        for sp in role.on:
            schema = schema_map.get(sp.name)
            if not schema:
                continue

            schema_privs = []
            if sp.usage:  schema_privs.append("USAGE")
            if sp.create: schema_privs.append("CREATE")
            if schema_privs:
                lines.append(f"GRANT {', '.join(schema_privs)} ON SCHEMA {sql_safe_double_quote(sp.name)} TO {sql_safe_double_quote(role.name)};")

            for tp in sp.tables:
                table = table_map.get((sp.name, tp.name))
                if not table:
                    continue

                if role.clearance < table.clearance:
                    lines.append(f"-- SKIPPED: {role.name} clearance {role.clearance} < table {sp.name}.{tp.name} clearance {table.clearance}")
                    continue

                accessible_cols = [
                    c for c in table.columns
                    if role.clearance >= c.clearance
                    and (not c.sensitive or role.can_access_sensitive)
                ]
                restricted_cols = [
                    c for c in table.columns
                    if c not in accessible_cols
                ]
                restricted = len(restricted_cols) > 0

                if not accessible_cols:
                    lines.append(f"-- SKIPPED: {role.name} has no accessible columns on {sp.name}.{tp.name} (clearance or sensitive restrictions)")
                    lines.append("")
                    continue

                table_privs = []
                if tp.select:     table_privs.append("SELECT")
                if tp.insert:     table_privs.append("INSERT")
                if tp.update:     table_privs.append("UPDATE")
                if tp.delete:     table_privs.append("DELETE")
                if tp.truncate:   table_privs.append("TRUNCATE")
                if tp.references: table_privs.append("REFERENCES")
                if tp.trigger:    table_privs.append("TRIGGER")

                if tp.maintain:
                    try:
                        db_ver = int(project.database.version.split(".")[0].split()[0])
                    except (ValueError, IndexError):
                        db_ver = 0
                    if db_ver < 16:
                        warnings.warn("Grant privilege MAINTAIN is only supported on PostgreSQL 16 and above.")
                    else:
                        if role.can_maintain:
                            maintain_grants.append((f"{sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)}", role.name))
                        else:
                            warnings.warn(
                                f"Role '{role.name}' has maintain=True on {sp.name}.{tp.name} "
                                f"but can_maintain=False on the role. MAINTAIN will not be granted.",
                                UserWarning,
                                stacklevel=2,
                            )

                if table_privs:
                    lines.append(f"GRANT {', '.join(table_privs)} ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} TO {sql_safe_double_quote(role.name)};")

                if restricted:
                    col_list    = ", ".join(sql_safe_double_quote(c.name) for c in accessible_cols)
                    is_db_owner = role.name == project.database.owner

                    if is_db_owner:
                        warnings.warn(
                            f"Role '{role.name}' is the database owner and has restricted "
                            f"columns on {sp.name}.{tp.name}. Column-level REVOKEs have "
                            f"been skipped for this role to preserve shadow schema access.",
                            UserWarning,
                            stacklevel=2,
                        )
                    else:
                        if tp.select:
                            lines.append(f"-- Column-level SELECT restricted by clearance/sensitivity for {role.name} on {sp.name}.{tp.name}")
                            lines.append(f"REVOKE SELECT ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} FROM {sql_safe_double_quote(role.name)};")
                            lines.append(f"GRANT SELECT ({col_list}) ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} TO {sql_safe_double_quote(role.name)};")

                        if tp.update:
                            lines.append(f"-- Column-level UPDATE restricted by clearance/sensitivity for {role.name} on {sp.name}.{tp.name}")
                            lines.append(f"REVOKE UPDATE ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} FROM {sql_safe_double_quote(role.name)};")
                            lines.append(f"GRANT UPDATE ({col_list}) ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} TO {sql_safe_double_quote(role.name)};")

                        if tp.references:
                            lines.append(f"-- Column-level REFERENCES restricted by clearance/sensitivity for {role.name} on {sp.name}.{tp.name}")
                            lines.append(f"REVOKE REFERENCES ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} FROM {sql_safe_double_quote(role.name)};")
                            lines.append(f"GRANT REFERENCES ({col_list}) ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} TO {sql_safe_double_quote(role.name)};")

                        if tp.insert:
                            warnings.warn(
                                f"Role '{role.name}' has INSERT on {sp.name}.{tp.name}, "
                                f"which has restricted columns "
                                f"({', '.join(c.name for c in restricted_cols)}). "
                                f"Ensure restricted columns have DEFAULT values or are "
                                f"nullable, otherwise inserts will fail at runtime.",
                                UserWarning,
                                stacklevel=2,
                            )

            lines.append("")

    # MAINTAIN is a PG16+ privilege; on earlier versions this block is a no-op.
    if maintain_grants:
        grant_stmts = "\n        ".join(
            f"EXECUTE 'GRANT MAINTAIN ON {table_ref} TO {sql_safe_double_quote(role_name)}';"
            for table_ref, role_name in maintain_grants
        )
        lines += [
            "-- MAINTAIN grants (PostgreSQL 16+ only)",
            "DO $$",
            "BEGIN",
            "    IF current_setting('server_version_num')::int >= 160000 THEN",
            f"        {grant_stmts}",
            "    ELSE",
            "        RAISE NOTICE 'Tarkin: MAINTAIN grants skipped (requires PostgreSQL 16+, "
            "found version %)', current_setting('server_version_num');",
            "    END IF;",
            "END;",
            "$$ LANGUAGE plpgsql;",
            "",
        ]

    return "\n".join(lines)


def _generate_audit(project: GovernanceProject) -> str:
    """Generate pgaudit configuration SQL."""
    if not project.database.audit_enabled:
        return "-- Audit logging not enabled for this database.\n"

    levels  = ", ".join(str(level) for level in project.database.audit_logged)
    db_name = sql_safe_double_quote(project.database.name)

    lines = [
        f"-- Configure pgaudit for database {project.database.name}",
        f"-- Additive: merges with existing pgaudit settings rather than overwriting.",
        f"-- Pre-existing values are captured in __META__ for restoration on detach.",
        f"",
        f"DO $$",
        f"DECLARE",
        f"    _existing  text := current_setting('pgaudit.log', true);",
        f"    _new       text := '{levels}';",
        f"    _merged    text;",
        f"BEGIN",
        f"    -- Snapshot pre-existing pgaudit settings into the current build record",
        f"    UPDATE __META__.tarkin_builds",
        f"    SET pgaudit_log_before          = current_setting('pgaudit.log', true),",
        f"        pgaudit_log_catalog_before  = current_setting('pgaudit.log_catalog', true),",
        f"        pgaudit_log_relation_before = current_setting('pgaudit.log_relation', true),",
        f"        pgaudit_role_before         = current_setting('pgaudit.role', true)",
        f"    WHERE build_id = (SELECT max(build_id) FROM __META__.tarkin_builds);",
        f"",
        f"    -- Merge log levels",
        f"    SELECT string_agg(DISTINCT trim(val), ', ')",
        f"    INTO _merged",
        f"    FROM (",
        f"        SELECT unnest(string_to_array(_existing, ',')) AS val",
        f"        UNION",
        f"        SELECT unnest(string_to_array(_new, ',')) AS val",
        f"    ) t",
        f"    WHERE trim(val) <> '';",
        f"    EXECUTE format(",
        f"        'ALTER DATABASE {db_name} SET pgaudit.log = ''%s''',",
        f"        _merged",
        f"    );",
        f"END;",
        f"$$ LANGUAGE plpgsql;",
        f"",
        f"DO $$",
        f"BEGIN",
        f"    IF current_setting('pgaudit.log_catalog', true) <> 'on' THEN",
        f"        EXECUTE 'ALTER DATABASE {db_name} SET pgaudit.log_catalog = off';",
        f"    END IF;",
        f"END;",
        f"$$ LANGUAGE plpgsql;",
        f"",
        f"DO $$",
        f"BEGIN",
        f"    IF current_setting('pgaudit.log_relation', true) <> 'on' THEN",
        f"        EXECUTE 'ALTER DATABASE {db_name} SET pgaudit.log_relation = on';",
        f"    END IF;",
        f"END;",
        f"$$ LANGUAGE plpgsql;",
        f"",
    ]

    excluded_tables = [
        (s.name, t.name)
        for s in project.schemas
        for t in s.tables
        if not t.audit_enabled
    ]
    if excluded_tables:
        lines.append("-- The following tables have audit_enabled=false and are excluded from object-level audit.")
        for schema_name, table_name in excluded_tables:
            lines.append(f"--   {schema_name}.{table_name}")
        lines.append("")

    return "\n".join(lines)


def _generate_audit_grants(project: GovernanceProject) -> str:
    """Grant object-level audit privileges to tarkin_audit for tables where audit_enabled=True."""
    if not project.database.audit_enabled:
        return "-- Audit grants skipped (audit_enabled=false).\n"

    lines = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            if table.audit_enabled:
                lines.append(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} TO tarkin_audit;")

    if not lines:
        return "-- No tables have audit_enabled=true.\n"

    lines.append("")
    return "\n".join(lines)

def _generate_subject_identifier_indexes(project: GovernanceProject) -> str:
    """Generate per-column btree indexes for subject identifier columns on shadow tables."""
    lines: list[str] = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            id_cols = [c for c in table.columns if c.is_subject_identifier]
            if not id_cols:
                continue
            for col in id_cols:
                idx_name = sql_safe_double_quote(f"tarkin_subject_{table.name}_{col.name}")
                lines.append(f"CREATE INDEX {idx_name} ON {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} ({sql_safe_double_quote(col.name)});")
    if not lines:
        return "-- No subject identifier columns defined.\n"
    lines.append("")
    return "\n".join(lines)


def _generate_erase_functions(project: GovernanceProject) -> str:
    """Generate tarkin_erase_check() and tarkin_erase_apply() in __META__."""
    subject_tables = [
        (schema, table)
        for schema in project.schemas
        for table in schema.tables
        if table.erase_strategy is not None
        and any(c.is_subject_identifier for c in table.columns)
    ]

    if not subject_tables:
        return "-- No subject identifier tables defined; erasure functions skipped.\n"

    check_fn = f"""
CREATE OR REPLACE FUNCTION __META__.tarkin_erase_check(
    p_columns text[],
    p_values  text[]
)
RETURNS TABLE (
    schema_name   text,
    table_name    text,
    erase_strategy text,
    rows_matched  bigint
)
LANGUAGE plpgsql AS $$
DECLARE
    rec          __META__.tarkin_subject_identifiers%ROWTYPE;
    where_clause text;
    params       text[];
    col_name     text;
    col_type     text;
    i            int;
    clause_idx   int;
    row_count    bigint;
BEGIN
    IF array_length(p_columns, 1) IS DISTINCT FROM array_length(p_values, 1) THEN
        RAISE EXCEPTION 'tarkin_erase_check: p_columns and p_values must have the same length';
    END IF;

    FOR rec IN
        SELECT * FROM __META__.tarkin_subject_identifiers
    LOOP
        -- Build WHERE clause and corresponding parameter array dynamically.
        -- This avoids the previous hard cap of 8 positional parameters.
        where_clause := '';
        params       := ARRAY[]::text[];
        clause_idx   := 0;

        FOR i IN 1..array_length(p_columns, 1) LOOP
            col_name := p_columns[i];
            IF col_name = ANY(rec.identifier_cols) THEN
                col_type   := rec.identifier_types[array_position(rec.identifier_cols, col_name)];
                clause_idx := clause_idx + 1;
                params     := array_append(params, p_values[i]);
                IF where_clause <> '' THEN
                    where_clause := where_clause || ' AND ';
                END IF;
                where_clause := where_clause || format('%I = $%s::%s', col_name, clause_idx, col_type);
            END IF;
        END LOOP;

        IF where_clause = '' THEN
            CONTINUE;
        END IF;

        EXECUTE format(
            'SELECT count(*) FROM %I.%I WHERE %s',
            rec.shadow_schema, rec.shadow_table, where_clause
        ) USING VARIADIC params
          INTO row_count;

        schema_name    := rec.schema_name;
        table_name     := rec.table_name;
        erase_strategy := rec.erase_strategy;
        rows_matched   := COALESCE(row_count, 0);
        RETURN NEXT;
    END LOOP;
END;
$$;
""".strip()

    apply_fn = f"""
CREATE OR REPLACE FUNCTION __META__.tarkin_erase_apply(
    p_columns text[],
    p_values  text[]
)
RETURNS TABLE (
    schema_name   text,
    table_name    text,
    erase_strategy text,
    rows_affected bigint
)
LANGUAGE plpgsql AS $$
DECLARE
    rec          __META__.tarkin_subject_identifiers%ROWTYPE;
    where_clause text;
    set_clause   text;
    params       text[];
    col_name     text;
    col_type     text;
    i            int;
    j            int;
    clause_idx   int;
    non_id_cols  text[];
    non_id_types text[];
    row_count    bigint;
BEGIN
    IF array_length(p_columns, 1) IS DISTINCT FROM array_length(p_values, 1) THEN
        RAISE EXCEPTION 'tarkin_erase_apply: p_columns and p_values must have the same length';
    END IF;

    FOR rec IN
        SELECT * FROM __META__.tarkin_subject_identifiers
    LOOP
        where_clause := '';
        params       := ARRAY[]::text[];
        clause_idx   := 0;

        FOR i IN 1..array_length(p_columns, 1) LOOP
            col_name := p_columns[i];
            IF col_name = ANY(rec.identifier_cols) THEN
                col_type   := rec.identifier_types[array_position(rec.identifier_cols, col_name)];
                clause_idx := clause_idx + 1;
                params     := array_append(params, p_values[i]);
                IF where_clause <> '' THEN
                    where_clause := where_clause || ' AND ';
                END IF;
                where_clause := where_clause || format('%I = $%s::%s', col_name, clause_idx, col_type);
            END IF;
        END LOOP;

        IF where_clause = '' THEN
            CONTINUE;
        END IF;

        IF rec.erase_strategy = 'delete' THEN
            EXECUTE format(
                'WITH deleted AS (DELETE FROM %I.%I WHERE %s RETURNING 1)
                 SELECT count(*) FROM deleted',
                rec.shadow_schema, rec.shadow_table, where_clause
            ) USING VARIADIC params
              INTO row_count;

        ELSIF rec.erase_strategy IN ('nullify', 'obfuscate') THEN
            SELECT array_agg(column_name ORDER BY ordinal_position),
                   array_agg(udt_name    ORDER BY ordinal_position)
            INTO non_id_cols, non_id_types
            FROM information_schema.columns
            WHERE table_schema = rec.shadow_schema
              AND table_name   = rec.shadow_table
              AND column_name  <> ALL(rec.identifier_cols);

            set_clause := '';
            IF non_id_cols IS NOT NULL THEN
                FOR j IN 1..array_length(non_id_cols, 1) LOOP
                    col_name := non_id_cols[j];
                    col_type := non_id_types[j];
                    IF set_clause <> '' THEN
                        set_clause := set_clause || ', ';
                    END IF;

                    IF rec.erase_strategy = 'nullify' THEN
                        set_clause := set_clause || format(
                            $$%I = CASE WHEN (SELECT is_nullable = 'YES'
                                FROM information_schema.columns
                                WHERE table_schema = %L AND table_name = %L AND column_name = %L)
                                THEN NULL ELSE '[ERASED]'::%s END$$,
                            col_name, rec.shadow_schema, rec.shadow_table, col_name, col_type
                        );
                    ELSE -- obfuscate
                        set_clause := set_clause || format(
                            $$%I = (
                                SELECT CASE
                                    WHEN udt_name ILIKE 'text' OR udt_name ILIKE 'varchar'
                                      OR udt_name ILIKE 'bpchar'
                                        THEN encode(digest(%I::text, 'sha256'), 'hex')
                                    WHEN udt_name ILIKE 'uuid'
                                        THEN (
                                            left(encode(digest(%I::text,'sha256'),'hex'),8)      ||'-'||
                                            substr(encode(digest(%I::text,'sha256'),'hex'),9,4)  ||'-'||
                                            substr(encode(digest(%I::text,'sha256'),'hex'),13,4) ||'-'||
                                            substr(encode(digest(%I::text,'sha256'),'hex'),17,4) ||'-'||
                                            substr(encode(digest(%I::text,'sha256'),'hex'),21,12)
                                        )
                                    WHEN udt_name ILIKE 'int4' OR udt_name ILIKE 'int8'
                                      OR udt_name ILIKE 'int2' OR udt_name ILIKE 'numeric'
                                      OR udt_name ILIKE 'float4' OR udt_name ILIKE 'float8'
                                        THEN (('x'||left(encode(digest(%I::text,'sha256'),'hex'),16))::bit(64)::bigint)::text
                                    WHEN udt_name ILIKE 'bool'
                                        THEN (get_byte(digest(%I::text,'sha256'),0)%%2=0)::text
                                    ELSE '[ERASED]'
                                END::%s
                                FROM information_schema.columns
                                WHERE table_schema=%L AND table_name=%L AND column_name=%L
                            )$$,
                            col_name,
                            col_name, col_name, col_name, col_name, col_name, col_name, col_name, col_name,
                            col_type,
                            rec.shadow_schema, rec.shadow_table, col_name
                        );
                    END IF;
                END LOOP;
            END IF;

            IF set_clause = '' THEN
                EXECUTE format(
                    'WITH deleted AS (DELETE FROM %I.%I WHERE %s RETURNING 1)
                     SELECT count(*) FROM deleted',
                    rec.shadow_schema, rec.shadow_table, where_clause
                ) USING VARIADIC params
                  INTO row_count;
            ELSE
                EXECUTE format(
                    'WITH updated AS (UPDATE %I.%I SET %s WHERE %s RETURNING 1)
                     SELECT count(*) FROM updated',
                    rec.shadow_schema, rec.shadow_table, set_clause, where_clause
                ) USING VARIADIC params
                  INTO row_count;
            END IF;
        END IF;

        row_count := COALESCE(row_count, 0);

        INSERT INTO __META__.tarkin_erasures
            (schema_name, table_name, column_names, column_values, strategy, rows_affected)
        VALUES
            (rec.schema_name, rec.table_name, p_columns, p_values,
             rec.erase_strategy, row_count);

        schema_name    := rec.schema_name;
        table_name     := rec.table_name;
        erase_strategy := rec.erase_strategy;
        rows_affected  := row_count;
        RETURN NEXT;
    END LOOP;
END;
$$;
""".strip()

    return check_fn + "\n\n" + apply_fn + "\n"


def _generate_meta_population(
    project:        GovernanceProject,
    current:        GovernanceProject,
    needs_pgcrypto: bool = False,
) -> str:
    """Generate the DO block that populates all __META__ tables."""
    tarkin_version = pkg_version("tarkin")
    yaml_str       = Serializer.to_yaml_string(project)
    profile        = sql_safe_escape_string(project.database.profile or "")
    database_name  = sql_safe_escape_string(project.database.name)
    checksum       = project_checksum(project)

    dq_open, dq_close = sql_safe_dollar_quote(yaml_str)

    existing_role_names = {r.name for r in current.roles}

    revoked_grants: list[tuple[str, str, str | None, str]] = []

    for schema in project.schemas:
        for current_role in current.roles:
            for sp in current_role.on:
                if sp.name == schema.name:
                    if sp.usage:
                        revoked_grants.append((current_role.name, schema.name, None, "USAGE"))
                    if sp.create:
                        revoked_grants.append((current_role.name, schema.name, None, "CREATE"))
                    for tp in sp.tables:
                        for priv in ["select", "insert", "update", "delete", "truncate", "references", "trigger", "maintain"]:
                            if getattr(tp, priv):
                                revoked_grants.append((current_role.name, schema.name, tp.name, priv.upper()))

    current_fk_map: dict[tuple[str, str], set[str]] = {}
    for s in current.schemas:
        for t in s.tables:
            current_fk_map[(s.name, t.name)] = {fk.name for fk in t.foreign_keys}

    added_fks: list[tuple[str, str, str]] = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            existing_fks = current_fk_map.get((schema.name, table.name), set())
            for fk in table.foreign_keys:
                if fk.name not in existing_fks:
                    added_fks.append((shadow, table.name, fk.name))

    current_col_map: dict[tuple[str, str], set[str]] = {
        (s.name, t.name): {c.name for c in t.columns}
        for s in current.schemas
        for t in s.tables
    }
    added_generated_cols: list[tuple[str, str, str]] = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            existing_cols = current_col_map.get((schema.name, table.name), set())
            for col in table.columns:
                if (col.is_generated
                        and col.generated_storage == GeneratedColumnStorage.STORED
                        and col.name not in existing_cols):
                    added_generated_cols.append((shadow, table.name, col.name))

    current_schema_map = {s.name: s for s in current.schemas}
    moved_objects: list[tuple[str, str, str, str]] = []

    _object_kind_map = [
        ("sequences",          "sequence"),
        ("functions",          "function"),
        ("trigger_functions",  "trigger_function"),
        ("procedures",         "procedure"),
        ("types",              "type"),
        ("domains",            "domain"),
        ("collations",         "collation"),
        ("operators",          "operator"),
        ("foreign_tables",     "foreign_table"),
    ]

    for schema in project.schemas:
        shadow         = f"tk_{schema.name}"
        current_schema = current_schema_map.get(schema.name)
        if not current_schema:
            continue

        tarkin_view_names = _tarkin_view_names_for_schema(schema)

        for attr, kind in _object_kind_map:
            for entry in getattr(current_schema, attr):
                if kind in ("function", "trigger_function", "procedure"):
                    obj_name = entry.split("(")[0].split()[0]
                elif kind == "operator":
                    obj_name = entry
                else:
                    obj_name = entry.split()[0]
                moved_objects.append((schema.name, shadow, kind, obj_name))

        for view_name in current_schema.views:
            if view_name not in tarkin_view_names:
                moved_objects.append((schema.name, shadow, "view", view_name))

        for mv_name in current_schema.materialized_views:
            if mv_name not in tarkin_view_names:
                moved_objects.append((schema.name, shadow, "materialized_view", mv_name))

    lines = ["DO $$", "DECLARE", "    v_build_id bigint;", "BEGIN"]

    lines += [
        f"    INSERT INTO __META__.tarkin_builds (tarkin_version, profile, database_name, checksum, yaml, pgcrypto_enabled_by_tarkin)",
        f"    VALUES (",
        f"        '{tarkin_version}',",
        f"        '{profile}',",
        f"        '{database_name}',",
        f"        '{checksum}',",
        f"        {dq_open}{yaml_str}{dq_close},",
        f"        {str(needs_pgcrypto).lower()}",
        f"    )",
        f"    RETURNING build_id INTO v_build_id;",
        "",
    ]

    for schema in project.schemas:
        sn = sql_safe_escape_string(schema.name)
        lines.append(
            f"    INSERT INTO __META__.tarkin_schemas (build_id, name, shadow_name, clearance, audit_enabled) "
            f"VALUES (v_build_id, '{sn}', 'tk_{sn}', {schema.clearance}, {str(schema.audit_enabled).lower()});"
        )
        sc = _object_checksum({"name": schema.name, "clearance": schema.clearance})
        lines.append(
            f"    INSERT INTO __META__.tarkin_migrations "
            f"(build_id, object_type, object_schema, object_name, change_type, checksum_before, checksum_after) "
            f"VALUES (v_build_id, 'schema', NULL, '{sn}', 'created', NULL, '{sc}');"
        )
    lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            sn = sql_safe_escape_string(schema.name)
            tn = sql_safe_escape_string(table.name)
            lines.append(
                f"    INSERT INTO __META__.tarkin_tables (build_id, schema_name, name, clearance, audit_enabled) "
                f"VALUES (v_build_id, '{sn}', '{tn}', {table.clearance}, {str(table.audit_enabled).lower()});"
            )
            tc = _object_checksum({"schema": schema.name, "name": table.name, "clearance": table.clearance})
            lines.append(
                f"    INSERT INTO __META__.tarkin_migrations "
                f"(build_id, object_type, object_schema, object_table, object_name, change_type, checksum_before, checksum_after) "
                f"VALUES (v_build_id, 'table', '{sn}', NULL, '{tn}', 'created', NULL, '{tc}');"
            )
    lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            for col in table.columns:
                sn  = sql_safe_escape_string(schema.name)
                tn  = sql_safe_escape_string(table.name)
                cn  = sql_safe_escape_string(col.name)
                ct  = sql_safe_escape_string(col.type)
                dv  = f"'{sql_safe_escape_string(col.default)}'" if col.default else "NULL"
                ge  = f"'{sql_safe_escape_string(col.generated_expression)}'" if col.generated_expression else "NULL"
                ms  = sql_safe_escape_string(col.masking_strategy)
                gs  = sql_safe_escape_string(col.generated_storage)
                lines.append(
                    f"    INSERT INTO __META__.tarkin_columns "
                    f"(build_id, schema_name, table_name, name, type, clearance, nullable, \"unique\", "
                    f"immutable, versioned, sensitive, masking_strategy, "
                    f"default_value, generated_expression, generated_storage) "
                    f"VALUES (v_build_id, '{sn}', '{tn}', '{cn}', '{ct}', {col.clearance}, "
                    f"{str(col.nullable).lower()}, {str(col.unique).lower()}, "
                    f"{str(col.immutable).lower()}, {str(col.versioned).lower()}, "
                    f"{str(col.sensitive).lower()}, '{ms}', {dv}, {ge}, '{gs}');"
                )
                cc = _object_checksum({
                    "schema": schema.name, "table": table.name, "name": col.name,
                    "type": col.type, "clearance": col.clearance,
                    "masking_strategy": col.masking_strategy,
                })
                lines.append(
                    f"    INSERT INTO __META__.tarkin_migrations "
                    f"(build_id, object_type, object_schema, object_table, object_name, change_type, checksum_before, checksum_after) "
                    f"VALUES (v_build_id, 'column', '{sn}', '{tn}', '{cn}', 'created', NULL, '{cc}');"
                )
    lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            for idx in table.indexes:
                sn  = sql_safe_escape_string(schema.name)
                tn  = sql_safe_escape_string(table.name)
                idn = sql_safe_escape_string(idx.name)
                ca  = "ARRAY[" + ", ".join(f"'{c}'" for c in idx.columns) + "]"
                pf  = f"'{sql_safe_escape_string(idx.partial_filter)}'" if idx.partial_filter else "NULL"
                lines.append(
                    f"    INSERT INTO __META__.tarkin_indexes "
                    f"(build_id, schema_name, table_name, name, columns, index_type, \"unique\", primary_key, partial_filter) "
                    f"VALUES (v_build_id, '{sn}', '{tn}', '{idn}', {ca}, '{idx.index_type}', "
                    f"{str(idx.unique).lower()}, {str(idx.primary_key).lower()}, {pf});"
                )
    lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            for fk in table.foreign_keys:
                sn  = sql_safe_escape_string(schema.name)
                tn  = sql_safe_escape_string(table.name)
                fn_ = sql_safe_escape_string(fk.name)
                lines.append(
                    f"    INSERT INTO __META__.tarkin_foreign_keys "
                    f"(build_id, schema_name, table_name, name, column_name, "
                    f"referenced_schema, referenced_table, referenced_column) "
                    f"VALUES (v_build_id, '{sn}', '{tn}', '{fn_}', "
                    f"'{sql_safe_escape_string(fk.column)}', "
                    f"'{sql_safe_escape_string(fk.referenced_schema)}', "
                    f"'{sql_safe_escape_string(fk.referenced_table)}', "
                    f"'{sql_safe_escape_string(fk.referenced_column)}');"
                )
    lines.append("")

    for (shadow, table_name, constraint_name) in added_fks:
        sh = sql_safe_escape_string(shadow)
        tn = sql_safe_escape_string(table_name)
        cn = sql_safe_escape_string(constraint_name)
        lines.append(
            f"    INSERT INTO __META__.tarkin_added_fks "
            f"(build_id, shadow_schema, table_name, constraint_name) "
            f"VALUES (v_build_id, '{sh}', '{tn}', '{cn}');"
        )
    if added_fks:
        lines.append("")

    for (shadow, table_name, col_name) in added_generated_cols:
        sh = sql_safe_escape_string(shadow)
        tn = sql_safe_escape_string(table_name)
        cn = sql_safe_escape_string(col_name)
        lines.append(
            f"    INSERT INTO __META__.tarkin_added_generated_cols "
            f"(build_id, shadow_schema, table_name, column_name) "
            f"VALUES (v_build_id, '{sh}', '{tn}', '{cn}');"
        )
    if added_generated_cols:
        lines.append("")

    for (schema_name, shadow, kind, obj_name) in moved_objects:
        sn = sql_safe_escape_string(schema_name)
        sh = sql_safe_escape_string(shadow)
        kn = sql_safe_escape_string(kind)
        on = sql_safe_escape_string(obj_name)
        lines.append(
            f"    INSERT INTO __META__.tarkin_moved_objects "
            f"(build_id, schema_name, shadow_name, object_kind, object_name) "
            f"VALUES (v_build_id, '{sn}', '{sh}', '{kn}', '{on}');"
        )
    if moved_objects:
        lines.append("")

    for role in project.roles:
        rn  = sql_safe_escape_string(role.name)
        moa = ("ARRAY[" + ", ".join(f"'{sql_safe_escape_string(m)}'" for m in role.member_of) + "]"
               if role.member_of else "ARRAY[]::text[]")
        added = str(role.name not in existing_role_names).lower()
        lines.append(
            f"    INSERT INTO __META__.tarkin_roles "
            f"(build_id, name, clearance, can_login, can_admin, can_write, "
            f"can_maintain, can_access_sensitive, added_by_tarkin, member_of) "
            f"VALUES (v_build_id, '{rn}', {role.clearance}, "
            f"{str(role.can_login).lower()}, {str(role.can_admin).lower()}, "
            f"{str(role.can_write).lower()}, {str(role.can_maintain).lower()}, "
            f"{str(role.can_access_sensitive).lower()}, {added}, "
            f"{moa});"
        )
        rc = _object_checksum({
            "name": role.name, "clearance": role.clearance,
            "can_login": role.can_login, "can_admin": role.can_admin,
        })
        lines.append(
            f"    INSERT INTO __META__.tarkin_migrations "
            f"(build_id, object_type, object_name, change_type, checksum_before, checksum_after) "
            f"VALUES (v_build_id, 'role', '{rn}', 'created', NULL, '{rc}');"
        )
    lines.append("")

    for role in project.roles:
        for sp in role.on:
            rn = sql_safe_escape_string(role.name)
            sn = sql_safe_escape_string(sp.name)
            lines.append(
                f"    INSERT INTO __META__.tarkin_role_schemas "
                f"(build_id, role_name, schema_name, \"usage\", \"create\") "
                f"VALUES (v_build_id, '{rn}', '{sn}', "
                f"{str(sp.usage).lower()}, {str(sp.create).lower()});"
            )
    lines.append("")

    for role in project.roles:
        for sp in role.on:
            for tp in sp.tables:
                rn = sql_safe_escape_string(role.name)
                sn = sql_safe_escape_string(sp.name)
                tn = sql_safe_escape_string(tp.name)
                lines.append(
                    f"    INSERT INTO __META__.tarkin_role_tables "
                    f"(build_id, role_name, schema_name, table_name, \"select\", "
                    f"\"insert\", \"update\", \"delete\", \"truncate\", \"references\", \"trigger\", \"maintain\") "
                    f"VALUES (v_build_id, '{rn}', '{sn}', '{tn}', "
                    f"{str(tp.select).lower()}, {str(tp.insert).lower()}, "
                    f"{str(tp.update).lower()}, {str(tp.delete).lower()}, "
                    f"{str(tp.truncate).lower()}, {str(tp.references).lower()}, "
                    f"{str(tp.trigger).lower()}, {str(tp.maintain).lower()});"
                )
    lines.append("")

    if project.database.audit_enabled:
        lines.append(
            f"    INSERT INTO __META__.tarkin_roles "
            f"(build_id, name, clearance, can_login, can_admin, can_write, "
            f"can_maintain, can_access_sensitive, added_by_tarkin, member_of) "
            f"VALUES (v_build_id, 'tarkin_audit', 0, false, false, false, false, false, true, ARRAY[]::text[]);"
        )

    for (role_name, schema_name, table_name, grant_type) in revoked_grants:
        rn = sql_safe_escape_string(role_name)
        sn = sql_safe_escape_string(schema_name)
        tn = f"'{sql_safe_escape_string(table_name)}'" if table_name else "NULL"
        gt = sql_safe_escape_string(grant_type)
        lines.append(
            f"    INSERT INTO __META__.tarkin_revoked_grants "
            f"(build_id, role_name, schema_name, table_name, grant_type) "
            f"VALUES (v_build_id, '{rn}', '{sn}', {tn}, '{gt}');"
        )
    if revoked_grants:
        lines.append("")

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            id_cols = [c for c in table.columns if c.is_subject_identifier]
            if not id_cols or table.erase_strategy is None:
                continue
            sn        = sql_safe_escape_string(schema.name)
            tn        = sql_safe_escape_string(table.name)
            sh        = sql_safe_escape_string(shadow)
            es        = sql_safe_escape_string(str(table.erase_strategy))
            col_names = "ARRAY[" + ", ".join(f"'{sql_safe_escape_string(c.name)}'" for c in id_cols) + "]"
            col_types = "ARRAY[" + ", ".join(f"'{sql_safe_escape_string(c.type)}'" for c in id_cols) + "]"
            lines.append(
                f"    INSERT INTO __META__.tarkin_subject_identifiers "
                f"(build_id, schema_name, table_name, shadow_schema, shadow_table, "
                f"identifier_cols, identifier_types, erase_strategy) "
                f"VALUES (v_build_id, '{sn}', '{tn}', '{sh}', '{tn}', "
                f"{col_names}, {col_types}, '{es}');"
            )
    lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            if table.retention_days is None or table.erase_strategy is None:
                continue
            sn = sql_safe_escape_string(schema.name)
            tn = sql_safe_escape_string(table.name)
            es = sql_safe_escape_string(str(table.erase_strategy))
            lines.append(
                f"    INSERT INTO __META__.tarkin_retention "
                f"(build_id, schema_name, table_name, erase_strategy, retention_days) "
                f"VALUES (v_build_id, '{sn}', '{tn}', '{es}', {table.retention_days});"
            )
    lines.append("")

    lines += ["END;", "$$;"]
    return "\n".join(lines)


def _generate_rls(project: GovernanceProject) -> str:
    """Generate ENABLE ROW LEVEL SECURITY and CREATE POLICY statements."""
    import warnings
    lines: list[str] = []

    db_version = 0
    if project.database.version:
        try:
            db_version = int(project.database.version.split(".")[0].split()[0])
        except (ValueError, IndexError):
            pass

    rls_tables = [
        f"{schema.name}.{table.name}"
        for schema in project.schemas
        for table in schema.tables
        if table.rls_enabled
    ]

    if rls_tables and db_version and db_version < 15:
        warnings.warn(
            f"Database version is PostgreSQL {db_version} (< 15). "
            f"The security_invoker view option is not available before PG15 — "
            f"RLS policies on {', '.join(rls_tables)} will evaluate as the view "
            f"owner rather than the querying user, silently defeating access control. "
            f"Upgrade to PostgreSQL 15+ for correct RLS behaviour.",
            UserWarning,
            stacklevel=2,
        )

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            if not table.rls_enabled:
                continue

            tbl_ref = f"{sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)}"
            lines.append(f"ALTER TABLE {tbl_ref} ENABLE ROW LEVEL SECURITY;")
            if table.rls_force:
                lines.append(f"ALTER TABLE {tbl_ref} FORCE ROW LEVEL SECURITY;")

            for i, policy in enumerate(table.rls_policies):
                policy_name  = sql_safe_double_quote(f"tarkin_rls_{table.name}_{i}")
                roles_clause = ", ".join(
                    r if r == "PUBLIC" else sql_safe_double_quote(r)
                    for r in policy.roles
                )
                check_clause = (
                    f"\n    WITH CHECK ({policy.check_expr})"
                    if policy.check_expr is not None
                    else ""
                )
                lines.append(
                    f"CREATE POLICY {policy_name}\n"
                    f"    ON {tbl_ref}\n"
                    f"    TO {roles_clause}\n"
                    f"    USING ({policy.using_expr}){check_clause};"
                )

            lines.append("")

    if not lines:
        return "-- No row-level security policies defined.\n"

    return "\n".join(lines)


def _needs_pgcrypto(project: GovernanceProject) -> bool:
    """Return True if any column requires pgcrypto for hashing or erasure obfuscation."""
    has_hash = any(
        isinstance(col.mask_config, HashMaskConfig)
        and col.mask_config.algorithm in (
            HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.HMAC256
        )
        for schema in project.schemas
        for table in schema.tables
        for col in table.columns
    )
    has_obfuscate = any(
        table.erase_strategy == ErasureStrategy.OBFUSCATE
        for schema in project.schemas
        for table in schema.tables
    )
    return has_hash or has_obfuscate


def _generate_retention_columns(project: GovernanceProject, current: GovernanceProject) -> str:
    """Add __expires_at__ and __erase_on_expiry__ columns to retained shadow tables."""
    lines: list[str] = []

    current_col_map = {
        (s.name, t.name): {c.name for c in t.columns}
        for s in current.schemas
        for t in s.tables
    }

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            if table.retention_days is None:
                continue

            existing = current_col_map.get((schema.name, table.name), set())
            tbl_ref  = f"{sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)}"
            days     = table.retention_days

            if "__expires_at__" not in existing:
                lines.append(
                    f"ALTER TABLE {tbl_ref} "
                    f"ADD COLUMN __expires_at__ timestamptz NOT NULL "
                    f"DEFAULT (now() + interval '{days} days');"
                )

            if "__erase_on_expiry__" not in existing:
                lines.append(
                    f"ALTER TABLE {tbl_ref} "
                    f"ADD COLUMN __erase_on_expiry__ bool NOT NULL DEFAULT true;"
                )

            lines.append(
                f"CREATE INDEX {sql_safe_double_quote('idx_' + table.name + '_expires_at')} "
                f"ON {tbl_ref} (__expires_at__) "
                f"WHERE __erase_on_expiry__ = true;"
            )
            lines.append("")

    if not lines:
        return "-- No tables configured for retention.\n"

    return "\n".join(lines)


def _generate_retention(project: GovernanceProject) -> str:
    """Generate tarkin_erase_expired_records() and the pg_cron job."""
    retained = [
        (schema, table)
        for schema in project.schemas
        for table in schema.tables
        if table.retention_days is not None and table.erase_strategy is not None
    ]

    if not retained:
        return "-- No retention configured.\n"

    db_name  = project.database.name
    schedule = project.database.retention_schedule

    sweep_fn = """
CREATE OR REPLACE FUNCTION __META__.tarkin_erase_expired_records()
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    rec          __META__.tarkin_retention%ROWTYPE;
    shadow_schema text;
    shadow_table  text;
    where_clause  text;
    set_clause    text;
    col_name      text;
    col_type      text;
    non_id_cols   text[];
    non_id_types  text[];
    j             int;
    row_count     bigint;
BEGIN
    FOR rec IN SELECT * FROM __META__.tarkin_retention LOOP
        shadow_schema := 'tk_' || rec.schema_name;
        shadow_table  := rec.table_name;
        where_clause  := '__expires_at__ <= now() AND __erase_on_expiry__ = true';

        IF rec.erase_strategy = 'delete' THEN
            EXECUTE format(
                'WITH d AS (DELETE FROM %I.%I WHERE %s RETURNING 1) SELECT count(*) FROM d',
                shadow_schema, shadow_table, where_clause
            ) INTO row_count;

        ELSIF rec.erase_strategy IN ('nullify', 'obfuscate') THEN
            SELECT array_agg(column_name ORDER BY ordinal_position),
                   array_agg(udt_name    ORDER BY ordinal_position)
            INTO non_id_cols, non_id_types
            FROM information_schema.columns
            WHERE table_schema = shadow_schema
              AND table_name   = shadow_table
              AND column_name NOT IN ('__expires_at__', '__erase_on_expiry__');

            set_clause := '';
            IF non_id_cols IS NOT NULL THEN
                FOR j IN 1..array_length(non_id_cols, 1) LOOP
                    col_name := non_id_cols[j];
                    col_type := non_id_types[j];
                    IF set_clause <> '' THEN set_clause := set_clause || ', '; END IF;

                    IF rec.erase_strategy = 'nullify' THEN
                        set_clause := set_clause || format(
                            $$%I = CASE WHEN (SELECT is_nullable = 'YES' FROM information_schema.columns
                                WHERE table_schema = %L AND table_name = %L AND column_name = %L)
                                THEN NULL ELSE '[ERASED]'::%s END$$,
                            col_name, shadow_schema, shadow_table, col_name, col_type);
                    ELSE -- obfuscate
                        set_clause := set_clause || format(
                            $$%I = (SELECT CASE
                                WHEN udt_name ILIKE 'text' OR udt_name ILIKE 'varchar' OR udt_name ILIKE 'bpchar'
                                    THEN encode(digest(%I::text, 'sha256'), 'hex')
                                WHEN udt_name ILIKE 'uuid'
                                    THEN (left(encode(digest(%I::text,'sha256'),'hex'),8)||'-'||
                                          substr(encode(digest(%I::text,'sha256'),'hex'),9,4)||'-'||
                                          substr(encode(digest(%I::text,'sha256'),'hex'),13,4)||'-'||
                                          substr(encode(digest(%I::text,'sha256'),'hex'),17,4)||'-'||
                                          substr(encode(digest(%I::text,'sha256'),'hex'),21,12))
                                WHEN udt_name ILIKE 'int4' OR udt_name ILIKE 'int8' OR udt_name ILIKE 'int2'
                                  OR udt_name ILIKE 'numeric' OR udt_name ILIKE 'float4' OR udt_name ILIKE 'float8'
                                    THEN (('x'||left(encode(digest(%I::text,'sha256'),'hex'),16))::bit(64)::bigint)::text
                                WHEN udt_name ILIKE 'bool'
                                    THEN (get_byte(digest(%I::text,'sha256'),0)%%2=0)::text
                                ELSE '[ERASED]'
                            END::%s FROM information_schema.columns
                            WHERE table_schema=%L AND table_name=%L AND column_name=%L)$$,
                            col_name,
                            col_name, col_name, col_name, col_name, col_name, col_name, col_name, col_name,
                            col_type, shadow_schema, shadow_table, col_name);
                    END IF;
                END LOOP;
            END IF;

            IF set_clause = '' THEN
                EXECUTE format(
                    'WITH d AS (DELETE FROM %I.%I WHERE %s RETURNING 1) SELECT count(*) FROM d',
                    shadow_schema, shadow_table, where_clause
                ) INTO row_count;
            ELSE
                EXECUTE format(
                    'WITH u AS (UPDATE %I.%I SET %s WHERE %s RETURNING 1) SELECT count(*) FROM u',
                    shadow_schema, shadow_table, set_clause, where_clause
                ) INTO row_count;
            END IF;
        END IF;

        row_count := COALESCE(row_count, 0);
        IF row_count > 0 THEN
            INSERT INTO __META__.tarkin_erasures
                (schema_name, table_name, column_names, column_values,
                 strategy, rows_affected, was_scheduled)
            VALUES
                (rec.schema_name, rec.table_name,
                 ARRAY['__expires_at__'], ARRAY[now()::text],
                 rec.erase_strategy, row_count, true);
        END IF;
    END LOOP;
END;
$$;
""".strip()

    lines = [sweep_fn, ""]

    if schedule:
        job_name = f"tarkin_retention_{db_name}"
        lines += [
            f"-- Register pg_cron job '{job_name}'",
            f"SELECT cron.unschedule(jobname) FROM cron.job WHERE jobname = '{job_name}';",
            f"SELECT cron.schedule(",
            f"    '{job_name}',",
            f"    '{sql_safe_escape_string(schedule)}',",
            f"    'SELECT __META__.tarkin_erase_expired_records()'",
            f");",
            "",
            f"-- Note: __expires_at__ and __erase_on_expiry__ can be set manually.",
            f"-- Set __erase_on_expiry__ = false on any row to exempt it from scheduled deletion (legal hold).",
        ]
    else:
        lines += [
            "-- No retention_schedule configured; pg_cron job not created.",
            "-- Call SELECT __META__.tarkin_erase_expired_records() manually to process expired records.",
        ]

    return "\n".join(lines) + "\n"


def _escape_hmac_key() -> str:
    """Return the SQL expression for the HMAC key GUC."""
    return "current_setting('tarkin.hmac_key')"


def _object_checksum(obj: dict) -> str:
    """Return a 16-character SHA-256 hex digest for a single governance object dict."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]
