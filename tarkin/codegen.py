"""
SQL code generation for Tarkin governance builds.

:func:`generate_sql` is the single entry point.  It accepts a
:class:`~tarkin.model.GovernanceProject` (the governance specification),
the current live-database state (also a ``GovernanceProject``, produced by
:mod:`tarkin.inspect`), and a :class:`~tarkin.credentials.ConnectionProfile`
for HMAC key injection, and returns the full SQL string to be executed during
``tarkin attach``.
"""
from __future__ import annotations

from datetime import datetime, UTC
from importlib.metadata import version as pkg_version
import hashlib
import warnings

from .credentials import ConnectionProfile
from .model import (
    GovernanceProject, TableConfig, ColumnConfig,
    MaskingStrategy, MaskConfig, FullMaskConfig,
    PartialMaskConfig, HashAlgorithm, HashMaskConfig,
    EmailMaskConfig, PhoneMaskConfig, CreditCardMaskConfig,
    IpAddressMaskConfig, NameMaskConfig,
    PartialMaskVisibleSide,
)


# =========================================================
# ENTRY POINT
# =========================================================


def generate_sql(
    project: GovernanceProject,
    current: GovernanceProject,
    profile: ConnectionProfile,
) -> str:
    """Generate the full SQL build artifact for a governance project.

    Args:
        project: The target governance specification (from YAML).
        current: The current live-database state (from inspect).
        profile: The active credentials profile, used for HMAC key injection.

    Returns:
        A single SQL string suitable for execution via ``tarkin attach``.
    """
    sections = [
        _section("TARKIN BUILD", f"Generated at {datetime.now(UTC).isoformat()}"),
        _section("TRANSACTION START"),
        "BEGIN;\n",
        _section("HMAC KEY"),
        _generate_hmac_key(project, profile),
        _section("EXTENSIONS"),
        _generate_extensions(project),
        _section("META SCHEMA"),
        _generate_meta_schema(),
        _section("SHADOW SCHEMAS"),
        _generate_shadow_schemas(project),
        _section("VERSIONING COLUMNS"),
        _generate_versioning_columns(project, current),
        _section("VIEWS"),
        _generate_views(project),
        _section("TRIGGERS"),
        _generate_triggers(project),
        _section("ROLES"),
        _generate_roles(project, current),
        _section("GRANTS"),
        _generate_grants(project),
        _section("AUDIT"),
        _generate_audit(project),
        _section("META POPULATION"),
        _generate_meta_population(project, current),
        _section("TRANSACTION END"),
        "COMMIT;\n",
    ]
    return "\n".join(sections)


# =========================================================
# META SCHEMA
# =========================================================


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
    pgcrypto_enabled_by_tarkin  bool NOT NULL DEFAULT false,
    -- pgaudit snapshot: values before Tarkin modified them, for restoration on detach
    pgaudit_log_before          text,
    pgaudit_log_catalog_before  text,
    pgaudit_log_relation_before text
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
""".strip()


# =========================================================
# SHADOW SCHEMAS
# =========================================================


def _generate_shadow_schemas(project: GovernanceProject) -> str:
    """Generate SQL to rename existing schemas to shadow names and create fresh public schemas."""
    lines = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        lines.append(f"-- Rename {schema.name} -> {shadow}")
        lines.append(f"ALTER SCHEMA {_q(schema.name)} RENAME TO {_q(shadow)};")
        lines.append(f"CREATE SCHEMA {_q(schema.name)};")
        lines.append("")
    return "\n".join(lines)


# =========================================================
# VERSIONING COLUMNS
# =========================================================


def _generate_versioning_columns(
    project: GovernanceProject,
    current: GovernanceProject,
) -> str:
    """Generate ALTER TABLE statements to add versioning columns to shadow tables."""
    lines = []
    current_col_map = {
        (s.name, t.name): {c.name for c in t.columns}
        for s in current.schemas
        for t in s.tables
    }

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
                    f"ALTER TABLE {_q(shadow)}.{_q(table.name)} "
                    f"ADD COLUMN __valid_from__ timestamptz NOT NULL DEFAULT now();"
                )
            if not has_to:
                lines.append(
                    f"ALTER TABLE {_q(shadow)}.{_q(table.name)} "
                    f"ADD COLUMN __valid_to__ timestamptz NOT NULL DEFAULT 'infinity'::timestamptz;"
                )
            lines.append(
                f"CREATE INDEX {_q('idx_' + table.name + '_current')} "
                f"ON {_q(shadow)}.{_q(table.name)} (__valid_to__) "
                f"WHERE __valid_to__ = 'infinity'::timestamptz;"
            )
            lines.append("")

    return "\n".join(lines)


# =========================================================
# EXTENSIONS
# =========================================================


def _generate_extensions(project: GovernanceProject) -> str:
    """Emit SQL to enable extensions required by the project.

    If ``pgcrypto`` is needed and not already installed, it is created and
    ``pgcrypto_enabled_by_tarkin = true`` is recorded in ``__META__.tarkin_builds``
    so that ``tarkin detach`` can warn the operator.

    A DO block is used so we can check ``pg_extension`` before creating, avoiding
    the ``IF NOT EXISTS`` idiom which silently succeeds even when Tarkin was
    not the creator.
    """
    needs_pgcrypto = any(
        isinstance(col.mask_config, HashMaskConfig)
        and col.mask_config.algorithm in (
            HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.HMAC256
        )
        for schema in project.schemas
        for table in schema.tables
        for col in table.columns
    )
    if not needs_pgcrypto:
        return "-- No pgcrypto-dependent features in use.\n"

    return """\
DO $$
DECLARE
    _existed bool;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
    ) INTO _existed;

    IF NOT _existed THEN
        CREATE EXTENSION pgcrypto;
        -- Record that Tarkin enabled pgcrypto so detach can warn.
        UPDATE __META__.tarkin_builds
        SET pgcrypto_enabled_by_tarkin = true
        WHERE build_id = (SELECT max(build_id) FROM __META__.tarkin_builds);
    END IF;
END;
$$ LANGUAGE plpgsql;
"""


# =========================================================
# VIEWS
# =========================================================


def _generate_views(project: GovernanceProject) -> str:
    """Generate CREATE VIEW statements for all tables in the project.

    Each table gets a full-history view in the public schema.  Versioned
    tables additionally receive a ``_current`` view filtered to live records.
    Masking expressions are applied according to each column's
    ``masking_strategy`` and ``mask_config``.
    """
    lines = []

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            is_versioned = any(c.versioned for c in table.columns)

            col_exprs = [_mask_expression(c, shadow, table.name) for c in table.columns]
            col_list  = ",\n    ".join(col_exprs)

            lines.append(
                f"CREATE VIEW {_q(schema.name)}.{_q(table.name)} AS\n"
                f"    SELECT\n    {col_list}\n"
                f"    FROM {_q(shadow)}.{_q(table.name)};"
            )

            if is_versioned:
                lines.append(
                    f"CREATE VIEW {_q(schema.name)}.{_q(table.name + '_current')} AS\n"
                    f"    SELECT\n    {col_list}\n"
                    f"    FROM {_q(shadow)}.{_q(table.name)}\n"
                    f"    WHERE __valid_to__ >= now();"
                )

            lines.append("")

    return "\n".join(lines)


def _generate_hmac_key(project: GovernanceProject, profile: ConnectionProfile) -> str:
    """Emit an ALTER DATABASE statement to set the HMAC key for HMAC256 masking.

    The key is sourced from the credentials profile and stored as the
    database-level GUC ``tarkin.hmac_key``.  It is evaluated at query time
    via ``current_setting()`` and is never baked into view definitions.

    Raises:
        ValueError: If HMAC256 columns are present but no HMAC key is
            configured in the credentials profile.
    """
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

    key     = _escape_sql_string(profile.hmac_key.get_secret_value())
    db_name = _q(project.database.name)
    return (
        f"-- Set HMAC key for HMAC256 masking.\n"
        f"-- This value is stored as a database-level GUC and is visible to superusers.\n"
        f"-- Treat it as a secret and rotate it via credentials.toml if compromised.\n"
        f"-- WARNING: Rotating the key will invalidate all existing HMAC-hashed values.\n"
        f"ALTER DATABASE {db_name} SET tarkin.hmac_key = '{key}';\n"
    )


def _mask_expression(col: ColumnConfig, shadow: str, table_name: str) -> str:
    """Return a SQL expression for a column in a view, applying masking if configured.

    Columns with ``masking_strategy='none'`` are passed through as-is.

    Args:
        col:        The column configuration.
        shadow:     The shadow schema name (e.g. ``tk_public``).
        table_name: The table name within the shadow schema.

    Returns:
        A SQL fragment suitable for use in a SELECT list.
    """
    _default_mask_char = "X"

    strategy = MaskingStrategy(col.masking_strategy)
    ref      = f"{_q(shadow)}.{_q(table_name)}.{_q(col.name)}"
    cfg      = col.mask_config

    if strategy == MaskingStrategy.NONE:
        return _q(col.name)

    def _wrap_null(exp: str, hn: bool) -> str:
        if hn:
            return f"COALESCE({exp}, {_mask_null_literal(strategy, cfg)}) AS {_q(col.name)}"
        return f"CASE WHEN {ref} IS NULL THEN NULL ELSE {exp} END AS {_q(col.name)}"

    if strategy == MaskingStrategy.FULL:
        if not isinstance(cfg, FullMaskConfig):
            raise ValueError(
                f"Column '{col.name}': strategy 'full' requires FullMaskConfig, "
                f"got {type(cfg).__name__}"
            )
        mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
        expr = f"regexp_replace({ref}::text, '.', '{mask_char}', 'g')"
        return _wrap_null(expr, cfg.hide_null)

    elif strategy == MaskingStrategy.PARTIAL:
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
        return _wrap_null(expr, cfg.hide_null)

    elif strategy == MaskingStrategy.HASH:
        if not isinstance(cfg, HashMaskConfig):
            raise ValueError(
                f"Column '{col.name}': strategy 'hash' requires HashMaskConfig, "
                f"got {type(cfg).__name__}"
            )
        algorithm = cfg.algorithm

        if algorithm == HashAlgorithm.XXHASH:
            warnings.warn(
                f"Column '{col.name}': hash algorithm 'xxhash' is non-cryptographic. "
                f"Hash values are trivially reversible given knowledge of the source "
                f"data distribution. Use sha256, sha512, or hmac256 for sensitive data.",
                UserWarning,
                stacklevel=2,
            )
            expr = f"hashtextextended({ref}::text, 0)::text"

        elif algorithm == HashAlgorithm.SHA256:
            warnings.warn(
                f"Column '{col.name}': hash algorithm 'sha256' is cryptographic but "
                f"may be vulnerable to dictionary attacks on low-entropy data "
                f"(e.g. SSNs, postcodes). Consider hmac256 for stronger protection.",
                UserWarning,
                stacklevel=2,
            )
            expr = f"encode(digest({ref}::text, 'sha256'), 'hex')"

        elif algorithm == HashAlgorithm.SHA512:
            warnings.warn(
                f"Column '{col.name}': hash algorithm 'sha512' is cryptographic but "
                f"may be vulnerable to dictionary attacks on low-entropy data "
                f"(e.g. SSNs, postcodes). Consider hmac256 for stronger protection.",
                UserWarning,
                stacklevel=2,
            )
            expr = f"encode(digest({ref}::text, 'sha512'), 'hex')"

        elif algorithm == HashAlgorithm.HMAC256:
            expr = f"encode(hmac({ref}::text, {_escape_hmac_key()}, 'sha256'), 'hex')"

        else:
            raise ValueError(
                f"Column '{col.name}': unhandled hash algorithm '{algorithm}'. "
                f"This is a Tarkin bug — please file an issue."
            )

        return _wrap_null(expr, cfg.hide_null)

    elif strategy == MaskingStrategy.EMAIL:
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
        return _wrap_null(expr, cfg.hide_null)

    elif strategy == MaskingStrategy.PHONE:
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
        return _wrap_null(expr, cfg.hide_null)

    elif strategy == MaskingStrategy.CREDIT_CARD:
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
        return _wrap_null(expr, cfg.hide_null)

    elif strategy == MaskingStrategy.IP_ADDRESS:
        if not isinstance(cfg, IpAddressMaskConfig):
            raise ValueError(
                f"Column '{col.name}': strategy 'ip_address' requires IpAddressMaskConfig, "
                f"got {type(cfg).__name__}"
            )
        visible   = cfg.visible_octets
        mask_char = cfg.mask_char if cfg.mask_char else _default_mask_char
        if visible == 1:
            expr = (
                f"'{mask_char}.' || '{mask_char}.' || '{mask_char}.' || "
                f"split_part({ref}::text, '.', 4)"
            )
        elif visible == 2:
            expr = (
                f"'{mask_char}.' || '{mask_char}.' || "
                f"split_part({ref}::text, '.', 3) || '.' || "
                f"split_part({ref}::text, '.', 4)"
            )
        elif visible == 3:
            expr = (
                f"'{mask_char}.' || "
                f"split_part({ref}::text, '.', 2) || '.' || "
                f"split_part({ref}::text, '.', 3) || '.' || "
                f"split_part({ref}::text, '.', 4)"
            )
        else:
            expr = f"{ref}::text"
        return _wrap_null(expr, cfg.hide_null)

    elif strategy == MaskingStrategy.NAME:
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
        return _wrap_null(expr, cfg.hide_null)

    raise ValueError(
        f"Column '{col.name}': unhandled masking strategy '{strategy}'. "
        f"This is a Tarkin bug — please file an issue."
    )


def _mask_null_literal(strategy: MaskingStrategy, cfg: MaskConfig | None) -> str:
    """Return a SQL literal to use when hide_null=True and the value is NULL."""
    if strategy == MaskingStrategy.HASH:
        if isinstance(cfg, HashMaskConfig):
            if cfg.algorithm == HashAlgorithm.XXHASH:
                return "hashtextextended('', 0)::text"
            elif cfg.algorithm == HashAlgorithm.HMAC256:
                return "encode(hmac('', current_setting('tarkin.hmac_key'), 'sha256'), 'hex')"
            else:
                algo = cfg.algorithm.value
                return f"encode(digest('', '{algo}'), 'hex')"
        return "hashtextextended('', 0)::text"

    if cfg and hasattr(cfg, "mask_char") and cfg.mask_char:
        mask_char = cfg.mask_char
    else:
        mask_char = "X"
    return f"'{mask_char}'"


# =========================================================
# TRIGGERS
# =========================================================


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
    col_names = [c.name for c in table.columns]

    insert_cols = ", ".join(_q(c) for c in col_names)
    insert_vals = ", ".join(f"NEW.{_q(c)}" for c in col_names)

    immutable_checks = _generate_immutable_checks(table) if any(c.immutable for c in table.columns) else ""
    sensitive_stubs  = _generate_sensitive_stubs(table) if any(
        c.sensitive or c.masking_strategy != "none"
        for c in table.columns
    ) else ""

    fn_name = _q("tr_" + table.name)
    tbl_ref = f"{_q(shadow)}.{_q(table.name)}"
    pk_filt = _pk_filter(table)

    if any(c.versioned for c in table.columns):
        v_insert_cols = insert_cols + ", __valid_from__, __valid_to__"
        v_insert_vals = insert_vals + ", now(), 'infinity'::timestamptz"

        return f"""
CREATE OR REPLACE FUNCTION {_q(shadow)}.{fn_name}()
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
        WHERE {pk_filt} AND __valid_to__ = 'infinity'::timestamptz;
        RETURN OLD;
    END IF;
END;
$$;
""".strip()

    else:
        update_set = ", ".join(f"{_q(c)} = NEW.{_q(c)}" for c in col_names)

        return f"""
CREATE OR REPLACE FUNCTION {_q(shadow)}.{fn_name}()
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
        WHERE {pk_filt};
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
                f"        IF OLD.{_q(col.name)} IS DISTINCT FROM NEW.{_q(col.name)} THEN\n"
                f"            RAISE EXCEPTION 'Column {col.name} is immutable and cannot be updated.';\n"
                f"        END IF;"
            )
    return "\n".join(lines) + "\n" if lines else ""


def _generate_sensitive_stubs(table: TableConfig) -> str:
    """Generate comment stubs for sensitive columns.

    Sensitive column access is enforced via column-level grants on views,
    not trigger logic.  These stubs document the intent for developers
    reading the generated SQL.
    """
    lines = []
    for col in table.columns:
        if col.sensitive:
            lines.append(
                f"        -- NOTE: '{col.name}' is sensitive. Access is enforced via "
                f"column-level grants on the view layer, not here."
            )
        if col.masking_strategy != "none":
            lines.append(
                f"        -- NOTE: '{col.name}' uses masking strategy "
                f"'{col.masking_strategy}' in the view layer."
            )
    return "\n".join(lines) + "\n" if lines else ""


def _attach_trigger(schema_name: str, table_name: str) -> str:
    """Generate the CREATE TRIGGER statement attaching a trigger to a view."""
    shadow = f"tk_{schema_name}"
    return (
        f"CREATE TRIGGER {_q('tr_' + table_name)}\n"
        f"INSTEAD OF INSERT OR UPDATE OR DELETE\n"
        f"ON {_q(schema_name)}.{_q(table_name)}\n"
        f"FOR EACH ROW EXECUTE FUNCTION {_q(shadow)}.{_q('tr_' + table_name)}();"
    )


def _pk_filter(table: TableConfig) -> str:
    """Return a WHERE clause fragment matching the primary key columns.

    Raises:
        ValueError: If the table has no primary key defined.
    """
    pk_cols = [col for idx in table.indexes if idx.primary_key for col in idx.columns]
    if not pk_cols:
        raise ValueError(
            f"Table '{table.name}' has no primary key defined. "
            f"Tarkin requires a primary key to generate safe trigger functions. "
            f"This should have been caught by validation — please file a bug."
        )
    return " AND ".join(f"{_q(col)} = NEW.{_q(col)}" for col in pk_cols)


# =========================================================
# ROLES
# =========================================================


def _generate_roles(
    project: GovernanceProject,
    current: GovernanceProject,
) -> str:
    """Generate CREATE/ALTER ROLE statements and membership grants."""
    lines = []
    existing_role_names = {r.name for r in current.roles}

    for role in project.roles:
        if role.name in existing_role_names:
            parts = [f"ALTER ROLE {_q(role.name)}"]
        else:
            parts = [f"CREATE ROLE {_q(role.name)}"]

        parts.append("LOGIN" if role.can_login  else "NOLOGIN")
        parts.append("SUPERUSER" if role.can_admin else "NOSUPERUSER")
        parts.append("CREATEDB CREATEROLE" if role.can_write else "NOCREATEDB NOCREATEROLE")

        lines.append(" ".join(parts) + ";")

        for parent in role.member_of:
            lines.append(f"GRANT {_q(parent)} TO {_q(role.name)};")

        lines.append("")

    return "\n".join(lines)


# =========================================================
# GRANTS
# =========================================================


def _generate_grants(project: GovernanceProject) -> str:
    """Generate GRANT and REVOKE statements for all roles and schemas.

    Shadow schemas are revoked from all non-owner roles.  Column-level
    restrictions are applied via revoke/re-grant patterns for SELECT, UPDATE,
    and REFERENCES when clearance or sensitivity restricts access.

    Sensitive columns generate a warning if unmasked or if all roles have
    ``can_access_sensitive=True``.
    """
    lines: list[str] = []

    schema_map  = {s.name: s for s in project.schemas}
    table_map   = {(s.name, t.name): t for s in project.schemas for t in s.tables}
    shadow_schemas = [f"tk_{s.name}" for s in project.schemas]

    # Warn if any sensitive column has no masking strategy
    for schema in project.schemas:
        for table in schema.tables:
            for col in table.columns:
                if col.sensitive and col.masking_strategy == "none":
                    warnings.warn(
                        f"Column '{schema.name}.{table.name}.{col.name}' is marked "
                        f"sensitive but has no masking strategy. Roles with "
                        f"can_access_sensitive=True will see the raw value.",
                        UserWarning,
                        stacklevel=2,
                    )

    # Warn if all roles have can_access_sensitive and any sensitive columns exist
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

    # Revoke all access to shadow schemas for non-owner roles
    for role in project.roles:
        if role.name == project.database.owner:
            continue
        for shadow in shadow_schemas:
            lines.append(
                f"REVOKE ALL ON SCHEMA {_q(shadow)} FROM {_q(role.name)};"
            )
            lines.append(
                f"REVOKE ALL ON ALL TABLES IN SCHEMA {_q(shadow)} FROM {_q(role.name)};"
            )

    if lines:
        lines.append("")

    for role in project.roles:
        for sp in role.on:
            schema = schema_map.get(sp.name)
            if not schema:
                continue

            # Schema-level grants
            schema_privs = []
            if sp.usage:  schema_privs.append("USAGE")
            if sp.create: schema_privs.append("CREATE")
            if schema_privs:
                lines.append(
                    f"GRANT {', '.join(schema_privs)} ON SCHEMA {_q(sp.name)} TO {_q(role.name)};"
                )

            # Table-level grants
            for tp in sp.tables:
                table = table_map.get((sp.name, tp.name))
                if not table:
                    continue

                if role.clearance < table.clearance:
                    lines.append(
                        f"-- SKIPPED: {role.name} clearance {role.clearance} < "
                        f"table {sp.name}.{tp.name} clearance {table.clearance}"
                    )
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
                    lines.append(
                        f"-- SKIPPED: {role.name} has no accessible columns on "
                        f"{sp.name}.{tp.name} (clearance or sensitive restrictions)"
                    )
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
                if tp.maintain:   table_privs.append("MAINTAIN")

                if table_privs:
                    lines.append(
                        f"GRANT {', '.join(table_privs)} ON "
                        f"{_q(sp.name)}.{_q(tp.name)} TO {_q(role.name)};"
                    )

                if restricted:
                    col_list    = ", ".join(_q(c.name) for c in accessible_cols)
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
                            lines.append(
                                f"-- Column-level SELECT restricted by clearance/sensitivity "
                                f"for {role.name} on {sp.name}.{tp.name}"
                            )
                            lines.append(
                                f"REVOKE SELECT ON {_q(sp.name)}.{_q(tp.name)} FROM {_q(role.name)};"
                            )
                            lines.append(
                                f"GRANT SELECT ({col_list}) ON {_q(sp.name)}.{_q(tp.name)} TO {_q(role.name)};"
                            )

                        if tp.update:
                            lines.append(
                                f"-- Column-level UPDATE restricted by clearance/sensitivity "
                                f"for {role.name} on {sp.name}.{tp.name}"
                            )
                            lines.append(
                                f"REVOKE UPDATE ON {_q(sp.name)}.{_q(tp.name)} FROM {_q(role.name)};"
                            )
                            lines.append(
                                f"GRANT UPDATE ({col_list}) ON {_q(sp.name)}.{_q(tp.name)} TO {_q(role.name)};"
                            )

                        if tp.references:
                            lines.append(
                                f"-- Column-level REFERENCES restricted by clearance/sensitivity "
                                f"for {role.name} on {sp.name}.{tp.name}"
                            )
                            lines.append(
                                f"REVOKE REFERENCES ON {_q(sp.name)}.{_q(tp.name)} FROM {_q(role.name)};"
                            )
                            lines.append(
                                f"GRANT REFERENCES ({col_list}) ON {_q(sp.name)}.{_q(tp.name)} TO {_q(role.name)};"
                            )

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

    return "\n".join(lines)


# =========================================================
# AUDIT (pgaudit)
# =========================================================


def _generate_audit(project: GovernanceProject) -> str:
    """Generate pgaudit configuration SQL.

    Before modifying pgaudit settings, the current values of ``pgaudit.log``,
    ``pgaudit.log_catalog``, and ``pgaudit.log_relation`` are captured into
    ``__META__.tarkin_builds`` so they can be restored on detach.

    Configuration is then applied additively — existing log levels are merged
    with the declared levels rather than overwritten.
    """
    if not project.database.audit_enabled:
        return "-- Audit logging not enabled for this database.\n"

    levels  = ", ".join(str(level) for level in project.database.audit_logged)
    db_name = _q(project.database.name)

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
        f"        pgaudit_log_relation_before = current_setting('pgaudit.log_relation', true)",
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
        lines.append("-- The following tables have audit_enabled=false.")
        lines.append("-- Per-table audit exclusion requires pgaudit object-level audit (future implementation).")
        for schema_name, table_name in excluded_tables:
            lines.append(f"--   {schema_name}.{table_name}")
        lines.append("")

    return "\n".join(lines)


# =========================================================
# META POPULATION
# =========================================================


def _generate_meta_population(
    project: GovernanceProject,
    current: GovernanceProject,
) -> str:
    """Generate the DO block that populates all ``__META__`` tables.

    Includes recording of revoked grants (for restoration on detach) and
    the ``added_by_tarkin`` flag on roles.

    Args:
        project: The target governance specification.
        current: The current live-database state (used to determine which
            roles are new and which grants existed before Tarkin).
    """
    tarkin_version = pkg_version("tarkin")
    yaml_str       = _project_to_yaml_string(project)
    profile        = _escape_sql_string(project.database.profile or "")
    database_name  = _escape_sql_string(project.database.name)
    checksum       = _project_checksum(project)

    existing_role_names = {r.name for r in current.roles}

    # Collect pre-existing schema grants that Tarkin will revoke on shadow schemas.
    # Shadow schema names are tk_{schema} — the original schema had the same grants
    # before the rename, so we record them as belonging to the original schema name.
    revoked_grants: list[tuple[str, str, str | None, str]] = []  # role, schema, table, grant_type

    for schema in project.schemas:
        # Find the current role that maps to this schema (pre-rename it was called schema.name)
        for current_role in current.roles:
            for sp in current_role.on:
                if sp.name == schema.name:
                    if sp.usage:
                        revoked_grants.append((current_role.name, schema.name, None, "USAGE"))
                    if sp.create:
                        revoked_grants.append((current_role.name, schema.name, None, "CREATE"))
                    for tp in sp.tables:
                        for priv in ["select", "insert", "update", "delete",
                                     "truncate", "references", "trigger", "maintain"]:
                            if getattr(tp, priv):
                                revoked_grants.append(
                                    (current_role.name, schema.name, tp.name, priv.upper())
                                )

    lines = ["DO $$", "DECLARE", "    v_build_id bigint;", "BEGIN"]

    # Build record — use dollar-quoting for the YAML blob to avoid escaping issues
    lines += [
        f"    INSERT INTO __META__.tarkin_builds (tarkin_version, profile, database_name, checksum, yaml)",
        f"    VALUES (",
        f"        '{tarkin_version}',",
        f"        '{profile}',",
        f"        '{database_name}',",
        f"        '{checksum}',",
        f"        $tarkin_yaml${yaml_str}$tarkin_yaml$",
        f"    )",
        f"    RETURNING build_id INTO v_build_id;",
        "",
    ]

    # Schemas
    for schema in project.schemas:
        sn = _escape_sql_string(schema.name)
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

    # Tables
    for schema in project.schemas:
        for table in schema.tables:
            sn = _escape_sql_string(schema.name)
            tn = _escape_sql_string(table.name)
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

    # Columns
    for schema in project.schemas:
        for table in schema.tables:
            for col in table.columns:
                sn  = _escape_sql_string(schema.name)
                tn  = _escape_sql_string(table.name)
                cn  = _escape_sql_string(col.name)
                ct  = _escape_sql_string(col.type)
                dv  = f"'{_escape_sql_string(col.default)}'" if col.default else "NULL"
                ge  = f"'{_escape_sql_string(col.generated_expression)}'" if col.generated_expression else "NULL"
                ms  = _escape_sql_string(col.masking_strategy)
                gs  = _escape_sql_string(col.generated_storage)
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

    # Indexes
    for schema in project.schemas:
        for table in schema.tables:
            for idx in table.indexes:
                sn  = _escape_sql_string(schema.name)
                tn  = _escape_sql_string(table.name)
                idn = _escape_sql_string(idx.name)
                ca  = "ARRAY[" + ", ".join(f"'{c}'" for c in idx.columns) + "]"
                pf  = f"'{_escape_sql_string(idx.partial_filter)}'" if idx.partial_filter else "NULL"
                lines.append(
                    f"    INSERT INTO __META__.tarkin_indexes "
                    f"(build_id, schema_name, table_name, name, columns, index_type, \"unique\", primary_key, partial_filter) "
                    f"VALUES (v_build_id, '{sn}', '{tn}', '{idn}', {ca}, '{idx.index_type}', "
                    f"{str(idx.unique).lower()}, {str(idx.primary_key).lower()}, {pf});"
                )
    lines.append("")

    # Foreign keys
    for schema in project.schemas:
        for table in schema.tables:
            for fk in table.foreign_keys:
                sn  = _escape_sql_string(schema.name)
                tn  = _escape_sql_string(table.name)
                fn_ = _escape_sql_string(fk.name)
                lines.append(
                    f"    INSERT INTO __META__.tarkin_foreign_keys "
                    f"(build_id, schema_name, table_name, name, column_name, "
                    f"referenced_schema, referenced_table, referenced_column) "
                    f"VALUES (v_build_id, '{sn}', '{tn}', '{fn_}', "
                    f"'{_escape_sql_string(fk.column)}', "
                    f"'{_escape_sql_string(fk.referenced_schema)}', "
                    f"'{_escape_sql_string(fk.referenced_table)}', "
                    f"'{_escape_sql_string(fk.referenced_column)}');"
                )
    lines.append("")

    # Roles — record added_by_tarkin flag
    for role in project.roles:
        rn  = _escape_sql_string(role.name)
        moa = ("ARRAY[" + ", ".join(f"'{_escape_sql_string(m)}'" for m in role.member_of) + "]"
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

    # Role schema permissions
    for role in project.roles:
        for sp in role.on:
            rn = _escape_sql_string(role.name)
            sn = _escape_sql_string(sp.name)
            lines.append(
                f"    INSERT INTO __META__.tarkin_role_schemas "
                f"(build_id, role_name, schema_name, \"usage\", \"create\") "
                f"VALUES (v_build_id, '{rn}', '{sn}', "
                f"{str(sp.usage).lower()}, {str(sp.create).lower()});"
            )
    lines.append("")

    # Role table permissions
    for role in project.roles:
        for sp in role.on:
            for tp in sp.tables:
                rn = _escape_sql_string(role.name)
                sn = _escape_sql_string(sp.name)
                tn = _escape_sql_string(tp.name)
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

    # Revoked grants — stored for restoration on detach
    for (role_name, schema_name, table_name, grant_type) in revoked_grants:
        rn = _escape_sql_string(role_name)
        sn = _escape_sql_string(schema_name)
        tn = f"'{_escape_sql_string(table_name)}'" if table_name else "NULL"
        gt = _escape_sql_string(grant_type)
        lines.append(
            f"    INSERT INTO __META__.tarkin_revoked_grants "
            f"(build_id, role_name, schema_name, table_name, grant_type) "
            f"VALUES (v_build_id, '{rn}', '{sn}', {tn}, '{gt}');"
        )
    if revoked_grants:
        lines.append("")

    lines += ["END;", "$$;"]
    return "\n".join(lines)


# =========================================================
# UTILS
# =========================================================


def _escape_hmac_key() -> str:
    """Return the SQL expression for the HMAC key GUC."""
    return "current_setting('tarkin.hmac_key')"


def _q(name: str) -> str:
    """Double-quote a PostgreSQL identifier."""
    return f'"{name}"'


def _section(title: str, subtitle: str = "") -> str:
    """Return a SQL comment block marking a named section."""
    line  = "-" * 60
    parts = [f"-- {line}", f"-- {title}"]
    if subtitle:
        parts.append(f"-- {subtitle}")
    parts.append(f"-- {line}")
    return "\n".join(parts)


def _escape_sql_string(s: str) -> str:
    """Escape a string value for safe inclusion in a SQL single-quoted literal.

    Handles single quotes (doubled) and backslashes (doubled).  This is safe
    with PostgreSQL's default ``standard_conforming_strings = on``.  For string
    blobs (e.g. the governance YAML), prefer dollar-quoting instead.
    """
    if not s:
        return ""
    return s.replace("\\", "\\\\").replace("'", "''")


def _project_to_yaml_string(project: GovernanceProject) -> str:
    """Serialize a GovernanceProject to a YAML string."""
    from .serialize import Serializer
    return Serializer.to_yaml_string(project)


def _project_checksum(project: GovernanceProject) -> str:
    """Return a SHA-256 hex digest of the project's serialized YAML.

    Because the YAML serializer is pinned via uv.lock and only serializes
    declared properties (no runtime values, sequences, or comments), this
    checksum is stable across runs for structurally identical projects.
    """
    return hashlib.sha256(_project_to_yaml_string(project).encode()).hexdigest()


def _object_checksum(obj: dict) -> str:  # type: ignore[type-arg]
    """Return a 16-character SHA-256 hex digest for a single governance object dict."""
    import json
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]
