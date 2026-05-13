from __future__ import annotations
from datetime import datetime, UTC
from importlib.metadata import version as pkg_version
import hashlib

from .model import (
    GovernanceProject, TableConfig, ColumnConfig,
    MaskingStrategy,
    FullMaskConfig, PartialMaskConfig,
    EmailMaskConfig, PhoneMaskConfig, CreditCardMaskConfig,
    IpAddressMaskConfig, NameMaskConfig,
    PartialMaskVisibleSide,
)


# =========================================================
# ENTRY POINT
# =========================================================

def generate_sql(project: GovernanceProject, current: GovernanceProject) -> str:
    sections = [
        _section("TARKIN BUILD", f"Generated at {datetime.now(UTC).isoformat()}"),
        _section("TRANSACTION START"),
        "BEGIN;\n",
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
        _generate_meta_population(project),
        _section("TRANSACTION END"),
        "COMMIT;\n",
    ]
    return "\n".join(sections)


# =========================================================
# META SCHEMA
# =========================================================

def _generate_meta_schema() -> str:
    return """
CREATE SCHEMA IF NOT EXISTS __META__;

CREATE TABLE IF NOT EXISTS __META__.tarkin_builds (
    build_id        bigserial PRIMARY KEY,
    built_at        timestamptz NOT NULL DEFAULT now(),
    tarkin_version  text NOT NULL,
    profile         text NOT NULL,
    database_name   text NOT NULL,
    checksum        text NOT NULL,
    yaml            text NOT NULL
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
    encrypted            bool NOT NULL DEFAULT false,
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
    active                bool NOT NULL DEFAULT true,
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
""".strip()


# =========================================================
# SHADOW SCHEMAS
# =========================================================

def _generate_shadow_schemas(project: GovernanceProject) -> str:
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

def _generate_versioning_columns(project: GovernanceProject, current: GovernanceProject) -> str:
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
# VIEWS
# =========================================================

def _generate_views(project: GovernanceProject) -> str:
    lines = []

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            is_versioned = any(c.versioned for c in table.columns)

            col_exprs = [_mask_expression(c, shadow, table.name) for c in table.columns]
            col_list  = ",\n    ".join(col_exprs)

            # Full view — all records
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


def _mask_expression(col: ColumnConfig, shadow: str, table_name: str) -> str:
    """
    Return a SQL expression for a column in a view, applying masking if configured.
    Columns with masking_strategy='none' are passed through as-is.
    """
    strategy = MaskingStrategy(col.masking_strategy)
    ref      = f"{_q(shadow)}.{_q(table_name)}.{_q(col.name)}"
    cfg      = col.mask_config

    if strategy == MaskingStrategy.NONE:
        return _q(col.name)

    # Shared null handling wrapper
    def _wrap_null(expr: str, hide_null: bool) -> str:
        if hide_null:
            return f"COALESCE({expr}, {_mask_null_literal(strategy, cfg)}) AS {_q(col.name)}"
        return f"CASE WHEN {ref} IS NULL THEN NULL ELSE {expr} END AS {_q(col.name)}"

    if strategy == MaskingStrategy.FULL:
        mask_char = cfg.mask_char if isinstance(cfg, FullMaskConfig) else "X"
        hide_null = cfg.hide_null if cfg else False
        expr = f"regexp_replace({ref}::text, '.', '{mask_char}', 'g')"
        return _wrap_null(expr, hide_null)

    elif strategy == MaskingStrategy.PARTIAL:
        if not isinstance(cfg, PartialMaskConfig):
            # Fallback — shouldn't happen after validation
            return _q(col.name)
        mask_char = cfg.mask_char
        length    = cfg.visible_length
        side      = cfg.visible_side
        hide_null = cfg.hide_null
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
        return _wrap_null(expr, hide_null)

    elif strategy == MaskingStrategy.HASH:
        hide_null = cfg.hide_null if cfg else False
        expr = f"hashtextextended({ref}::text, 0)::text"
        warning = f"/* HASH MASK: not encryption, see tarkin docs */"
        return _wrap_null(f"{warning} {expr}", hide_null)

    elif strategy == MaskingStrategy.EMAIL:
        mask_char = cfg.mask_char if isinstance(cfg, EmailMaskConfig) else "X"
        hide_null = cfg.hide_null if cfg else False
        # j***@example.com — keep first char + mask up to @
        expr = (
            f"left({ref}::text, 1) || "
            f"repeat('{mask_char}', greatest(0, position('@' IN {ref}::text) - 2)) || "
            f"substring({ref}::text FROM position('@' IN {ref}::text))"
        )
        return _wrap_null(expr, hide_null)

    elif strategy == MaskingStrategy.PHONE:
        visible = cfg.visible_digits if isinstance(cfg, PhoneMaskConfig) else 4
        mask_char = cfg.mask_char if isinstance(cfg, PhoneMaskConfig) else "X"
        hide_null = cfg.hide_null if cfg else False
        # Keep last N digits only (strips non-digits first, then remasks)
        expr = (
            f"repeat('{mask_char}', greatest(0, length(regexp_replace({ref}::text, '[^0-9]', '', 'g')) - {visible})) || "
            f"right(regexp_replace({ref}::text, '[^0-9]', '', 'g'), {visible})"
        )
        return _wrap_null(expr, hide_null)

    elif strategy == MaskingStrategy.CREDIT_CARD:
        mask_char = cfg.mask_char if isinstance(cfg, CreditCardMaskConfig) else "X"
        hide_null = cfg.hide_null if cfg else False
        # XXXX-XXXX-XXXX-1234 — strip non-digits, show last 4, format with dashes
        expr = (
            f"repeat('{mask_char}', 4) || '-' || repeat('{mask_char}', 4) || '-' || "
            f"repeat('{mask_char}', 4) || '-' || "
            f"right(regexp_replace({ref}::text, '[^0-9]', '', 'g'), 4)"
        )
        return _wrap_null(expr, hide_null)

    elif strategy == MaskingStrategy.IP_ADDRESS:
        visible  = cfg.visible_octets if isinstance(cfg, IpAddressMaskConfig) else 2
        mask_char = cfg.mask_char if isinstance(cfg, IpAddressMaskConfig) else "X"
        hide_null = cfg.hide_null if cfg else False
        # For IPv4: show last visible_octets, mask the rest
        # We split on '.', mask leading octets, rejoin
        # Simplest correct approach in pure SQL for IPv4:
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
        return _wrap_null(expr, hide_null)

    elif strategy == MaskingStrategy.NAME:
        mask_char = cfg.mask_char if isinstance(cfg, NameMaskConfig) else "*"
        hide_null = cfg.hide_null if cfg else False
        # First letter of each word + mask_char * 3: "John Smith" -> "J*** S***"
        expr = (
            f"array_to_string(ARRAY("
            f"SELECT left(word, 1) || repeat('{mask_char}', 3) "
            f"FROM regexp_split_to_table({ref}::text, '\\s+') AS word"
            f"), ' ')"
        )
        return _wrap_null(expr, hide_null)

    # Fallback
    return _q(col.name)


def _mask_null_literal(strategy: MaskingStrategy, cfg) -> str:
    """Return a SQL literal to use when hide_null=True and the value is NULL."""
    if strategy == MaskingStrategy.HASH:
        return "hashtextextended('', 0)::text"
    mask_char = "X"
    if cfg and hasattr(cfg, "mask_char"):
        mask_char = cfg.mask_char
    return f"'{mask_char}'"


# =========================================================
# TRIGGERS
# =========================================================

def _generate_triggers(project: GovernanceProject) -> str:
    lines = []
    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            lines.append(_generate_trigger_function(shadow, table))
            lines.append(_attach_trigger(schema.name, table.name))
            lines.append("")
    return "\n".join(lines)


def _generate_trigger_function(shadow: str, table: TableConfig) -> str:
    col_names = [c.name for c in table.columns]

    insert_cols = ", ".join(_q(c) for c in col_names)
    insert_vals = ", ".join(f"NEW.{_q(c)}" for c in col_names)

    immutable_checks = _generate_immutable_checks(table) if any(c.immutable for c in table.columns) else ""
    sensitive_stubs  = _generate_sensitive_stubs(table) if any(
        c.sensitive or c.encrypted or c.masking_strategy != "none"
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
    lines = []
    for col in table.columns:
        if col.sensitive:
            lines.append(f"        -- STUB: sensitive column {col.name} -- implement access control here")
        if col.encrypted:
            lines.append(f"        -- STUB: encrypted column {col.name} -- implement encryption/decryption here")
        if col.masking_strategy != "none":
            lines.append(f"        -- STUB: masking strategy '{col.masking_strategy}' on column {col.name} -- implement masking here")
    return "\n".join(lines) + "\n" if lines else ""


def _attach_trigger(schema_name: str, table_name: str) -> str:
    shadow = f"tk_{schema_name}"
    return (
        f"CREATE TRIGGER {_q('tr_' + table_name)}\n"
        f"INSTEAD OF INSERT OR UPDATE OR DELETE\n"
        f"ON {_q(schema_name)}.{_q(table_name)}\n"
        f"FOR EACH ROW EXECUTE FUNCTION {_q(shadow)}.{_q('tr_' + table_name)}();"
    )


def _pk_filter(table: TableConfig) -> str:
    pk_cols = [col for idx in table.indexes if idx.primary_key for col in idx.columns]
    if not pk_cols:
        pk_cols = [c.name for c in table.columns]
    return " AND ".join(f"{_q(col)} = NEW.{_q(col)}" for col in pk_cols)


# =========================================================
# ROLES
# =========================================================

def _generate_roles(project: GovernanceProject, current: GovernanceProject) -> str:
    lines = []
    existing_role_names = {r.name for r in current.roles}

    for role in project.roles:
        if role.name in existing_role_names:
            parts = [f"ALTER ROLE {_q(role.name)}"]
        else:
            parts = [f"CREATE ROLE {_q(role.name)}"]

        parts.append("LOGIN"    if role.can_login  else "NOLOGIN")
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
    lines = []

    schema_map = {s.name: s for s in project.schemas}
    table_map  = {(s.name, t.name): t for s in project.schemas for t in s.tables}

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

                # Determine which columns this role can access:
                # must meet clearance AND (column not sensitive OR role can_access_sensitive)
                accessible_cols = [
                    c for c in table.columns
                    if role.clearance >= c.clearance
                    and (not c.sensitive or role.can_access_sensitive)
                ]
                all_cols        = table.columns
                restricted      = len(accessible_cols) < len(all_cols)

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

                # Column-level SELECT restriction if needed
                if tp.select and restricted:
                    col_list = ", ".join(_q(c.name) for c in accessible_cols)
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

            lines.append("")

    return "\n".join(lines)


# =========================================================
# AUDIT (pgaudit)
# =========================================================

def _generate_audit(project: GovernanceProject) -> str:
    if not project.database.audit_enabled:
        return "-- Audit logging not enabled for this database.\n"

    levels = ", ".join(str(level) for level in project.database.audit_logged)
    db_name = _escape_sql_string(project.database.name)

    lines = [
        f"-- Configure pgaudit for database {db_name}",
        f"ALTER DATABASE {_q(db_name)} SET pgaudit.log = '{levels}';",
        f"ALTER DATABASE {_q(db_name)} SET pgaudit.log_catalog = off;",
        f"ALTER DATABASE {_q(db_name)} SET pgaudit.log_relation = on;",
        "",
    ]

    # Per-table audit overrides: disable pgaudit for tables with audit_enabled=false
    # by setting pgaudit.log = 'none' at the role level via SECURITY LABEL is complex,
    # so instead we document which tables are excluded as comments for now.
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

def _generate_meta_population(project: GovernanceProject) -> str:
    tarkin_version = pkg_version("tarkin")
    yaml_str       = _project_to_yaml_string(project)
    yaml_escaped   = _escape_sql_string(yaml_str)
    profile        = _escape_sql_string(project.database.profile or "")
    database_name  = _escape_sql_string(project.database.name)
    checksum       = _project_checksum(project)

    lines = ["DO $$", "DECLARE", "    v_build_id bigint;", "BEGIN"]

    # Build record
    lines += [
        f"    INSERT INTO __META__.tarkin_builds (tarkin_version, profile, database_name, checksum, yaml)",
        f"    VALUES ('{tarkin_version}', '{profile}', '{database_name}', '{checksum}', '{yaml_escaped}')",
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
        # migration record
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
                    f"immutable, versioned, sensitive, encrypted, masking_strategy, "
                    f"default_value, generated_expression, generated_storage) "
                    f"VALUES (v_build_id, '{sn}', '{tn}', '{cn}', '{ct}', {col.clearance}, "
                    f"{str(col.nullable).lower()}, {str(col.unique).lower()}, "
                    f"{str(col.immutable).lower()}, {str(col.versioned).lower()}, "
                    f"{str(col.sensitive).lower()}, {str(col.encrypted).lower()}, "
                    f"'{ms}', {dv}, {ge}, '{gs}');"
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

    # Roles
    for role in project.roles:
        rn  = _escape_sql_string(role.name)
        moa = ("ARRAY[" + ", ".join(f"'{_escape_sql_string(m)}'" for m in role.member_of) + "]"
               if role.member_of else "ARRAY[]::text[]")
        lines.append(
            f"    INSERT INTO __META__.tarkin_roles "
            f"(build_id, name, clearance, can_login, can_admin, can_write, "
            f"can_maintain, can_access_sensitive, active, member_of) "
            f"VALUES (v_build_id, '{rn}', {role.clearance}, "
            f"{str(role.can_login).lower()}, {str(role.can_admin).lower()}, "
            f"{str(role.can_write).lower()}, {str(role.can_maintain).lower()}, "
            f"{str(role.can_access_sensitive).lower()}, {str(role.active).lower()}, "
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

    lines += ["END;", "$$;"]
    return "\n".join(lines)


# =========================================================
# UTILS
# =========================================================

def _q(name: str) -> str:
    return f'"{name}"'


def _section(title: str, subtitle: str = "") -> str:
    line  = "-" * 60
    parts = [f"-- {line}", f"-- {title}"]
    if subtitle:
        parts.append(f"-- {subtitle}")
    parts.append(f"-- {line}")
    return "\n".join(parts)


def _escape_sql_string(s: str) -> str:
    if not s:
        return ""
    return s.replace("'", "''")


def _project_to_yaml_string(project: GovernanceProject) -> str:
    from .serialize import Serializer
    return Serializer.to_yaml_string(project)


def _project_checksum(project: GovernanceProject) -> str:
    return hashlib.sha256(_project_to_yaml_string(project).encode()).hexdigest()


def _object_checksum(obj: dict) -> str:
    """Generate a short checksum for a single governance object."""
    import json
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]
