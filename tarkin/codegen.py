from __future__ import annotations
from datetime import datetime, UTC
from importlib.metadata import version as pkg_version
import hashlib

from .model import (
    GovernanceProject, TableConfig,
)


# =========================================================
# ENTRY POINT
# =========================================================

def generate_sql(project: GovernanceProject, current: GovernanceProject) -> str:
    """
    Generate the full Tarkin SQL build for a governance project.
    current is the live database state captured by inspect at build time.
    """
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
    role_id              bigserial PRIMARY KEY,
    build_id             bigint NOT NULL REFERENCES __META__.tarkin_builds(build_id),
    name                 text NOT NULL,
    clearance            int NOT NULL DEFAULT 0,
    can_login            bool NOT NULL DEFAULT false,
    can_admin            bool NOT NULL DEFAULT false,
    can_write            bool NOT NULL DEFAULT false,
    can_maintain         bool NOT NULL DEFAULT false,
    can_access_sensitive bool NOT NULL DEFAULT false,
    active               bool NOT NULL DEFAULT true,
    member_of            text[] NOT NULL DEFAULT '{}'
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

def _generate_versioning_columns(
    project: GovernanceProject,
    current: GovernanceProject,
) -> str:
    lines = []

    current_col_map = {
        (s.name, t.name): {c.name for c in t.columns}
        for s in current.schemas
        for t in s.tables
    }

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            versioned_cols = [c for c in table.columns if c.versioned]
            if not versioned_cols:
                continue

            existing_cols = current_col_map.get((schema.name, table.name), set())
            has_valid_from = "__valid_from__" in existing_cols
            has_valid_to   = "__valid_to__" in existing_cols

            if has_valid_from or has_valid_to:
                lines.append(
                    f"-- WARNING: {shadow}.{table.name} already has "
                    f"__valid_from__/__valid_to__ columns. "
                    f"Existing data in these columns will be overwritten "
                    f"by Tarkin versioning."
                )

            if not has_valid_from:
                lines.append(
                    f"ALTER TABLE {_q(shadow)}.{_q(table.name)} "
                    f"ADD COLUMN __valid_from__ timestamptz "
                    f"NOT NULL DEFAULT now();"
                )
            if not has_valid_to:
                lines.append(
                    f"ALTER TABLE {_q(shadow)}.{_q(table.name)} "
                    f"ADD COLUMN __valid_to__ timestamptz "
                    f"NOT NULL DEFAULT 'infinity'::timestamptz;"
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
            col_list   = ", ".join(_q(c.name) for c in table.columns)
            is_versioned = any(c.versioned for c in table.columns)

            # Full view — all records
            lines.append(
                f"CREATE VIEW {_q(schema.name)}.{_q(table.name)} AS\n"
                f"    SELECT {col_list}\n"
                f"    FROM {_q(shadow)}.{_q(table.name)};"
            )

            if is_versioned:
                # Current view — active records only
                lines.append(
                    f"CREATE VIEW {_q(schema.name)}.{_q(table.name + '_current')} AS\n"
                    f"    SELECT {col_list}\n"
                    f"    FROM {_q(shadow)}.{_q(table.name)}\n"
                    f"    WHERE __valid_to__ >= now();"
                )

            lines.append("")

    return "\n".join(lines)


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


def _generate_trigger_function(
    shadow: str,
    table: TableConfig,
) -> str:
    col_names = [c.name for c in table.columns]

    insert_cols = ", ".join(_q(c) for c in col_names)
    insert_vals = ", ".join(f"NEW.{_q(c)}" for c in col_names)

    immutable_checks = _generate_immutable_checks(table) if any(c.immutable for c in table.columns) else ''
    sensitive_stubs = _generate_sensitive_stubs(table) if any(
        c.sensitive or c.encrypted or c.masking_strategy != "none"
        for c in table.columns
    ) else ''

    fn_name = _q('tr_' + table.name)
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
        update_set = ", ".join(
            f"{_q(c)} = NEW.{_q(c)}" for c in col_names
        )

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
    immutable_cols = [c for c in table.columns if c.immutable]
    if not immutable_cols:
        return ""
    lines = []
    for col in immutable_cols:
        lines.append(
            f"        IF OLD.{_q(col.name)} IS DISTINCT FROM NEW.{_q(col.name)} THEN\n"
            f"            RAISE EXCEPTION "
            f"'Column {col.name} is immutable and cannot be updated.';\n"
            f"        END IF;"
        )
    return "\n".join(lines) + "\n"


def _generate_sensitive_stubs(table: TableConfig) -> str:
    lines = []
    for col in table.columns:
        if col.sensitive:
            lines.append(
                f"        -- STUB: sensitive column {col.name} "
                f"-- implement access control here"
            )
        if col.encrypted:
            lines.append(
                f"        -- STUB: encrypted column {col.name} "
                f"-- implement encryption/decryption here"
            )
        if col.masking_strategy != "none":
            lines.append(
                f"        -- STUB: masking strategy '{col.masking_strategy}' "
                f"on column {col.name} -- implement masking here"
            )
    return "\n".join(lines) + "\n" if lines else ""


def _attach_trigger(schema_name: str, table_name: str) -> str:
    shadow = f"tk_{schema_name}"
    return (
        f"CREATE TRIGGER {_q('tr_' + table_name)}\n"
        f"INSTEAD OF INSERT OR UPDATE OR DELETE\n"
        f"ON {_q(schema_name)}.{_q(table_name)}\n"
        f"FOR EACH ROW EXECUTE FUNCTION "
        f"{_q(shadow)}.{_q('tr_' + table_name)}();"
    )


def _pk_filter(table: TableConfig) -> str:
    """Build a WHERE clause matching primary key columns."""
    pk_cols = [
        col
        for idx in table.indexes if idx.primary_key
        for col in idx.columns
    ]
    if not pk_cols:
        pk_cols = [c.name for c in table.columns]
    return " AND ".join(
        f"{_q(col)} = NEW.{_q(col)}"
        for col in pk_cols
    )


# =========================================================
# ROLES
# =========================================================

def _generate_roles(project: GovernanceProject, current: GovernanceProject) -> str:
    lines = []
    existing_role_names = {r.name for r in current.roles}

    for role in project.roles:
        if role.name in existing_role_names:
            # Role exists — ALTER to match desired state
            parts = [f"ALTER ROLE {_q(role.name)}"]
        else:
            # Role is new — CREATE
            parts = [f"CREATE ROLE {_q(role.name)}"]

        if role.can_login:
            parts.append("LOGIN")
        else:
            parts.append("NOLOGIN")
        if role.can_admin:
            parts.append("SUPERUSER")
        else:
            parts.append("NOSUPERUSER")
        if role.can_write:
            parts.append("CREATEDB CREATEROLE")
        else:
            parts.append("NOCREATEDB NOCREATEROLE")

        lines.append(" ".join(parts) + ";")

        # Only GRANT membership for new roles — existing membership
        # may already be set and re-granting is harmless, but
        # we should avoid revoking memberships not in the model
        for parent in role.member_of:
            lines.append(
                f"GRANT {_q(parent)} TO {_q(role.name)};"
            )

        lines.append("")

    return "\n".join(lines)


# =========================================================
# GRANTS
# =========================================================

def _generate_grants(project: GovernanceProject) -> str:
    lines = []

    schema_map = {s.name: s for s in project.schemas}
    table_map  = {
        (s.name, t.name): t
        for s in project.schemas
        for t in s.tables
    }

    for role in project.roles:
        for sp in role.on:
            schema = schema_map.get(sp.name)
            if not schema:
                continue

            # Schema-level grants
            schema_privs = []
            if sp.usage:
                schema_privs.append("USAGE")
            if sp.create:
                schema_privs.append("CREATE")
            if schema_privs:
                lines.append(
                    f"GRANT {', '.join(schema_privs)} ON SCHEMA {_q(sp.name)} "
                    f"TO {_q(role.name)};"
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

                table_privs = []
                if tp.select:      table_privs.append("SELECT")
                if tp.insert:      table_privs.append("INSERT")
                if tp.update:      table_privs.append("UPDATE")
                if tp.delete:      table_privs.append("DELETE")
                if tp.truncate:    table_privs.append("TRUNCATE")
                if tp.references:  table_privs.append("REFERENCES")
                if tp.trigger:     table_privs.append("TRIGGER")
                if tp.maintain:    table_privs.append("MAINTAIN")

                if table_privs:
                    lines.append(
                        f"GRANT {', '.join(table_privs)} ON "
                        f"{_q(sp.name)}.{_q(tp.name)} TO {_q(role.name)};"
                    )

                # Column-level clearance filtering
                if tp.select:
                    restricted_cols = [
                        c for c in table.columns
                        if role.clearance < c.clearance
                    ]
                    if restricted_cols:
                        allowed_cols = [
                            c for c in table.columns
                            if role.clearance >= c.clearance
                        ]
                        if not allowed_cols:
                            lines.append(
                                f"-- No columns accessible for {role.name} on "
                                f"{sp.name}.{tp.name} due to clearance restrictions"
                            )
                            lines.append(
                                f"REVOKE SELECT ON {_q(sp.name)}.{_q(tp.name)} "
                                f"FROM {_q(role.name)};"
                            )
                        else:
                            col_list = ", ".join(_q(c.name) for c in allowed_cols)
                            lines.append(
                                f"-- Column-level SELECT restricted by clearance "
                                f"for {role.name} on {sp.name}.{tp.name}"
                            )
                            lines.append(
                                f"REVOKE SELECT ON {_q(sp.name)}.{_q(tp.name)} "
                                f"FROM {_q(role.name)};"
                            )
                            lines.append(
                                f"GRANT SELECT ({col_list}) ON "
                                f"{_q(sp.name)}.{_q(tp.name)} TO {_q(role.name)};"
                            )

            lines.append("")

    return "\n".join(lines)


# =========================================================
# META POPULATION
# =========================================================

def _generate_meta_population(project: GovernanceProject) -> str:
    tarkin_version = pkg_version("tarkin")

    yaml_str      = _project_to_yaml_string(project)
    yaml_escaped  = _escape_sql_string(yaml_str)
    profile       = _escape_sql_string(project.database.profile or "")
    database_name = _escape_sql_string(project.database.name)
    checksum      = _project_checksum(project)

    lines = ["DO $$", "DECLARE", "    v_build_id bigint;", "BEGIN"]

    # Build record
    lines += [
        f"    INSERT INTO __META__.tarkin_builds "
        f"(tarkin_version, profile, database_name, checksum, yaml)",
        f"    VALUES ("
        f"'{tarkin_version}', '{profile}', '{database_name}', "
        f"'{checksum}', '{yaml_escaped}')",
        f"    RETURNING build_id INTO v_build_id;",
        "",
    ]

    # Schemas
    for schema in project.schemas:
        lines.append(
            f"    INSERT INTO __META__.tarkin_schemas "
            f"(build_id, name, shadow_name, clearance, audit_enabled) VALUES ("
            f"v_build_id, '{_escape_sql_string(schema.name)}', "
            f"'tk_{_escape_sql_string(schema.name)}', "
            f"{schema.clearance}, {str(schema.audit_enabled).lower()});"
        )
    lines.append("")

    # Tables
    for schema in project.schemas:
        for table in schema.tables:
            lines.append(
                f"    INSERT INTO __META__.tarkin_tables "
                f"(build_id, schema_name, name, clearance, audit_enabled) VALUES ("
                f"v_build_id, '{_escape_sql_string(schema.name)}', "
                f"'{_escape_sql_string(table.name)}', "
                f"{table.clearance}, {str(table.audit_enabled).lower()});"
            )
    lines.append("")

    # Columns
    for schema in project.schemas:
        for table in schema.tables:
            for col in table.columns:
                default_val = (
                    f"'{_escape_sql_string(col.default)}'"
                    if col.default else "NULL"
                )
                gen_expr = (
                    f"'{_escape_sql_string(col.generated_expression)}'"
                    if col.generated_expression else "NULL"
                )
                lines.append(
                    f"    INSERT INTO __META__.tarkin_columns "
                    f"(build_id, schema_name, table_name, name, type, clearance, "
                    f"nullable, \"unique\", immutable, versioned, sensitive, encrypted, "
                    f"masking_strategy, default_value, generated_expression, "
                    f"generated_storage) VALUES ("
                    f"v_build_id, '{_escape_sql_string(schema.name)}', "
                    f"'{_escape_sql_string(table.name)}', "
                    f"'{_escape_sql_string(col.name)}', "
                    f"'{_escape_sql_string(col.type)}', "
                    f"{col.clearance}, {str(col.nullable).lower()}, "
                    f"{str(col.unique).lower()}, {str(col.immutable).lower()}, "
                    f"{str(col.versioned).lower()}, {str(col.sensitive).lower()}, "
                    f"{str(col.encrypted).lower()}, "
                    f"'{_escape_sql_string(col.masking_strategy)}', "
                    f"{default_val}, {gen_expr}, "
                    f"'{_escape_sql_string(col.generated_storage)}');"
                )
    lines.append("")

    # Indexes
    for schema in project.schemas:
        for table in schema.tables:
            for idx in table.indexes:
                cols_array = (
                    "ARRAY[" + ", ".join(f"'{c}'" for c in idx.columns) + "]"
                )
                partial = (
                    f"'{_escape_sql_string(idx.partial_filter)}'"
                    if idx.partial_filter else "NULL"
                )
                lines.append(
                    f"    INSERT INTO __META__.tarkin_indexes "
                    f"(build_id, schema_name, table_name, name, columns, "
                    f"index_type, \"unique\", primary_key, partial_filter) VALUES ("
                    f"v_build_id, '{_escape_sql_string(schema.name)}', "
                    f"'{_escape_sql_string(table.name)}', "
                    f"'{_escape_sql_string(idx.name)}', "
                    f"{cols_array}, '{idx.index_type}', "
                    f"{str(idx.unique).lower()}, {str(idx.primary_key).lower()}, "
                    f"{partial});"
                )
    lines.append("")

    # Foreign keys
    for schema in project.schemas:
        for table in schema.tables:
            for fk in table.foreign_keys:
                lines.append(
                    f"    INSERT INTO __META__.tarkin_foreign_keys "
                    f"(build_id, schema_name, table_name, name, column_name, "
                    f"referenced_schema, referenced_table, referenced_column) VALUES ("
                    f"v_build_id, '{_escape_sql_string(schema.name)}', "
                    f"'{_escape_sql_string(table.name)}', "
                    f"'{_escape_sql_string(fk.name)}', "
                    f"'{_escape_sql_string(fk.column)}', "
                    f"'{_escape_sql_string(fk.referenced_schema)}', "
                    f"'{_escape_sql_string(fk.referenced_table)}', "
                    f"'{_escape_sql_string(fk.referenced_column)}');"
                )
    lines.append("")

    # Roles
    for role in project.roles:
        member_of_array = (
            "ARRAY[" + ", ".join(f"'{_escape_sql_string(m)}'" for m in role.member_of) + "]"
            if role.member_of else "ARRAY[]::text[]"
        )
        lines.append(
            f"    INSERT INTO __META__.tarkin_roles "
            f"(build_id, name, clearance, can_login, can_admin, can_write, "
            f"can_maintain, can_access_sensitive, active, member_of) VALUES ("
            f"v_build_id, '{_escape_sql_string(role.name)}', {role.clearance}, "
            f"{str(role.can_login).lower()}, {str(role.can_admin).lower()}, "
            f"{str(role.can_write).lower()}, {str(role.can_maintain).lower()}, "
            f"{str(role.can_access_sensitive).lower()}, {str(role.active).lower()}, "
            f"{member_of_array});"
        )
    lines.append("")

    # Role schema permissions
    for role in project.roles:
        for sp in role.on:
            lines.append(
                f"    INSERT INTO __META__.tarkin_role_schemas "
                f"(build_id, role_name, schema_name, \"usage\", \"create\") VALUES ("
                f"v_build_id, '{_escape_sql_string(role.name)}', "
                f"'{_escape_sql_string(sp.name)}', "
                f"{str(sp.usage).lower()}, {str(sp.create).lower()});"
            )
    lines.append("")

    # Role table permissions
    for role in project.roles:
        for sp in role.on:
            for tp in sp.tables:
                lines.append(
                    f"    INSERT INTO __META__.tarkin_role_tables "
                    f"(build_id, role_name, schema_name, table_name, \"select\", "
                    f"\"insert\", \"update\", \"delete\", \"truncate\", \"references\", \"trigger\", "
                    f"\"maintain\") VALUES ("
                    f"v_build_id, '{_escape_sql_string(role.name)}', "
                    f"'{_escape_sql_string(sp.name)}', "
                    f"'{_escape_sql_string(tp.name)}', "
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
    """Quote a PostgreSQL identifier."""
    return f'"{name}"'


def _section(title: str, subtitle: str = "") -> str:
    line = "-" * 60
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
    yaml_str = _project_to_yaml_string(project)
    return hashlib.sha256(yaml_str.encode()).hexdigest()
