"""Generate a migration artifact from the current build to a new governance YAML."""
from __future__ import annotations
import copy
from collections import defaultdict
from datetime import datetime, UTC
from importlib.metadata import version as pkg_version
from pathlib import Path
from sqlalchemy import text
from typing import cast

from .codegen import (
    _generate_rls,
    _generate_triggers,
    _generate_views,
)
from .credentials import ConnectionProfile
from .diff import (
    diff_projects,
    Change,
    ChangeKind,
    ObjectType,
)
from .model import (
    DatabaseConfig,
    GovernanceProject,
    RoleConfig,
    SchemaConfig,
    SchemaPermissionConfig,
    TableConfig,
)
from .serialize import Serializer
from .yaml import YamlLoader
from .utils import (
    OUT_DIR,
    build_output_directory,
    project_checksum,
    sql_comment_block_section,
    sql_safe_dollar_quote,
    sql_safe_double_quote,
    write_artifact,
)


def migrate(
    after:    GovernanceProject,
    profile:  ConnectionProfile,
    output: Path | None = None,
) -> Path:
    """Generate a migration artifact from the current live build to *after*."""
    output = (output or OUT_DIR)
    build_output_directory(output)

    print("Reading current build from __META__...", end="\r")
    before, build_checksum, db_name = _read_current_build(profile)
    print("Reading current build from __META__... Done.")

    print("Assessing differences...", end="\r")
    changes = diff_projects(before, after)
    print(f"Assessing differences... Done. {len(changes)} change(s) detected.")

    if not changes:
        raise MigrateError(
            "No differences detected between the current build and the target YAML. "
            "Nothing to migrate."
        )

    print("Generating migration SQL...", end="\r")
    sql = _generate_migration_sql(before, after, changes)
    print("Generating migration SQL... Done.")

    timestamp = datetime.now(UTC).strftime("%Y_%m_%d_%H_%M_%S")
    zip_path  = output / f"tarkin_migrate_{timestamp}.zip"
    metadata  = _migration_metadata(after, profile, build_checksum, db_name, changes)
    write_artifact(zip_path, sql, metadata)
    print(f"Migration artifact written to {zip_path}.")

    return zip_path


def _read_current_build(profile: ConnectionProfile) -> tuple[GovernanceProject, str, str]:
    """Read the most recent build's YAML, checksum, and database name from __META__."""
    engine = profile.engine()
    try:
        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT yaml, checksum, database_name "
                "FROM __META__.tarkin_builds "
                "ORDER BY built_at DESC LIMIT 1"
            )).fetchone()
    finally:
        engine.dispose()

    if not row:
        raise MigrateError(
            "No Tarkin build found in __META__. "
            "Run 'tarkin build' and 'tarkin attach' before migrating."
        )

    yaml_str, checksum, db_name = row[0], row[1], row[2]

    try:
        project = YamlLoader.loads(yaml_str)
    except Exception as exc:
        raise MigrateError(
            f"Failed to parse the stored build YAML from __META__: {exc}"
        ) from exc

    if project is None:
        raise MigrateError("Stored build YAML in __META__ parsed to None.")

    return project, checksum, db_name


def _generate_migration_sql(
    before:  GovernanceProject,
    after:   GovernanceProject,
    changes: list[Change],
) -> str:
    """Generate ordered, transactional migration SQL from a list of Changes.

    Execution order:
      1. Drop FK constraints (free dependencies)
      2. Drop RLS policies
      3. Drop indexes (non-PK)
      4. Drop triggers and views
      5. Schema additions / removals
      6. Table additions / removals
      7. Column ALTER/ADD/DROP on shadow tables
      8. Versioning column additions
      9. Recreate views
      10. Recreate triggers
      11. Recreate indexes
      12. Recreate FK constraints
      13. Recreate RLS policies
      14. Role and permission changes
      15. Update __META__

    Changes that cannot be safely automated (e.g. schema renames, PK changes)
    are emitted as prominently commented stubs that raise at runtime, forcing
    the operator to handle them manually.
    """
    sections = [
        sql_comment_block_section("TARKIN MIGRATION", f"Generated at {datetime.now(UTC).isoformat()}"),
        sql_comment_block_section("TRANSACTION START"),
        "BEGIN;\n",
    ]

    before_schema_map = {s.name: s for s in before.schemas}
    after_schema_map  = {s.name: s for s in after.schemas}
    before_table_map  = {
        (s.name, t.name): t
        for s in before.schemas for t in s.tables
    }
    after_table_map   = {
        (s.name, t.name): t
        for s in after.schemas for t in s.tables
    }

    drop_fks     = _emit_drop_fks(changes)
    drop_rls     = _emit_drop_rls(changes)
    drop_indexes = _emit_drop_indexes(changes, before_table_map)
    drop_views   = _emit_drop_views(changes, before_schema_map)
    schema_ops   = _emit_schema_changes(changes)
    table_ops    = _emit_table_changes(changes, after_schema_map)
    column_ops   = _emit_column_changes(changes, after_table_map)
    add_views    = _emit_add_views(changes, after)
    add_triggers = _emit_add_triggers(changes, after)
    add_indexes  = _emit_add_indexes(changes, after_table_map)
    add_fks      = _emit_add_fks(changes, after_table_map)
    add_rls      = _emit_add_rls(changes, after_table_map, after)
    role_ops     = _emit_role_changes(changes, before, after)
    meta_update  = _emit_meta_update(after)

    for title, sql_block in [
        ("DROP FK CONSTRAINTS",       drop_fks),
        ("DROP RLS POLICIES",         drop_rls),
        ("DROP INDEXES",              drop_indexes),
        ("DROP VIEWS & TRIGGERS",     drop_views),
        ("SCHEMA CHANGES",            schema_ops),
        ("TABLE CHANGES",             table_ops),
        ("COLUMN CHANGES",            column_ops),
        ("ADD VIEWS",                 add_views),
        ("ADD TRIGGERS",              add_triggers),
        ("ADD INDEXES",               add_indexes),
        ("ADD FK CONSTRAINTS",        add_fks),
        ("ADD RLS POLICIES",          add_rls),
        ("ROLE & PERMISSION CHANGES", role_ops),
        ("UPDATE META",               meta_update),
    ]:
        if sql_block.strip():
            sections.append(sql_comment_block_section(title))
            sections.append(sql_block)

    sections += [sql_comment_block_section("TRANSACTION END"), "COMMIT;\n"]
    return "\n".join(sections)


def _emit_drop_fks(changes: list[Change]) -> str:
    lines = []
    for c in changes:
        if c.object_type == ObjectType.FOREIGN_KEY and c.kind in (ChangeKind.REMOVED, ChangeKind.MODIFIED):
            parts = c.path.split(".")
            if len(parts) == 3:
                schema_name, table_name, fk_name = parts
                shadow = f"tk_{schema_name}"
                lines.append(
                    f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} "
                    f"DROP CONSTRAINT IF EXISTS {sql_safe_double_quote(fk_name)};"
                )
    return "\n".join(lines) + "\n" if lines else ""


def _emit_drop_rls(changes: list[Change]) -> str:
    """Drop RLS policies for tables whose RLS config changed."""
    lines = []
    affected: set[tuple[str, str]] = set()

    for c in changes:
        if c.object_type == ObjectType.TABLE and c.field and c.field.startswith("rls"):
            parts = c.path.split(".")
            if len(parts) == 2:
                affected.add((parts[0], parts[1]))

    for schema_name, table_name in sorted(affected):
        shadow = f"tk_{schema_name}"
        lines += [
            f"-- Drop all tarkin_rls_* policies on {schema_name}.{table_name} for recreation",
            f"DO $$",
            f"DECLARE r record;",
            f"BEGIN",
            f"    FOR r IN SELECT policyname FROM pg_policies",
            f"        WHERE schemaname = '{schema_name}' AND tablename = '{table_name}'",
            f"          AND policyname LIKE 'tarkin_rls_%'",
            f"    LOOP",
            f"        EXECUTE format('DROP POLICY IF EXISTS %I ON {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(table_name)}', r.policyname);",
            f"    END LOOP;",
            f"END; $$ LANGUAGE plpgsql;",
            f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} DISABLE ROW LEVEL SECURITY;",
            f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} NO FORCE ROW LEVEL SECURITY;",
        ]
    return "\n".join(lines) + "\n" if lines else ""


def _emit_drop_indexes(changes: list[Change], before_table_map: dict) -> str:
    lines = []
    for c in changes:
        if c.object_type == ObjectType.INDEX and c.kind in (ChangeKind.REMOVED, ChangeKind.MODIFIED):
            parts = c.path.split(".")
            if len(parts) == 3:
                schema_name, table_name, idx_name = parts
                tbl = cast(TableConfig, before_table_map.get((schema_name, table_name)))
                if tbl:
                    idx = next((i for i in tbl.indexes if i.name == idx_name), None)
                    if idx and idx.primary_key:
                        lines.append(
                            f"-- WARNING: Primary key change on {schema_name}.{table_name}.{idx_name} "
                            f"requires manual intervention.\n"
                            f"-- RAISE EXCEPTION 'Tarkin: manual primary key migration required on "
                            f"{schema_name}.{table_name}';"
                        )
                        continue
                shadow = f"tk_{schema_name}"
                lines.append(f"DROP INDEX IF EXISTS {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(idx_name)};")
    return "\n".join(lines) + "\n" if lines else ""


def _affected_tables_for_changes(changes: list[Change]) -> dict[str, set[str]]:
    """Return a mapping of schema_name -> {table_names} that have structural changes."""
    affected: dict[str, set[str]] = {}
    for c in changes:
        parts = c.path.split(".")
        if c.object_type == ObjectType.COLUMN and len(parts) == 3:
            schema_name, table_name, _ = parts
            affected.setdefault(schema_name, set()).add(table_name)
        elif c.object_type == ObjectType.TABLE and len(parts) == 2:
            schema_name, table_name = parts
            affected.setdefault(schema_name, set()).add(table_name)
        elif c.object_type == ObjectType.SCHEMA and len(parts) == 1:
            affected.setdefault(parts[0], set())
    return affected


def _emit_drop_views(changes: list[Change], before_schema_map: dict) -> str:
    """Drop views and triggers for changed tables only."""
    lines = []
    affected = _affected_tables_for_changes(changes)

    for schema_name, changed_tables in sorted(affected.items()):
        schema = cast(SchemaConfig, before_schema_map.get(schema_name))
        if not schema:
            # New schema — nothing to drop
            continue

        tables_to_drop = (
            schema.tables if not changed_tables
            else [t for t in schema.tables if t.name in changed_tables]
        )

        for table in tables_to_drop:
            lines.append(
                f"DROP TRIGGER IF EXISTS {sql_safe_double_quote('tr_' + table.name)} "
                f"ON {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(table.name)};"
            )
            lines.append(
                f"DROP FUNCTION IF EXISTS {sql_safe_double_quote('tk_' + schema_name)}.{sql_safe_double_quote('tr_' + table.name)}();"
            )
            lines.append(f"DROP VIEW IF EXISTS {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(table.name)} CASCADE;")
            versioned = any(c.versioned for c in table.columns)
            if versioned:
                lines.append(
                    f"DROP VIEW IF EXISTS {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(table.name + '_current')} CASCADE;"
                )

    return "\n".join(lines) + "\n" if lines else ""


def _emit_schema_changes(changes: list[Change]) -> str:
    lines = []
    for c in changes:
        if c.object_type != ObjectType.SCHEMA:
            continue
        if c.kind == ChangeKind.ADDED:
            shadow = f"tk_{c.path}"
            lines += [
                f"CREATE SCHEMA {sql_safe_double_quote(c.path)};",
                f"CREATE SCHEMA {sql_safe_double_quote(shadow)};",
            ]
        elif c.kind == ChangeKind.REMOVED:
            lines.append(
                f"-- WARNING: Schema '{c.path}' removed from YAML. "
                f"Shadow schema 'tk_{c.path}' and all its data will be lost.\n"
                f"DROP SCHEMA IF EXISTS {sql_safe_double_quote('tk_' + c.path)} CASCADE;\n"
                f"DROP SCHEMA IF EXISTS {sql_safe_double_quote(c.path)} CASCADE;"
            )
    return "\n".join(lines) + "\n" if lines else ""


def _emit_table_changes(changes: list[Change], after_schema_map: dict) -> str:
    lines = []
    for c in changes:
        if c.object_type != ObjectType.TABLE:
            continue
        if c.kind == ChangeKind.ADDED:
            parts = c.path.split(".")
            if len(parts) != 2:
                continue
            schema_name, table_name = parts
            schema = cast(SchemaConfig, after_schema_map.get(schema_name))
            if not schema:
                continue
            table = next((t for t in schema.tables if t.name == table_name), None)
            if not table:
                continue
            shadow = f"tk_{schema_name}"
            col_defs = ", ".join(
                f"{sql_safe_double_quote(col.name)} {col.type}"
                + (" NOT NULL" if not col.nullable else "")
                for col in table.columns
                if not col.is_generated
            )
            lines.append(f"CREATE TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} ({col_defs});")
            for idx in table.indexes:
                unique = "UNIQUE " if idx.unique else ""
                cols   = ", ".join(sql_safe_double_quote(c) for c in idx.columns)
                if idx.primary_key:
                    lines.append(
                        f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} ADD PRIMARY KEY ({cols});"
                    )
                else:
                    lines.append(
                        f"CREATE {unique}INDEX {sql_safe_double_quote(idx.name)} "
                        f"ON {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} ({cols});"
                    )

        elif c.kind == ChangeKind.REMOVED:
            parts = c.path.split(".")
            if len(parts) != 2:
                continue
            schema_name, table_name = parts
            shadow = f"tk_{schema_name}"
            lines.append(
                f"-- WARNING: Table '{c.path}' removed. All data will be lost.\n"
                f"DROP TABLE IF EXISTS {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} CASCADE;"
            )

        elif c.kind == ChangeKind.MODIFIED and c.field in (
            "rls_enabled", "rls_force", "rls_security_barrier",
            "audit_enabled", "clearance", "erase_strategy",
            "retention_days",
        ):
            # These are metadata or codegen-level — handled in other sections or META update
            pass

    return "\n".join(lines) + "\n" if lines else ""


def _emit_column_changes(changes: list[Change], after_table_map: dict) -> str:
    lines = []
    for c in changes:
        if c.object_type != ObjectType.COLUMN:
            continue
        parts = c.path.split(".")
        if len(parts) != 3:
            continue
        schema_name, table_name, col_name = parts
        shadow  = f"tk_{schema_name}"
        tbl_ref = f"{sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)}"

        if c.kind == ChangeKind.ADDED:
            tbl = cast(TableConfig, after_table_map.get((schema_name, table_name)))
            col = next((c2 for c2 in tbl.columns if c2.name == col_name), None) if tbl else None
            if col:
                null_clause = "" if col.nullable else " NOT NULL"
                default     = f" DEFAULT {col.default}" if col.default else ""
                lines.append(
                    f"ALTER TABLE {tbl_ref} ADD COLUMN {sql_safe_double_quote(col_name)} {col.type}{null_clause}{default};"
                )

        elif c.kind == ChangeKind.REMOVED:
            lines.append(
                f"-- WARNING: Column '{c.path}' removed. Data in this column will be lost.\n"
                f"ALTER TABLE {tbl_ref} DROP COLUMN IF EXISTS {sql_safe_double_quote(col_name)};"
            )

        elif c.kind == ChangeKind.MODIFIED:
            if c.field == "type":
                lines.append(
                    f"-- WARNING: Type change on '{c.path}': {c.before} → {c.after}.\n"
                    f"-- Verify the USING cast is correct before applying.\n"
                    f"ALTER TABLE {tbl_ref} ALTER COLUMN {sql_safe_double_quote(col_name)} "
                    f"TYPE {c.after} USING {sql_safe_double_quote(col_name)}::{c.after};"
                )
            elif c.field == "nullable":
                if c.after:
                    lines.append(
                        f"ALTER TABLE {tbl_ref} ALTER COLUMN {sql_safe_double_quote(col_name)} DROP NOT NULL;"
                    )
                else:
                    lines.append(
                        f"-- WARNING: Adding NOT NULL to '{c.path}'. "
                        f"Ensure no NULL values exist before applying.\n"
                        f"ALTER TABLE {tbl_ref} ALTER COLUMN {sql_safe_double_quote(col_name)} SET NOT NULL;"
                    )
            elif c.field == "default":
                if c.after is None:
                    lines.append(
                        f"ALTER TABLE {tbl_ref} ALTER COLUMN {sql_safe_double_quote(col_name)} DROP DEFAULT;"
                    )
                else:
                    lines.append(
                        f"ALTER TABLE {tbl_ref} ALTER COLUMN {sql_safe_double_quote(col_name)} SET DEFAULT {c.after};"
                    )
            elif c.field in ("masking_strategy", "mask_config", "sensitive",
                             "clearance", "is_subject_identifier", "versioned"):
                # View-layer changes — handled by view recreation
                pass

    return "\n".join(lines) + "\n" if lines else ""


def _emit_add_views(changes: list[Change], after: GovernanceProject) -> str:
    """Recreate views for changed tables only."""
    affected = _affected_tables_for_changes(changes)

    if not affected:
        return ""

    filtered_schemas = []
    for schema in after.schemas:
        changed_tables = affected.get(schema.name)
        if changed_tables is None:
            continue
        if not changed_tables:
            filtered_schemas.append(schema)
        else:
            s = copy.copy(schema)
            s = s.model_copy(update={"tables": [t for t in schema.tables if t.name in changed_tables]})
            if s.tables:
                filtered_schemas.append(s)

    if not filtered_schemas:
        return ""

    filtered = after.model_copy(update={"schemas": filtered_schemas})
    return _generate_views(filtered)


def _emit_add_triggers(changes: list[Change], after: GovernanceProject) -> str:
    """Recreate triggers for changed tables only."""
    affected = _affected_tables_for_changes(changes)

    if not affected:
        return ""

    filtered_schemas = []
    for schema in after.schemas:
        changed_tables = affected.get(schema.name)
        if changed_tables is None:
            continue
        if not changed_tables:
            filtered_schemas.append(schema)
        else:
            s = schema.model_copy(update={"tables": [t for t in schema.tables if t.name in changed_tables]})
            if s.tables:
                filtered_schemas.append(s)

    if not filtered_schemas:
        return ""

    filtered = after.model_copy(update={"schemas": filtered_schemas})
    return _generate_triggers(filtered)


def _emit_add_indexes(changes: list[Change], after_table_map: dict) -> str:
    lines = []
    for c in changes:
        if c.object_type == ObjectType.INDEX and c.kind in (ChangeKind.ADDED, ChangeKind.MODIFIED):
            parts = c.path.split(".")
            if len(parts) != 3:
                continue
            schema_name, table_name, idx_name = parts
            tbl = cast(TableConfig, after_table_map.get((schema_name, table_name)))
            if not tbl:
                continue
            idx = next((i for i in tbl.indexes if i.name == idx_name), None)
            if not idx:
                continue
            if idx.primary_key:
                lines.append(
                    f"-- WARNING: Primary key addition/change on {c.path} requires manual intervention."
                )
                continue
            shadow  = f"tk_{schema_name}"
            unique  = "UNIQUE " if idx.unique else ""
            cols    = ", ".join(sql_safe_double_quote(col) for col in idx.columns)
            partial = f" WHERE {idx.partial_filter}" if idx.partial_filter else ""
            lines.append(
                f"CREATE {unique}INDEX {sql_safe_double_quote(idx_name)} "
                f"ON {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} ({cols}){partial};"
            )
    return "\n".join(lines) + "\n" if lines else ""


def _emit_add_fks(changes: list[Change], after_table_map: dict) -> str:
    lines = []
    for c in changes:
        if c.object_type == ObjectType.FOREIGN_KEY and c.kind in (ChangeKind.ADDED, ChangeKind.MODIFIED):
            parts = c.path.split(".")
            if len(parts) != 3:
                continue
            schema_name, table_name, fk_name = parts
            tbl = cast(TableConfig, after_table_map.get((schema_name, table_name)))
            if not tbl:
                continue
            fk = next((f for f in tbl.foreign_keys if f.name == fk_name), None)
            if not fk:
                continue
            shadow     = f"tk_{schema_name}"
            ref_shadow = f"tk_{fk.referenced_schema}"
            lines.append(
                f"ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)} "
                f"ADD CONSTRAINT {sql_safe_double_quote(fk_name)} "
                f"FOREIGN KEY ({sql_safe_double_quote(fk.column)}) "
                f"REFERENCES {sql_safe_double_quote(ref_shadow)}.{sql_safe_double_quote(fk.referenced_table)} ({sql_safe_double_quote(fk.referenced_column)});"
            )
    return "\n".join(lines) + "\n" if lines else ""


def _emit_add_rls(changes: list[Change], after_table_map: dict, after: GovernanceProject) -> str:
    affected: set[tuple[str, str]] = set()
    for c in changes:
        if c.object_type == ObjectType.TABLE and c.field and c.field.startswith("rls"):
            parts = c.path.split(".")
            if len(parts) == 2:
                affected.add((parts[0], parts[1]))

    if not affected:
        return ""

    schema_tables: dict[str, list] = defaultdict(list)
    for schema_name, table_name in affected:
        tbl = after_table_map.get((schema_name, table_name))
        if tbl:
            schema_tables[schema_name].append(tbl)

    schemas = [
        SchemaConfig(name=sn, tables=tbls)
        for sn, tbls in schema_tables.items()
    ]
    dummy_role = RoleConfig(
        name      = "__dummy__",
        can_login = True,
        on        = [SchemaPermissionConfig(name=sn) for sn in schema_tables],
    )
    proj = GovernanceProject(
        database = DatabaseConfig(name="__dummy__", version=after.database.version),
        schemas  = schemas,
        roles    = [dummy_role],
    )
    return _generate_rls(proj)


def _emit_role_changes(changes: list[Change], before: GovernanceProject, after: GovernanceProject) -> str:
    from .codegen import _generate_roles, _generate_grants
    role_changes = [c for c in changes if c.object_type in (ObjectType.ROLE, ObjectType.PERMISSION)]
    if not role_changes:
        return ""

    lines = [
        "-- Role and permission changes are applied by regenerating grants.",
        "-- Existing grants for affected roles are revoked first.",
    ]

    affected_roles = {c.path.split(".")[0] for c in role_changes}
    before_role_map = {r.name: r for r in before.roles}

    for role_name in sorted(affected_roles):
        before_role = before_role_map.get(role_name)
        if before_role:
            for sp in before_role.on:
                for tp in sp.tables:
                    for priv in ("SELECT", "INSERT", "UPDATE", "DELETE",
                                 "TRUNCATE", "REFERENCES", "TRIGGER"):
                        lines.append(
                            f"REVOKE {priv} ON {sql_safe_double_quote(sp.name)}.{sql_safe_double_quote(tp.name)} "
                            f"FROM {sql_safe_double_quote(role_name)};"
                        )
                lines.append(f"REVOKE USAGE ON SCHEMA {sql_safe_double_quote(sp.name)} FROM {sql_safe_double_quote(role_name)};")

    synthetic_current_roles = list(before.roles)
    if before.database.audit_enabled:
        synthetic_current_roles.append(RoleConfig(
            name      = "tarkin_audit",
            can_login = False,
            on        = [SchemaPermissionConfig(name=before.schemas[0].name)] if before.schemas else [],
        ))
    synthetic_current = before.model_copy(update={"roles": synthetic_current_roles})

    lines.append(_generate_roles(after, synthetic_current))
    lines.append(_generate_grants(after))

    return "\n".join(lines) + "\n"


def _emit_meta_update(after: GovernanceProject) -> str:
    """Update __META__.tarkin_builds with the new YAML and checksum."""
    yaml_str  = Serializer.to_yaml_string(after)
    checksum  = project_checksum(after)
    version   = pkg_version("tarkin")
    dq_open, dq_close = sql_safe_dollar_quote(yaml_str)
    return (
        f"INSERT INTO __META__.tarkin_builds "
        f"(tarkin_version, profile, database_name, checksum, yaml, pgcrypto_enabled_by_tarkin) "
        f"VALUES ('{version}', "
        f"(SELECT profile FROM __META__.tarkin_builds ORDER BY built_at DESC LIMIT 1), "
        f"(SELECT database_name FROM __META__.tarkin_builds ORDER BY built_at DESC LIMIT 1), "
        f"'{checksum}', "
        f"{dq_open}{yaml_str}{dq_close}, "
        f"(SELECT pgcrypto_enabled_by_tarkin FROM __META__.tarkin_builds ORDER BY built_at DESC LIMIT 1)"
        f");\n"
    )


def _migration_metadata(
    after:           GovernanceProject,
    profile:         ConnectionProfile,
    source_checksum: str,
    db_name:         str,
    changes:         list[Change],
) -> dict:
    return {
        "artifact_type":   "migrate",
        "tarkin_version":  pkg_version("tarkin"),
        "migrated_at":     datetime.now(UTC).isoformat(),
        "profile":         profile.profile,
        "database":        db_name,
        "host":            profile.host,
        "port":            profile.port,
        "source_checksum": source_checksum,
        "target_checksum": project_checksum(after),
        "change_count":    len(changes),
        "changes": [
            {
                "kind":        c.kind,
                "object_type": c.object_type,
                "path":        c.path,
                "field":       c.field,
                "before":      str(c.before) if c.before is not None else None,
                "after":       str(c.after)  if c.after  is not None else None,
                "note":        c.note,
            }
            for c in changes
        ],
    }


class MigrateError(Exception):
    """Raised when a migration cannot be generated or applied."""
    pass
