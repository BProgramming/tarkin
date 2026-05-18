"""Removes a Tarkin model from a live database."""
from __future__ import annotations
from sqlalchemy import text

from .credentials import ConnectionProfile
from .inspect import inspect_database
from .model import (
    GovernanceProject,
    SchemaConfig,
    TableConfig,
)
from .utils import sql_safe_double_quote


def detach(
    profile:           ConnectionProfile,
    keep_versioning:   bool = False,
    drop_versioning:   bool = False,
    no_warn:           bool = False,
    no_restore_grants: bool = False,
) -> None:
    """Remove a Tarkin governance model from a live database."""
    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile, include_tk=True)
    except Exception as exc:
        raise DetachError(f"Failed to inspect database: {exc}") from exc
    print("Inspecting current database state... Done.")

    tk_schemas = [s for s in current.schemas if s.name.startswith("tk_")]
    if not tk_schemas:
        raise DetachError(
            "No Tarkin shadow schemas found. "
            "The database does not appear to have a Tarkin build applied."
        )

    print("Assessing versioning...", end="\r")
    versioned_tables = [
        (s, t)
        for s in tk_schemas
        for t in s.tables
        if "__valid_from__" in {c.name for c in t.columns}
        and "__valid_to__" in {c.name for c in t.columns}
    ]
    has_versioning = bool(versioned_tables)
    print("Assessing versioning... Done.")

    print("Reading build metadata...", end="\r")
    try:
        (
            tarkin_created_roles,
            revoked_grants,
            db_name,
            pgcrypto_enabled_by_tarkin,
            pgaudit_snapshot,
            added_fks,
            added_generated_cols,
            moved_objects,
            subject_identifier_indexes,
            retention_tables,
        ) = _read_meta(profile)
    except Exception as exc:
        if not no_restore_grants:
            raise DetachError(
                f"Failed to read __META__, and cannot restore grants safely.\n"
                f"Error: {exc}\n"
                f"Use --no-restore-grants to detach without restoring grants."
            ) from exc
        print(f"\nWarning: could not read __META__ ({exc}). Proceeding without grant restoration.")
        tarkin_created_roles        = []
        revoked_grants              = []
        db_name                     = profile.database
        pgcrypto_enabled_by_tarkin  = False
        pgaudit_snapshot            = {}
        added_fks                   = []
        added_generated_cols        = []
        moved_objects               = []
        subject_identifier_indexes  = []
        retention_tables            = []
    print("Reading build metadata... Done.")

    if not has_versioning:
        if keep_versioning or drop_versioning:
            print(
                "Warning: versioning options specified but no versioned tables "
                "were found. Proceeding without versioning changes."
            )
    else:
        if not keep_versioning and not drop_versioning:
            raise DetachError(
                "Versioned tables were found but no versioning option was specified.\n"
                "Use --keep-versioning / -k to retain versioning columns and data, or\n"
                "     --drop-versioning / -d to remove them.\n"
                "Add --no-warn / -n to suppress confirmation when dropping."
            )
        if drop_versioning and not no_warn:
            _confirm_drop_versioning(versioned_tables)

    print("Generating rollback SQL...", end="\r")
    sql = _generate_detach_sql(
        current,
        drop_versioning,
        tarkin_created_roles,
        revoked_grants if not no_restore_grants else [],
        db_name,
        pgaudit_snapshot,
        added_fks,
        added_generated_cols,
        moved_objects,
        subject_identifier_indexes,
        retention_tables,
    )
    print("Generating rollback SQL... Done.")

    print("Removing Tarkin model from database...", end="\r")
    try:
        engine = profile.engine()
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor()
            cursor.execute(sql)
            raw.commit()
            cursor.close()
        finally:
            raw.close()
        engine.dispose()
    except Exception as exc:
        raise DetachError(
            f"Failed to detach. Database state may be inconsistent.\n"
            f"Error: {exc}"
        ) from exc
    print("Removing Tarkin model from database... Done.")

    print("Tarkin model successfully detached.")

    if pgcrypto_enabled_by_tarkin:
        print(
            "\nNote: Tarkin enabled the pgcrypto extension during attach. "
            "It has not been dropped automatically, as pgcrypto may be used by other "
            "objects in this database. If it is not otherwise in use, you can drop it with:\n"
            "    DROP EXTENSION IF EXISTS pgcrypto;"
        )


def _read_meta(
    profile: ConnectionProfile,
) -> tuple[
    list[str],
    list[tuple[str, str, str | None, str | None, str]],
    str,
    bool,
    dict[str, str | None],
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
    list[tuple[str, str, str, str]],
    list[tuple[str, str, list[str]]],
    list[tuple[str, str]],
]:
    """Read __META__ tables to retrieve all state needed for a clean detach."""
    engine = profile.engine()
    try:
        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT build_id,"
                "database_name, "
                "pgcrypto_enabled_by_tarkin, "
                "pgaudit_log_before,"
                "pgaudit_log_catalog_before,"
                "pgaudit_log_relation_before, "
                "pgaudit_role_before "
                "FROM __META__.tarkin_builds "
                "ORDER BY built_at DESC LIMIT 1"
            )).fetchone()
            if not row:
                return [], [], profile.database, False, {}, [], [], [], [], []

            build_id                    = row[0]
            db_name                     = row[1]
            pgcrypto_enabled_by_tarkin  = bool(row[2])
            pgaudit_snapshot = {
                "pgaudit_log":          row[3],
                "pgaudit_log_catalog":  row[4],
                "pgaudit_log_relation": row[5],
                "pgaudit_role":         row[6],
            }

            role_rows = conn.execute(text(
                "SELECT name FROM __META__.tarkin_roles "
                "WHERE build_id = :bid AND added_by_tarkin = true"
            ), {"bid": build_id}).fetchall()
            tarkin_roles = [r[0] for r in role_rows]

            grant_rows = conn.execute(text(
                "SELECT role_name, schema_name, table_name, column_name, grant_type "
                "FROM __META__.tarkin_revoked_grants "
                "WHERE build_id = :bid "
                "ORDER BY schema_name, table_name NULLS FIRST, role_name, grant_type"
            ), {"bid": build_id}).fetchall()
            grants = [(r[0], r[1], r[2], r[3], r[4]) for r in grant_rows]

            # Added FK constraints
            fk_rows = conn.execute(text(
                "SELECT shadow_schema, table_name, constraint_name "
                "FROM __META__.tarkin_added_fks "
                "WHERE build_id = :bid"
            ), {"bid": build_id}).fetchall()
            added_fks = [(r[0], r[1], r[2]) for r in fk_rows]

            # Added generated columns
            gen_col_rows = conn.execute(text(
                "SELECT shadow_schema, table_name, column_name "
                "FROM __META__.tarkin_added_generated_cols "
                "WHERE build_id = :bid"
            ), {"bid": build_id}).fetchall()
            added_generated_cols = [(r[0], r[1], r[2]) for r in gen_col_rows]

            # Moved schema objects
            obj_rows = conn.execute(text(
                "SELECT schema_name, shadow_name, object_kind, object_name "
                "FROM __META__.tarkin_moved_objects "
                "WHERE build_id = :bid"
            ), {"bid": build_id}).fetchall()
            moved_objects = [(r[0], r[1], r[2], r[3]) for r in obj_rows]

            # Subject identifier indexes (need explicit drops on detach)
            subj_rows = conn.execute(text(
                "SELECT shadow_schema, shadow_table, identifier_cols "
                "FROM __META__.tarkin_subject_identifiers "
                "WHERE build_id = :bid"
            ), {"bid": build_id}).fetchall()
            subject_identifier_indexes = [
                (r[0], r[1], list(r[2])) for r in subj_rows
            ]

            # Retention tables (need __expires_at__ and __erase_on_expiry__ dropped)
            ret_rows = conn.execute(text(
                "SELECT schema_name, table_name "
                "FROM __META__.tarkin_retention "
                "WHERE build_id = :bid"
            ), {"bid": build_id}).fetchall()
            retention_tables = [(r[0], r[1]) for r in ret_rows]

            return (
                tarkin_roles, grants, db_name, pgcrypto_enabled_by_tarkin,
                pgaudit_snapshot, added_fks, added_generated_cols, moved_objects,
                subject_identifier_indexes, retention_tables,
            )
    finally:
        engine.dispose()


def _confirm_drop_versioning(versioned_tables: list[tuple[SchemaConfig, TableConfig]]) -> None:
    """Prompt the user to confirm dropping versioning columns and history."""
    table_list = "\n".join(f"  {s.name}.{t.name}" for s, t in versioned_tables)
    print(
        f"\nThe following tables have versioning columns that will be permanently dropped:\n"
        f"{table_list}\n"
        f"Only current records (__valid_to__ = 'infinity') will be retained.\n"
        f"This operation cannot be undone."
    )
    response = input("Type 'y' to confirm: ").strip().casefold()
    if response != "y":
        raise DetachError("Detach cancelled by user.")


def _generate_detach_sql(
    current:                    GovernanceProject,
    drop_versioning:            bool,
    tarkin_created_roles:       list[str],
    revoked_grants:             list[tuple[str, str, str | None, str | None, str]],
    db_name:                    str,
    pgaudit_snapshot:           dict[str, str | None],
    added_fks:                  list[tuple[str, str, str]],
    added_generated_cols:       list[tuple[str, str, str]],
    moved_objects:              list[tuple[str, str, str, str]],
    subject_identifier_indexes: list[tuple[str, str, list[str]]],
    retention_tables:           list[tuple[str, str]],
) -> str:
    """
    Generate the full rollback SQL for a detach operation.

    Operations are ordered so that:

    1. Triggers and views are removed.
    2. Added FK constraints are dropped from shadow tables.
    3. Added generated columns are dropped from shadow tables.
    4. Subject identifier indexes are dropped from shadow tables.
    5. Versioning columns are dropped if requested.
    6. Revoked grants are restored (schema-level first, then table-level).
    7. Moved schema objects are moved back to shadow schemas.
    8. Tarkin-created roles are dropped.
    9. Shadow schemas are renamed back to their original names.
    10. __META__ is dropped.
    11. pgaudit settings are restored to their pre-attach values.
    12. The tarkin.hmac_key GUC is reset.
    """
    tk_schemas = [s for s in current.schemas if s.name.startswith("tk_")]

    lines = [
        "-- Tarkin detach",
        "BEGIN;",
        "",
    ]

    for schema in tk_schemas:
        original_name = schema.name[3:]  # strip tk_ prefix
        shadow        = schema.name

        for table in schema.tables:
            lines.append(
                f'DROP TRIGGER IF EXISTS {sql_safe_double_quote("tr_" + table.name)} '
                f'ON {sql_safe_double_quote(original_name)}.{sql_safe_double_quote(table.name)};'
            )
            lines.append(
                f'DROP FUNCTION IF EXISTS {sql_safe_double_quote(shadow)}.{sql_safe_double_quote("tr_" + table.name)}();'
            )

        for table in schema.tables:
            versioned = (
                "__valid_from__" in {c.name for c in table.columns}
                and "__valid_to__" in {c.name for c in table.columns}
            )
            lines.append(f'DROP VIEW IF EXISTS {sql_safe_double_quote(original_name)}.{sql_safe_double_quote(table.name)} CASCADE;')
            if versioned:
                lines.append(
                    f'DROP VIEW IF EXISTS {sql_safe_double_quote(original_name)}.{sql_safe_double_quote(table.name + "_current")} CASCADE;'
                )

        if drop_versioning:
            for table in schema.tables:
                versioned = (
                    "__valid_from__" in {c.name for c in table.columns}
                    and "__valid_to__" in {c.name for c in table.columns}
                )
                if versioned:
                    lines.append(
                        f'DELETE FROM {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} '
                        f"WHERE __valid_to__ != 'infinity'::timestamptz;"
                    )
                    lines.append(
                        f'DROP INDEX IF EXISTS {sql_safe_double_quote("idx_" + table.name + "_current")};'
                    )
                    lines.append(
                        f'ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} '
                        f"DROP COLUMN __valid_from__;"
                    )
                    lines.append(
                        f'ALTER TABLE {sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table.name)} '
                        f"DROP COLUMN __valid_to__;"
                    )

        lines.append("")

    if added_fks:
        lines.append("-- Drop FK constraints added by Tarkin")
        for (shadow_schema, table_name, constraint_name) in added_fks:
            lines.append(
                f'ALTER TABLE {sql_safe_double_quote(shadow_schema)}.{sql_safe_double_quote(table_name)} '
                f'DROP CONSTRAINT IF EXISTS {sql_safe_double_quote(constraint_name)};'
            )
        lines.append("")

    if added_generated_cols:
        lines.append("-- Drop generated columns added by Tarkin")
        for (shadow_schema, table_name, column_name) in added_generated_cols:
            lines.append(
                f'ALTER TABLE {sql_safe_double_quote(shadow_schema)}.{sql_safe_double_quote(table_name)} '
                f'DROP COLUMN IF EXISTS {sql_safe_double_quote(column_name)};'
            )
        lines.append("")

    if subject_identifier_indexes:
        lines.append("-- Drop subject identifier indexes added by Tarkin")
        for (shadow_schema, table_name, col_names) in subject_identifier_indexes:
            for col_name in col_names:
                idx_name = sql_safe_double_quote(f"tarkin_subject_{table_name}_{col_name}")
                lines.append(f'DROP INDEX IF EXISTS {sql_safe_double_quote(shadow_schema)}.{idx_name};')
        lines.append("")

    if retention_tables:
        lines.append("-- Unschedule pg_cron retention job (if pg_cron is installed)")
        lines += [
            "DO $$",
            "BEGIN",
            f"    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN",
            f"        PERFORM cron.unschedule(jobname)",
            f"        FROM cron.job",
            f"        WHERE jobname LIKE 'tarkin_retention_%';",
            "    END IF;",
            "END;",
            "$$ LANGUAGE plpgsql;",
            "",
        ]
        lines.append("-- Drop retention columns added by Tarkin")
        for (schema_name, table_name) in retention_tables:
            shadow = f"tk_{schema_name}"
            tbl_ref = f'{sql_safe_double_quote(shadow)}.{sql_safe_double_quote(table_name)}'
            lines.append(f'DROP INDEX IF EXISTS {sql_safe_double_quote(shadow)}.{sql_safe_double_quote("idx_" + table_name + "_expires_at")};')
            lines.append(f'ALTER TABLE {tbl_ref} DROP COLUMN IF EXISTS __expires_at__;')
            lines.append(f'ALTER TABLE {tbl_ref} DROP COLUMN IF EXISTS __erase_on_expiry__;')
        lines.append("")

    if moved_objects:
        lines.append("-- Move schema objects back to shadow schemas")
        _alter_map = {
            "sequence":          "ALTER SEQUENCE",
            "function":          "ALTER FUNCTION",
            "trigger_function":  "ALTER FUNCTION",
            "procedure":         "ALTER PROCEDURE",
            "type":              "ALTER TYPE",
            "domain":            "ALTER DOMAIN",
            "collation":         "ALTER COLLATION",
            "view":              "ALTER VIEW",
            "materialized_view": "ALTER MATERIALIZED VIEW",
            "foreign_table":     "ALTER FOREIGN TABLE",
        }
        for (schema_name, shadow_name, object_kind, object_name) in moved_objects:
            if object_kind == "operator":
                lines.append(f'ALTER OPERATOR {sql_safe_double_quote(schema_name)}.{object_name} SET SCHEMA {sql_safe_double_quote(shadow_name)};')
            else:
                alter_cmd = _alter_map.get(object_kind, "ALTER")
                lines.append(f'{alter_cmd} {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(object_name)} SET SCHEMA {sql_safe_double_quote(shadow_name)};')
        lines.append("")

    if tarkin_created_roles:
        lines.append("-- Drop roles created by Tarkin")
        for role_name in tarkin_created_roles:
            for schema in tk_schemas:
                for table in schema.tables:
                    lines.append(f'REVOKE ALL ON {sql_safe_double_quote(schema.name)}.{sql_safe_double_quote(table.name)} FROM {sql_safe_double_quote(role_name)};')
            lines.append(f'REASSIGN OWNED BY {sql_safe_double_quote(role_name)} TO CURRENT_USER;')
            lines.append(f'DROP OWNED BY {sql_safe_double_quote(role_name)};')
            lines.append(f'DROP ROLE IF EXISTS {sql_safe_double_quote(role_name)};')
        lines.append("")

    for schema in tk_schemas:
        original_name = schema.name[3:]
        shadow        = schema.name
        lines.append(f'DROP SCHEMA {sql_safe_double_quote(original_name)} CASCADE;')
        lines.append(f'ALTER SCHEMA {sql_safe_double_quote(shadow)} RENAME TO {sql_safe_double_quote(original_name)};')
        lines.append("")

    original_schema_names = [s.name[3:] for s in tk_schemas]
    schema_array = "ARRAY[" + ", ".join(f"'{n}'" for n in original_schema_names) + "]"
    lines += [
        "-- Drop tarkin_rls_* policies and disable RLS on restored tables",
        "DO $$",
        "DECLARE",
        "    r record;",
        "BEGIN",
        "    FOR r IN",
        "        SELECT schemaname, tablename, policyname",
        "        FROM pg_policies",
        f"        WHERE policyname LIKE 'tarkin_rls_%'",
        f"          AND schemaname = ANY({schema_array})",
        "    LOOP",
        "        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',",
        "            r.policyname, r.schemaname, r.tablename);",
        "        EXECUTE format('ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY',",
        "            r.schemaname, r.tablename);",
        "        EXECUTE format('ALTER TABLE %I.%I NO FORCE ROW LEVEL SECURITY',",
        "            r.schemaname, r.tablename);",
        "    END LOOP;",
        "END;",
        "$$ LANGUAGE plpgsql;",
        "",
    ]

    schema_grants = [(r, s, gt) for (r, s, t, c, gt) in revoked_grants if t is None]
    table_grants = [(r, s, t, gt) for (r, s, t, c, gt) in revoked_grants if t is not None and c is None]
    column_grants = [(r, s, t, c, gt) for (r, s, t, c, gt) in revoked_grants if t is not None and c is not None]

    if schema_grants or table_grants or column_grants:
        lines.append("-- Restore grants revoked by Tarkin")

        for (role_name, schema_name, grant_type) in schema_grants:
            if schema_name:
                lines.append(f'GRANT {grant_type} ON SCHEMA {sql_safe_double_quote(schema_name)} TO {sql_safe_double_quote(role_name)};')

        for (role_name, schema_name, table_name, grant_type) in table_grants:
            if schema_name and table_name:
                lines.append(f'GRANT {grant_type} ON {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(table_name)} TO {sql_safe_double_quote(role_name)};')

        for (role_name, schema_name, table_name, column_name, grant_type) in column_grants:
            if schema_name and table_name and column_name:
                lines.append(
                    f'GRANT {grant_type} ({sql_safe_double_quote(column_name)}) '
                    f'ON {sql_safe_double_quote(schema_name)}.{sql_safe_double_quote(table_name)} '
                    f'TO {sql_safe_double_quote(role_name)};'
                )

        lines.append("")

    lines += [
        "DROP SCHEMA IF EXISTS __META__ CASCADE;",
        "",
    ]

    pgaudit_log          = pgaudit_snapshot.get("pgaudit_log")
    pgaudit_log_catalog  = pgaudit_snapshot.get("pgaudit_log_catalog")
    pgaudit_log_relation = pgaudit_snapshot.get("pgaudit_log_relation")
    pgaudit_role         = pgaudit_snapshot.get("pgaudit_role")

    lines.append("-- Restore pgaudit settings to pre-attach values")
    if pgaudit_log is not None:
        lines.append(
            f'ALTER DATABASE {sql_safe_double_quote(db_name)} SET pgaudit.log = \'{pgaudit_log}\';'
            if pgaudit_log
            else f'ALTER DATABASE {sql_safe_double_quote(db_name)} RESET pgaudit.log;'
        )
    if pgaudit_log_catalog is not None:
        lines.append(
            f'ALTER DATABASE {sql_safe_double_quote(db_name)} SET pgaudit.log_catalog = \'{pgaudit_log_catalog}\';'
            if pgaudit_log_catalog
            else f'ALTER DATABASE {sql_safe_double_quote(db_name)} RESET pgaudit.log_catalog;'
        )
    if pgaudit_log_relation is not None:
        lines.append(
            f'ALTER DATABASE {sql_safe_double_quote(db_name)} SET pgaudit.log_relation = \'{pgaudit_log_relation}\';'
            if pgaudit_log_relation
            else f'ALTER DATABASE {sql_safe_double_quote(db_name)} RESET pgaudit.log_relation;'
        )
    if pgaudit_role is not None:
        lines.append(
            f'ALTER DATABASE {sql_safe_double_quote(db_name)} SET pgaudit.role = \'{pgaudit_role}\';'
            if pgaudit_role
            else f'ALTER DATABASE {sql_safe_double_quote(db_name)} RESET pgaudit.role;'
        )
    lines.append("")

    lines += [
        "-- Reset tarkin.hmac_key GUC",
        f'ALTER DATABASE {sql_safe_double_quote(db_name)} RESET tarkin.hmac_key;',
        "",
        "COMMIT;",
    ]

    return "\n".join(lines)


class DetachError(Exception):
    """Raised when a detach operation cannot be completed."""
    pass
