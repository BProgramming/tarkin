"""Removes a Tarkin model from a live database."""
from __future__ import annotations
from sqlalchemy import text

from .credentials import ConnectionProfile
from .inspect import inspect_database
from .model import GovernanceProject


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
        tarkin_created_roles, revoked_grants, db_name, pgcrypto_enabled_by_tarkin, pgaudit_snapshot = _read_meta(profile)
    except Exception as exc:
        if not no_restore_grants:
            raise DetachError(
                f"Failed to read __META__, and cannot restore grants safely.\n"
                f"Error: {exc}\n"
                f"Use --no-restore-grants to detach without restoring grants."
            ) from exc
        print(f"\nWarning: could not read __META__ ({exc}). Proceeding without grant restoration.")
        tarkin_created_roles = []
        revoked_grants = []
        db_name = profile.database
        pgcrypto_enabled_by_tarkin = False
        pgaudit_snapshot = {}
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
    )
    print("Generating rollback SQL... Done.")

    print("Removing Tarkin model from database...", end="\r")
    try:
        engine = profile.engine()
        raw    = engine.raw_connection()
        try:
            setattr(raw, "autocommit", True)
            raw.execute(sql)
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


def _read_meta(profile: ConnectionProfile) -> tuple[list[str], list[tuple[str, str, str | None, str]], str, bool, dict[str, str | None]]:
    """Read __META__ tables to retrieve roles, grants, and extension state."""
    engine = profile.engine()
    try:
        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT build_id, database_name, "
                "pgcrypto_enabled_by_tarkin, "
                "pgaudit_log_before, pgaudit_log_catalog_before, pgaudit_log_relation_before "
                "FROM __META__.tarkin_builds "
                "ORDER BY built_at DESC LIMIT 1"
            )).fetchone()
            if not row:
                return [], [], profile.database, False, {}

            build_id                    = row[0]
            db_name                     = row[1]
            pgcrypto_enabled_by_tarkin  = bool(row[2])
            pgaudit_snapshot = {
                "pgaudit_log":          row[3],
                "pgaudit_log_catalog":  row[4],
                "pgaudit_log_relation": row[5],
            }

            role_rows = conn.execute(text(
                "SELECT name FROM __META__.tarkin_roles "
                "WHERE build_id = :bid AND added_by_tarkin = true"
            ), {"bid": build_id}).fetchall()
            tarkin_roles = [r[0] for r in role_rows]

            grant_rows = conn.execute(text(
                "SELECT role_name, schema_name, table_name, grant_type "
                "FROM __META__.tarkin_revoked_grants "
                "WHERE build_id = :bid "
                "ORDER BY schema_name, table_name NULLS FIRST, role_name, grant_type"
            ), {"bid": build_id}).fetchall()
            grants = [(r[0], r[1], r[2], r[3]) for r in grant_rows]

            return tarkin_roles, grants, db_name, pgcrypto_enabled_by_tarkin, pgaudit_snapshot
    finally:
        engine.dispose()


def _confirm_drop_versioning(versioned_tables: list) -> None:
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
    current:              GovernanceProject,
    drop_versioning:      bool,
    tarkin_created_roles: list[str],
    revoked_grants:       list[tuple[str, str, str | None, str]],
    db_name:              str,
    pgaudit_snapshot:     dict[str, str | None],
) -> str:
    """Generate the full rollback SQL for a detach operation.

    The SQL is wrapped in a single ``BEGIN``/``COMMIT`` transaction.  Operations
    are ordered so that:

    1. Triggers and views are removed first.
    2. Versioning columns are dropped if requested.
    3. Revoked grants are restored (schema-level first, then table-level).
    4. Shadow schemas are renamed back to their original names.
    5. ``__META__`` is dropped.
    6. Tarkin-created roles are dropped last (after all privilege dependencies
       are resolved).
    7. pgaudit settings are restored to their pre-attach values.
    8. The ``tarkin.hmac_key`` GUC is reset.

    Args:
        current:              Inspected current state of the database.
        drop_versioning:      Whether to drop versioning columns.
        tarkin_created_roles: Role names to drop (created by Tarkin).
        revoked_grants:       Grants to restore in (role, schema, table, type) form.
        db_name:              The database name for ALTER DATABASE statements.
        pgaudit_snapshot:     Pre-attach pgaudit settings to restore.

    Returns:
        The complete SQL string ready for execution.
    """
    tk_schemas = [s for s in current.schemas if s.name.startswith("tk_")]
    dq = lambda name: f'"{name}"'

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
                f'DROP TRIGGER IF EXISTS "tr_{table.name}" '
                f'ON {dq(original_name)}.{dq(table.name)};'
            )
            lines.append(
                f'DROP FUNCTION IF EXISTS {dq(shadow)}."tr_{table.name}"();'
            )

        for table in schema.tables:
            versioned = (
                "__valid_from__" in {c.name for c in table.columns}
                and "__valid_to__" in {c.name for c in table.columns}
            )
            lines.append(f'DROP VIEW IF EXISTS {dq(original_name)}.{dq(table.name)};')
            if versioned:
                lines.append(
                    f'DROP VIEW IF EXISTS {dq(original_name)}.{dq(table.name + "_current")};'
                )

        if drop_versioning:
            for table in schema.tables:
                versioned = (
                    "__valid_from__" in {c.name for c in table.columns}
                    and "__valid_to__" in {c.name for c in table.columns}
                )
                if versioned:
                    lines.append(
                        f'DELETE FROM {dq(shadow)}.{dq(table.name)} '
                        f"WHERE __valid_to__ != 'infinity'::timestamptz;"
                    )
                    lines.append(
                        f'DROP INDEX IF EXISTS "idx_{table.name}_current";'
                    )
                    lines.append(
                        f'ALTER TABLE {dq(shadow)}.{dq(table.name)} '
                        f"DROP COLUMN __valid_from__;"
                    )
                    lines.append(
                        f'ALTER TABLE {dq(shadow)}.{dq(table.name)} '
                        f"DROP COLUMN __valid_to__;"
                    )

        lines.append(f'DROP SCHEMA {dq(original_name)} CASCADE;')
        lines.append(f'ALTER SCHEMA {dq(shadow)} RENAME TO {dq(original_name)};')
        lines.append("")

    schema_grants = [(r, s, gt) for (r, s, t, gt) in revoked_grants if t is None]
    table_grants  = [(r, s, t, gt) for (r, s, t, gt) in revoked_grants if t is not None]

    if schema_grants or table_grants:
        lines.append("-- Restore grants revoked by Tarkin")

    for (role_name, schema_name, grant_type) in schema_grants:
        lines.append(
            f'GRANT {grant_type} ON SCHEMA {dq(schema_name)} TO {dq(role_name)};'
        )

    for (role_name, schema_name, table_name, grant_type) in table_grants:
        lines.append(
            f'GRANT {grant_type} ON {dq(schema_name)}.{dq(table_name)} TO {dq(role_name)};'
        )

    if schema_grants or table_grants:
        lines.append("")

    lines += [
        "DROP SCHEMA IF EXISTS __META__ CASCADE;",
        "",
    ]

    if tarkin_created_roles:
        lines.append("-- Drop roles created by Tarkin")
        for role_name in tarkin_created_roles:
            lines.append(f'DROP ROLE IF EXISTS {dq(role_name)};')
        lines.append("")

    pgaudit_log          = pgaudit_snapshot.get("pgaudit_log")
    pgaudit_log_catalog  = pgaudit_snapshot.get("pgaudit_log_catalog")
    pgaudit_log_relation = pgaudit_snapshot.get("pgaudit_log_relation")

    lines.append("-- Restore pgaudit settings to pre-attach values")
    if pgaudit_log is not None:
        lines.append(
            f'ALTER DATABASE {dq(db_name)} SET pgaudit.log = \'{pgaudit_log}\';'
            if pgaudit_log
            else f'ALTER DATABASE {dq(db_name)} RESET pgaudit.log;'
        )
    if pgaudit_log_catalog is not None:
        lines.append(
            f'ALTER DATABASE {dq(db_name)} SET pgaudit.log_catalog = \'{pgaudit_log_catalog}\';'
            if pgaudit_log_catalog
            else f'ALTER DATABASE {dq(db_name)} RESET pgaudit.log_catalog;'
        )
    if pgaudit_log_relation is not None:
        lines.append(
            f'ALTER DATABASE {dq(db_name)} SET pgaudit.log_relation = \'{pgaudit_log_relation}\';'
            if pgaudit_log_relation
            else f'ALTER DATABASE {dq(db_name)} RESET pgaudit.log_relation;'
        )
    lines.append("")

    lines += [
        f'-- Reset tarkin.hmac_key GUC',
        f'ALTER DATABASE {dq(db_name)} RESET tarkin.hmac_key;',
        "",
        "COMMIT;",
    ]

    return "\n".join(lines)


class DetachError(Exception):
    """Raised when a detach operation cannot be completed."""
    pass
