from __future__ import annotations

from .credentials import ConnectionProfile
from .inspect import inspect_database


# =========================================================
# DETACH ENTRY POINT
# =========================================================

def detach(
    profile: ConnectionProfile,
    keep_versioning: bool = False,
    drop_versioning: bool = False,
    no_warn: bool = False,
) -> None:
    """
    Remove a Tarkin model from a live database.

    1. Inspect current state to find tk_ schemas and versioned tables
    2. Validate versioning options
    3. Generate and execute rollback SQL
    """

    # Step 1 — inspect current state
    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile, include_tk=True)
    except Exception as exc:
        raise DetachError(f"Failed to inspect database: {exc}") from exc
    print("Inspecting current database state... Done.")

    # Find tk_ schemas
    tk_schemas = [s for s in current.schemas if s.name.startswith("tk_")]
    if not tk_schemas:
        raise DetachError(
            "No Tarkin shadow schemas found. "
            "The database does not appear to have a Tarkin build applied."
        )

    # Find versioned tables
    versioned_tables = [
        (s, t)
        for s in tk_schemas
        for t in s.tables
        if "valid_from" in {c.name for c in t.columns}
        and "valid_to" in {c.name for c in t.columns}
    ]
    has_versioning = bool(versioned_tables)

    # Step 2 — validate versioning options
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

    # Step 3 — generate and execute rollback SQL
    print("Generating rollback SQL...", end="\r")
    sql = _generate_detach_sql(current, drop_versioning)
    print("Generating rollback SQL... Done.")

    print("Removing Tarkin model from database...", end="\r")
    try:
        engine = profile.engine()
        with engine.connect() as conn:
            conn.connection.execute(sql)
        engine.dispose()
    except Exception as exc:
        raise DetachError(
            f"Failed to detach — database has been rolled back.\n"
            f"Error: {exc}"
        ) from exc
    print("Removing Tarkin model from database... Done.")

    print("Tarkin model successfully detached.")


# =========================================================
# CONFIRMATION
# =========================================================

def _confirm_drop_versioning(versioned_tables: list) -> None:
    table_list = "\n".join(
        f"  {s.name}.{t.name}" for s, t in versioned_tables
    )
    print(
        f"\nThe following tables have versioning columns that will be permanently dropped:\n"
        f"{table_list}\n"
        f"Only current records (valid_to = 'infinity') will be retained.\n"
        f"This operation cannot be undone."
    )
    response = input("Type 'y' to confirm: ").strip().casefold()
    if response != "y":
        raise DetachError("Detach cancelled by user.")


# =========================================================
# SQL GENERATION
# =========================================================

def _generate_detach_sql(current, drop_versioning: bool) -> str:
    tk_schemas = [s for s in current.schemas if s.name.startswith("tk_")]
    lines = [
        "-- Tarkin detach",
        "BEGIN;",
        "",
    ]

    for schema in tk_schemas:
        original_name = schema.name[3:]  # strip tk_ prefix
        shadow        = schema.name

        # Drop triggers and trigger functions on views
        for table in schema.tables:
            lines.append(
                f'DROP TRIGGER IF EXISTS "tr_{table.name}" '
                f'ON "{original_name}"."{table.name}";'
            )
            lines.append(
                f'DROP FUNCTION IF EXISTS "{shadow}"."tr_{table.name}"();'
            )

        # Drop views in original schema
        for table in schema.tables:
            versioned = (
                "valid_from" in {c.name for c in table.columns}
                and "valid_to" in {c.name for c in table.columns}
            )
            lines.append(
                f'DROP VIEW IF EXISTS "{original_name}"."{table.name}";'
            )
            if versioned:
                lines.append(
                    f'DROP VIEW IF EXISTS "{original_name}"."{table.name}_current";'
                )

        # Drop versioning columns if requested
        if drop_versioning:
            for table in schema.tables:
                versioned = (
                    "valid_from" in {c.name for c in table.columns}
                    and "valid_to" in {c.name for c in table.columns}
                )
                if versioned:
                    # Retain only current records
                    lines.append(
                        f'DELETE FROM "{shadow}"."{table.name}" '
                        f"WHERE valid_to != 'infinity'::timestamptz;"
                    )
                    lines.append(
                        f'DROP INDEX IF EXISTS "idx_{table.name}_current";'
                    )
                    lines.append(
                        f'ALTER TABLE "{shadow}"."{table.name}" '
                        f"DROP COLUMN valid_from;"
                    )
                    lines.append(
                        f'ALTER TABLE "{shadow}"."{table.name}" '
                        f"DROP COLUMN valid_to;"
                    )

        # Drop original schema and rename shadow back
        lines.append(f'DROP SCHEMA "{original_name}";')
        lines.append(f'ALTER SCHEMA "{shadow}" RENAME TO "{original_name}";')
        lines.append("")

    # Drop __META__ schema
    lines += [
        "DROP SCHEMA __META__ CASCADE;",
        "",
        "COMMIT;",
    ]

    return "\n".join(lines)


# =========================================================
# ERRORS
# =========================================================

class DetachError(Exception):
    pass
