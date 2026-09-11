"""Applies idempotent schema patches to the Tarkin installation.

Every patch in PATCHES must be safe to apply any number of times against any
database that has ever had Tarkin attached, including one already at the
current version. Patches converge the schema toward the definition the
installed Tarkin version expects - they do not track or detect prior
application.

In practice that means:
  - CREATE ... IF NOT EXISTS for schemas, tables, indexes, and columns
  - CREATE OR REPLACE for functions and views
  - DROP ... IF EXISTS for removals
  - GRANT / REVOKE, which are idempotent by nature

Patches that cannot meet this bar do not ship. There is no escape hatch: a
conditional patch would need state to condition on, and the moment that state
can disagree with the database, `tarkin update` stops being trustworthy.

Patches run in list order within a single transaction. Order matters where one
patch is a precondition for another — the __META__ tables must exist before
the discovery functions that read them can be created, because PostgreSQL
validates LANGUAGE sql function bodies at creation time.
"""
from __future__ import annotations

from sqlalchemy import text

from .codegen import _generate_discovery_functions, _generate_meta_schema
from .credentials import ConnectionProfile


class UpdateError(Exception):
    """Raised when an update patch fails."""


PATCHES: list[tuple[str, str]] = [
    # (description, sql)
    (
        "Ensure __META__ tables exist",
        _generate_meta_schema(),
    ),
    (
        "Add description column to tarkin_schemas",
        "ALTER TABLE __META__.tarkin_schemas ADD COLUMN IF NOT EXISTS description text;",
    ),
    (
        "Add description column to tarkin_tables",
        "ALTER TABLE __META__.tarkin_tables ADD COLUMN IF NOT EXISTS description text;",
    ),
    (
        "Add description column to tarkin_columns",
        "ALTER TABLE __META__.tarkin_columns ADD COLUMN IF NOT EXISTS description text;",
    ),
    (
        "Add description column to tarkin_roles",
        "ALTER TABLE __META__.tarkin_roles ADD COLUMN IF NOT EXISTS description text;",
    ),
    (
        "Refresh __META__ discovery functions",
        _generate_discovery_functions(),
    ),
]


def update(profile: ConnectionProfile) -> list[str]:
    """Apply all patches idempotently. Returns a list of applied patch descriptions."""
    applied: list[str] = []

    try:
        engine = profile.engine()
        with engine.begin() as conn:
            attached = conn.execute(text(
                "SELECT to_regclass('__META__.tarkin_builds') IS NOT NULL"
            )).scalar()
            if not attached:
                raise UpdateError(
                    "No Tarkin build found in this database. 'tarkin update' converges "
                    "an attached database on the installed version's schema; it does not "
                    "create one. Run 'tarkin build' and 'tarkin attach' first."
                )

            for description, sql in PATCHES:
                try:
                    conn.execute(text(sql))
                    applied.append(description)
                except Exception as exc:
                    raise UpdateError(f"Patch failed: {description!r}: {exc}") from exc
        engine.dispose()
    except UpdateError:
        raise
    except Exception as exc:
        raise UpdateError(f"Failed to connect or execute patches: {exc}") from exc

    return applied
