"""Idempotent schema patches applied by the 'tarkin update' command."""
from __future__ import annotations

from sqlalchemy import text

from .credentials import ConnectionProfile


class UpdateError(Exception):
    """Raised when an update patch fails."""


PATCHES: list[tuple[str, str]] = [
    # (description, sql)
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
]


def update(profile: ConnectionProfile) -> list[str]:
    """Apply all patches idempotently. Returns a list of applied patch descriptions."""
    applied: list[str] = []

    try:
        engine = profile.engine()
        with engine.begin() as conn:  # begin() auto-commits on success
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
