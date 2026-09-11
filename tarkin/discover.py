"""Governed metadata discovery for Tarkin-attached databases."""
from __future__ import annotations

import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import text

from .credentials import ConnectionProfile
from .utils import build_output_directory


class DiscoverError(Exception):
    """Raised when a discovery operation fails."""


# object name -> (function name, ordered parameter names)
OBJECTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "build":          ("get_build",          ()),
    "schemas":        ("get_schemas",        ()),
    "tables":         ("get_tables",         ("schema",)),
    "columns":        ("get_columns",        ("schema", "table")),
    "roles":          ("get_roles",          ()),
    "retention":      ("get_retention",      ("schema", "table")),
    "erasures":       ("get_erasures",       ("since",)),
    "erasure_counts": ("get_erasure_counts", ("since",)),
    "rls":            ("get_rls_policies",   ("schema", "table")),
}

_PARAM_TYPES: dict[str, str] = {
    "schema": "text",
    "table":  "text",
    "since":  "timestamptz",
}


def _call(conn, fn: str, param_names: tuple[str, ...], values: dict[str, Any]) -> Any:
    """Call one __META__ discovery function and return its parsed JSON payload."""
    if param_names:
        args  = ", ".join(f"CAST(:{p} AS {_PARAM_TYPES[p]})" for p in param_names)
        bound = {p: values.get(p) for p in param_names}
    else:
        args  = ""
        bound = {}

    row = conn.execute(text(f"SELECT __META__.{fn}({args})"), bound).fetchone()
    return row[0] if row and row[0] is not None else None


def discover(
    profile:          ConnectionProfile,
    objects:          list[str],
    schema:           Optional[str]  = None,
    table:            Optional[str]  = None,
    since:            Optional[str]  = None,
    output_directory: Optional[Path] = None,
) -> tuple[dict[str, Any], Optional[Path]]:
    """Call the requested discovery functions.

    Returns the results keyed by object name, and the path written to when
    output_directory was supplied.
    """
    unknown = [o for o in objects if o not in OBJECTS]
    if unknown:
        raise DiscoverError(
            f"Unknown object(s): {', '.join(unknown)}. "
            f"Valid objects: {', '.join(OBJECTS)}."
        )

    values = {"schema": schema, "table": table, "since": since}
    engine = profile.engine()

    try:
        with engine.connect() as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            try:
                results = {
                    name: _call(conn, *OBJECTS[name], values)
                    for name in objects
                }
            finally:
                # Every discovery function is STABLE, so nothing can write. The
                # rollback keeps this path identical to query._execute_read_only.
                conn.execute(text("ROLLBACK"))
    except DiscoverError:
        raise
    except Exception as exc:
        raise DiscoverError(f"Discovery failed: {exc}") from exc
    finally:
        engine.dispose()

    written: Optional[Path] = None
    if output_directory is not None:
        build_output_directory(output_directory)
        stamp   = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        written = output_directory / f"tarkin_discover_{stamp}.json"
        if written is not None:
            written.write_text(json.dumps(results, indent=2, default=str))

    return results, written
