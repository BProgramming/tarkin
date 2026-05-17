"""Runtime erasure commands for Tarkin data subjects."""
from __future__ import annotations
import json
from datetime import datetime, UTC
from pathlib import Path
from sqlalchemy import text

from .credentials import ConnectionProfile


def erase_check(
    profile: ConnectionProfile,
    columns: list[str],
    values:  list[str],
    out_dir: Path | None = None,
) -> list[dict]:
    """Call __META__.tarkin_erase_check() and return (and optionally write) the result."""
    if len(columns) != len(values):
        raise EraseError("unequal number of columns and values provided. Please specify an equal amount of each.")
    results = _call_function(profile, "tarkin_erase_check", columns, values)
    if out_dir is not None:
        _write_result(out_dir, "erase_check", columns, values, results)
    return results


def erase_apply(
    profile: ConnectionProfile,
    columns: list[str],
    values:  list[str],
    out_dir: Path | None = None,
) -> list[dict]:
    """Call __META__.tarkin_erase_apply() and return (and optionally write) the result."""
    if len(columns) != len(values):
        raise EraseError("unequal number of columns and values provided. Please specify an equal amount of each.")
    results = _call_function(profile, "tarkin_erase_apply", columns, values)
    if out_dir is not None:
        _write_result(out_dir, "erase_apply", columns, values, results)
    return results


def _call_function(
    profile:       ConnectionProfile,
    function_name: str,
    columns:       list[str],
    values:        list[str],
) -> list[dict]:
    """Execute a __META__ erase function and return rows as dicts."""
    engine = profile.engine()
    try:
        with engine.connect() as conn:
            try:
                rows = conn.execute(
                    text(f"SELECT * FROM __META__.{function_name}(:cols, :vals)"),
                    {"cols": columns, "vals": values},
                ).fetchall()
            except Exception as exc:
                if "__META__" in str(exc) or "tarkin_erase" in str(exc):
                    raise EraseError(
                        f"Could not call __META__.{function_name}. "
                        f"Is there an active Tarkin build on this database? "
                        f"Run 'tarkin attach' first.\n"
                        f"Detail: {exc}"
                    ) from exc
                raise EraseError(str(exc)) from exc
        return [dict(row._mapping) for row in rows]
    finally:
        engine.dispose()


def _write_result(
    out_dir:   Path,
    operation: str,
    columns:   list[str],
    values:    list[str],
    results:   list[dict],
) -> Path:
    """Write erasure results to a timestamped JSON file in out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y_%m_%d_%H_%M_%S")
    path      = out_dir / f"tarkin_{operation}_{timestamp}.json"
    payload   = {
        "operation":   operation,
        "executed_at": datetime.now(UTC).isoformat(),
        "columns":     columns,
        "values":      values,
        "results":     results,
    }
    path.write_text(json.dumps(payload, indent=2, default=str))
    return path


class EraseError(Exception):
    """Raised when an erasure operation cannot be completed."""
    pass
