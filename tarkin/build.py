from __future__ import annotations
import json
import zipfile
from datetime import datetime, UTC
from importlib.metadata import version as pkg_version
from pathlib import Path

from .credentials import ConnectionProfile
from .inspect import inspect_database
from .model import GovernanceProject
from .codegen import generate_sql, _project_checksum


# =========================================================
# OUTPUT DIRECTORY
# =========================================================

OUT_DIR = Path("out")


def _ensure_out_dir(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


# =========================================================
# BUILD ENTRY POINT
# =========================================================

def build(
    project: GovernanceProject,
    profile: ConnectionProfile,
    out_dir: Path | None = None,
) -> Path:
    """
    Run a full Tarkin build against a live database.

    1. Re-inspect the live database to capture current state
    2. Verify no tk_ schemas exist (would indicate a prior build)
    3. Generate SQL
    4. Write build artifact (zip containing JSON metadata + SQL)
    5. Return path to the zip

    Raises BuildError on any failure.
    """
    out = _ensure_out_dir(out_dir or OUT_DIR)

    # Step 1 — re-inspect current state
    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile)
    except Exception as exc:
        raise BuildError(f"Failed to inspect database: {exc}") from exc
    print("Inspecting current database state... Done.")

    # Step 2 — check for existing Tarkin build
    _check_no_existing_build(current)

    # Step 3 — generate SQL
    print("Generating SQL...", end="\r")
    sql = generate_sql(project, current)
    print("Generating SQL... Done.")

    # Step 4 — write artifact
    print("Building artifact...", end="\r")
    timestamp = datetime.now(UTC).strftime("%Y_%m_%d_%H_%M_%S")
    zip_path  = out / f"tarkin_build_{timestamp}.zip"

    metadata = _build_metadata(project, current, profile)
    _write_artifact(zip_path, sql, metadata)

    print(f"Building artifact... Written to {zip_path}.")
    return zip_path


# =========================================================
# VALIDATION
# =========================================================

def _check_no_existing_build(current: GovernanceProject) -> None:
    """Fail if any tk_ schemas exist — indicates a prior Tarkin build."""
    tk_schemas = [s for s in current.schemas if s.name.casefold().startswith("tk_")]
    if tk_schemas:
        names = ", ".join(s.name for s in tk_schemas)
        raise BuildError(
            f"Existing Tarkin shadow schemas detected: {names}. "
            f"Run 'tarkin detach' to remove the existing build before building again."
        )


# =========================================================
# METADATA
# =========================================================

def _build_metadata(
    project: GovernanceProject,
    current: GovernanceProject,
    profile: ConnectionProfile,
) -> dict:
    return {
        "tarkin_version":  pkg_version("tarkin"),
        "built_at":        datetime.now(UTC).isoformat(),
        "profile":         profile.profile,
        "database":        profile.database,
        "host":            profile.host,
        "port":            profile.port,
        "yaml_checksum":   _project_checksum(project),
        "db_checksum":     _project_checksum(current),
        "schemas":         [s.name for s in project.schemas],
        "shadow_schemas":  [f"tk_{s.name}" for s in project.schemas],
    }


# =========================================================
# ARTIFACT
# =========================================================

def _write_artifact(zip_path: Path, sql: str, metadata: dict) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("tarkin_build.json", json.dumps(metadata, indent=2))
        zf.writestr("tarkin_build.sql",  sql)


# =========================================================
# ERRORS
# =========================================================

class BuildError(Exception):
    pass
