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

def build(project: GovernanceProject, profile: ConnectionProfile, out_dir: Path | None = None) -> Path:
    """
    Run a full Tarkin build against a live database.

    1. Re-inspect the live database to capture current state
    2. Verify no tk_ schemas exist (would indicate a prior build)
    3. Verify pgaudit is available if audit_enabled=True
    4. Generate SQL
    5. Write build artifact (zip containing JSON metadata + SQL)
    6. Return path to the zip

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

    # Step 3 — check pgaudit if required
    _check_pgaudit_requirements(project, current)
    _check_pgcrypto_requirements(project, current)

    # Step 4 — generate SQL
    print("Generating SQL...", end="\r")
    sql = generate_sql(project, current, profile)
    print("Generating SQL... Done.")

    # Step 5 — write artifact
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
    tk_schemas = [s for s in current.schemas if s.name.casefold().startswith("tk_")]
    if tk_schemas:
        names = ", ".join(s.name for s in tk_schemas)
        raise BuildError(
            f"Existing Tarkin shadow schemas detected: {names}. "
            f"Run 'tarkin detach' to remove the existing build before building again."
        )


def _check_pgaudit_requirements(project: GovernanceProject, current: GovernanceProject) -> None:
    """Fail if the YAML requires audit but the live database doesn't have pgaudit preloaded."""
    if project.database.audit_enabled and not current.database.audit_enabled:
        raise BuildError(
            "The governance YAML requires audit_enabled=true, but pgaudit is not "
            "installed or not preloaded on this database.\n"
            "Install postgresql-pgaudit, add 'pgaudit' to shared_preload_libraries "
            "in postgresql.conf, and restart PostgreSQL before building."
        )


def _check_pgcrypto_requirements(project: GovernanceProject, current: GovernanceProject) -> None:
    from .model import HashMaskConfig, HashAlgorithm
    needs_pgcrypto = any(
        isinstance(col.mask_config, HashMaskConfig)
        and col.mask_config.algorithm in (HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.HMAC256)
        for schema in project.schemas
        for table in schema.tables
        for col in table.columns
    )
    if needs_pgcrypto and not current.database.encryption_enabled:
        raise BuildError(
            "One or more columns use SHA/HMAC hashing, but pgcrypto is not installed on this database.\n"
            "Run: CREATE EXTENSION pgcrypto;\n"
            "Then re-run 'tarkin build'."
        )


# =========================================================
# METADATA
# =========================================================

def _build_metadata(project: GovernanceProject, current: GovernanceProject, profile: ConnectionProfile) -> dict:
    return {
        "tarkin_version": pkg_version("tarkin"),
        "built_at":       datetime.now(UTC).isoformat(),
        "profile":        profile.profile,
        "database":       profile.database,
        "host":           profile.host,
        "port":           profile.port,
        "yaml_checksum":  _project_checksum(project),
        "db_checksum":    _project_checksum(current),
        "schemas":        [s.name for s in project.schemas],
        "shadow_schemas": [f"tk_{s.name}" for s in project.schemas],
        "audit_enabled":  project.database.audit_enabled,
        "audit_logged":   [str(level) for level in project.database.audit_logged],
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
