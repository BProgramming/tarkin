"""Build a Tarkin model from a GovernanceProject."""
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


OUT_DIR = Path("out")


def _ensure_out_dir(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def build(project: GovernanceProject, profile: ConnectionProfile, out_dir: Path | None = None) -> Path:
    """Run a full Tarkin build against a live database."""
    out = _ensure_out_dir(out_dir or OUT_DIR)

    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile)
    except Exception as exc:
        raise BuildError(f"Failed to inspect database: {exc}") from exc
    print("Inspecting current database state... Done.")

    print("Checking requirements...", end="\r")
    _check_no_existing_build(current)
    _check_pgaudit_requirements(project, current)
    print("Checking requirements... Done.")

    print("Generating SQL...", end="\r")
    sql = generate_sql(project, current, profile)
    print("Generating SQL... Done.")

    print("Building artifact...", end="\r")
    timestamp = datetime.now(UTC).strftime("%Y_%m_%d_%H_%M_%S")
    zip_path  = out / f"tarkin_build_{timestamp}.zip"
    metadata = _build_metadata(project, current, profile)
    _write_artifact(zip_path, sql, metadata)
    print(f"Building artifact... Written to {zip_path}.")

    return zip_path


def _check_no_existing_build(current: GovernanceProject) -> None:
    """Check if there are no existing build artifacts."""
    tk_schemas = [s for s in current.schemas if s.name.casefold().startswith("tk_")]
    if tk_schemas:
        names = ", ".join(s.name for s in tk_schemas)
        raise BuildError(
            f"Existing Tarkin shadow schemas detected: {names}. "
            f"Run 'tarkin detach' to remove the existing build before building again."
        )


def _check_pgaudit_requirements(project: GovernanceProject, current: GovernanceProject) -> None:
    """Fail if the YAML requires pgaudit but the live database doesn't have pgaudit preloaded."""
    if project.database.audit_enabled and not current.database.audit_enabled:
        raise BuildError(
            "The governance YAML requires audit_enabled=true, but pgaudit is not "
            "installed or not preloaded on this database.\n"
            "Install postgresql-pgaudit, add 'pgaudit' to shared_preload_libraries "
            "in postgresql.conf, and restart PostgreSQL before building."
        )


def _build_metadata(project: GovernanceProject, current: GovernanceProject, profile: ConnectionProfile) -> dict:
    """Build a metadata dict for a GovernanceProject."""
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


def _write_artifact(zip_path: Path, sql: str, metadata: dict) -> None:
    """Write an artifact to a zip file."""
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("tarkin_build.json", json.dumps(metadata, indent=2))
        zf.writestr("tarkin_build.sql",  sql)


class BuildError(Exception):
    pass
