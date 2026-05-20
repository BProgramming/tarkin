"""Build a Tarkin model from a GovernanceProject."""
from __future__ import annotations
from datetime import datetime, UTC
from importlib.metadata import version as pkg_version
from pathlib import Path

from .codegen import generate_sql
from .credentials import ConnectionProfile, check_pgcron_available
from .inspect import inspect_database
from .model import GovernanceProject
from .utils import (
    OUT_DIR,
    build_output_directory,
    write_artifact,
)
from .serialize import project_checksum


def build(
    project: GovernanceProject,
    profile: ConnectionProfile,
    output_directory: Path | None = None,
) -> Path:
    """Run a full Tarkin build against a live database.

    *output_directory* is the directory the build artifact zip is written to
    (defaults to ``out/``). It is always treated as a directory.
    """
    out = build_output_directory(output_directory or OUT_DIR)

    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile)
    except Exception as exc:
        raise BuildError(f"Failed to inspect database: {exc}") from exc
    print("Inspecting current database state... Done.")

    print("Checking requirements...", end="\r")
    _check_no_existing_build(current)
    _check_owner_defined(project)
    _check_pgaudit_requirements(project, current)
    _check_pgcron_requirements(project, profile)
    print("Checking requirements... Done.")

    print("Generating SQL...", end="\r")
    sql = generate_sql(project, current, profile)
    print("Generating SQL... Done.")

    print("Building artifact...", end="\r")
    timestamp = datetime.now(UTC).strftime("%Y_%m_%d_%H_%M_%S")
    zip_path  = out / f"tarkin_build_{timestamp}.zip"
    metadata = _build_metadata(project, current, profile)
    write_artifact(zip_path, sql, metadata)
    print(f"Building artifact... Written to {zip_path}.")

    return zip_path


def _check_no_existing_build(current: GovernanceProject) -> None:
    """Check if there are no existing build artifacts."""
    tk_schemas = [s for s in current.schemas if s.name.casefold().startswith("tk_")]
    if tk_schemas:
        names = ", ".join(s.name for s in tk_schemas)
        raise BuildError(
            f"Existing Tarkin shadow schemas detected: {names}. "
            "Run 'tarkin detach' to remove the existing build before building again."
        )
    if current.database.audit_enabled and 'tarkin_audit' in {r.name for r in current.roles}:
        raise BuildError(
            "Tarkin uses the 'tarkin_audit' role to handle pgaudit operations, but a role with that name already exists. "
            "Please rename the existing role and try again."
        )


def _check_owner_defined(project: GovernanceProject) -> None:
    """Fail if no database owner is set."""
    if not project.database.owner:
        raise BuildError(
            "database.owner is not set. Tarkin revokes all shadow-schema access "
            "from PUBLIC and re-grants it only to the database owner, so a named "
            "owner role is required. Set 'owner' in the governance YAML "
            "(it is captured automatically by 'tarkin inspect')."
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


def _check_pgcron_requirements(project: GovernanceProject, profile: ConnectionProfile) -> None:
    """Fail if the YAML requires pg_cron but it is not installed on the live database."""
    has_retention = any(table.retention_days is not None for schema in project.schemas for table in schema.tables)
    if project.database.retention_schedule is not None or has_retention:
        if not check_pgcron_available(profile):
            raise BuildError(
                "Retention is configured but pg_cron is not installed or not preloaded "
                "on this database.\n"
                "Install pg_cron, add 'pg_cron' to shared_preload_libraries in "
                "postgresql.conf, and restart PostgreSQL before building.\n"
                "See https://github.com/citusdata/pg_cron for installation instructions."
            )


def _build_metadata(project: GovernanceProject, current: GovernanceProject, profile: ConnectionProfile) -> dict:
    """Build a metadata dict for a GovernanceProject."""
    return {
        "artifact_type":  "build",
        "tarkin_version": pkg_version("tarkin"),
        "built_at":       datetime.now(UTC).isoformat(),
        "profile":        profile.profile,
        "database":       profile.database,
        "host":           profile.host,
        "port":           profile.port,
        "yaml_checksum":  project_checksum(project),
        "db_checksum":    project_checksum(current),
        "schemas":        [s.name for s in project.schemas],
        "shadow_schemas": [f"tk_{s.name}" for s in project.schemas],
        "audit_enabled":  project.database.audit_enabled,
        "audit_logged":   [str(level) for level in project.database.audit_logged],
    }


class BuildError(Exception):
    pass
