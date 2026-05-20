"""Attach a Tarkin model to the database."""
from __future__ import annotations
import json
import zipfile
from pathlib import Path
from sqlalchemy import text

from .credentials import ConnectionProfile
from .inspect import inspect_database
from .utils import (
    OUT_DIR,
    find_latest_artifact,
)
from .serialize import project_checksum


def attach(profile: ConnectionProfile, build_path: Path | None = None) -> None:
    """Apply a Tarkin model to a live database."""
    zip_path = build_path or find_latest_artifact(OUT_DIR)
    if zip_path is None:
        raise AttachError(
            f"No artifacts found in {OUT_DIR}. "
            f"Run 'tarkin build' or 'tarkin migrate' to generate an artifact."
        )
    print(f"Using artifact: {zip_path}")

    metadata, sql = _read_artifact(zip_path)
    artifact_type = metadata.get("artifact_type", "build")

    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile, include_tk=True)
    except Exception as exc:
        raise AttachError(f"Failed to inspect database: {exc}") from exc
    tk_schemas = [s for s in current.schemas if s.name.startswith("tk_")]
    print("Inspecting current database state... Done.")

    if artifact_type == "migrate":
        _validate_for_migration(profile, metadata, tk_schemas)
    else:
        _validate_for_build(metadata, tk_schemas, current)

    verb = "migration" if artifact_type == "migrate" else "build"
    print(f"Applying {verb} to database...", end="\r")
    try:
        engine = profile.engine()
        raw = engine.raw_connection()
        try:
            raw.driver_connection.autocommit = True
            cursor = raw.cursor()
            cursor.execute(sql)
            cursor.close()
        finally:
            raw.close()
        engine.dispose()
    except Exception as exc:
        raise AttachError(
            f"Failed to apply {verb}. Database has been rolled back.\n\tError: {exc}"
        ) from exc
    print(f"Applying {verb} to database... Done.")

    print(f"Tarkin {verb} successfully applied.")


def _validate_for_build(metadata: dict, tk_schemas: list, current) -> None:
    """Validate pre-conditions for a standard build artifact."""
    if tk_schemas:
        raise AttachError("Database already has an active Tarkin build. Run 'tarkin detach' before attaching again.")

    print("Verifying database state...", end="\r")
    current_checksum = project_checksum(current)
    build_checksum   = metadata.get("db_checksum")

    if current_checksum != build_checksum:
        raise AttachError(
            f"Database state has changed since the build was generated.\n"
            f"\tBuild checksum:   {build_checksum}\n"
            f"\tCurrent checksum: {current_checksum}\n"
            f"Re-run 'tarkin build' to generate a fresh artifact."
        )
    print("Verifying database state... Done.")


def _validate_for_migration(profile: ConnectionProfile, metadata: dict, tk_schemas: list) -> None:
    """Validate pre-conditions for a migration artifact."""
    if not tk_schemas:
        raise AttachError(
            "No active Tarkin build found. "
            "A migration artifact requires an existing build to be attached. "
            "Run 'tarkin build' and 'tarkin attach' first."
        )

    print("Verifying migration source...", end="\r")
    source_checksum   = metadata.get("source_checksum")
    artifact_database = metadata.get("database")

    engine = profile.engine()
    try:
        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT checksum, database_name FROM __META__.tarkin_builds "
                "ORDER BY built_at DESC LIMIT 1"
            )).fetchone()
    finally:
        engine.dispose()

    if not row:
        raise AttachError(
            "Could not read the current build checksum from __META__. "
            "The database may have a partially applied or corrupt build."
        )

    live_checksum   = row[0]
    live_db_name    = row[1]

    if artifact_database and live_db_name != artifact_database:
        raise AttachError(
            f"Migration artifact was generated for database '{artifact_database}' "
            f"but the connected database is '{live_db_name}'. "
            f"Apply this migration to the correct database."
        )

    if source_checksum and live_checksum != source_checksum:
        raise AttachError(
            f"Migration source does not match the current build.\n"
            f"\tExpected source checksum: {source_checksum}\n"
            f"\tCurrent build checksum:   {live_checksum}\n"
            f"Re-run 'tarkin migrate' against the current build to generate a fresh artifact."
        )
    print("Verifying migration source... Done.")


def _read_artifact(zip_path: Path) -> tuple[dict, str]:
    """Extract metadata and SQL from a build/migrate artifact zip."""
    if not zip_path.exists():
        raise AttachError(f"Artifact {zip_path} not found.")

    try:
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()

            if "tarkin_build.json" not in names or "tarkin_build.sql" not in names:
                raise AttachError(f"Artifact {zip_path} is missing required files. Re-run 'tarkin build' or 'tarkin migrate' to generate a fresh artifact.")

            metadata = json.loads(zf.read("tarkin_build.json").decode())
            sql      = zf.read("tarkin_build.sql").decode()
    except zipfile.BadZipFile as exc:
        raise AttachError(f"Artifact {zip_path} is not a valid zip file.") from exc

    return metadata, sql


class AttachError(Exception):
    pass
