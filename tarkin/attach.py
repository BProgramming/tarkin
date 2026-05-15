"""Attach a Tarkin model to the database."""
from __future__ import annotations
import json
import zipfile
from pathlib import Path

from .credentials import ConnectionProfile
from .codegen import project_checksum
from .inspect import inspect_database


OUT_DIR = Path("out")


def attach(profile: ConnectionProfile, build_path: Path | None = None) -> None:
    """Apply a Tarkin model to a live database."""
    zip_path = build_path or _find_latest_artifact()
    print(f"Using build artifact: {zip_path}")

    metadata, sql = _read_artifact(zip_path)

    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile, include_tk=True)
    except Exception as exc:
        raise AttachError(f"Failed to inspect database: {exc}") from exc
    tk_schemas = [s for s in current.schemas if s.name.startswith("tk_")]
    if tk_schemas:
        raise AttachError(
            f"Database already has an active Tarkin build. "
            f"Run 'tarkin detach' before attaching again."
        )
    print("Inspecting current database state... Done.")

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

    print("Applying build to database...", end="\r")
    try:
        engine = profile.engine()
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor()
            cursor.execute(sql)
            raw.commit()
            cursor.close()
        finally:
            raw.close()
        engine.dispose()
    except Exception as exc:
        raise AttachError(
            f"Failed to apply build. Database has been rolled back.\n"
            f"\tError: {exc}"
        ) from exc
    print("Applying build to database... Done.")

    print("Tarkin model successfully attached.")


def _find_latest_artifact() -> Path:
    """Find the most recent build artifact in out/."""
    if not OUT_DIR.exists():
        raise AttachError(
            f"No build artifacts found in {OUT_DIR}. "
            f"Run 'tarkin build' first."
        )

    artifacts = sorted(OUT_DIR.glob("tarkin_build_*.zip"))
    if not artifacts:
        raise AttachError(
            f"No build artifacts found in {OUT_DIR}. "
            f"Run 'tarkin build' first."
        )

    return artifacts[-1]


def _read_artifact(zip_path: Path) -> tuple[dict, str]:
    """Extract metadata and SQL from a build artifact zip."""
    if not zip_path.exists():
        raise AttachError(f"Build artifact not found: {zip_path}")

    try:
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            if "tarkin_build.json" not in names or "tarkin_build.sql" not in names:
                raise AttachError(
                    f"Build artifact {zip_path} is missing required files. "
                    f"Re-run 'tarkin build' to generate a fresh artifact."
                )
            metadata = json.loads(zf.read("tarkin_build.json").decode())
            sql      = zf.read("tarkin_build.sql").decode()
    except zipfile.BadZipFile as exc:
        raise AttachError(f"Build artifact {zip_path} is not a valid zip file.") from exc

    return metadata, sql


class AttachError(Exception):
    pass
