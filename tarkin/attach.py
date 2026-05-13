from __future__ import annotations
import json
import zipfile
from pathlib import Path

from .credentials import ConnectionProfile
from .codegen import _project_checksum
from .inspect import inspect_database


# =========================================================
# OUTPUT DIRECTORY
# =========================================================

OUT_DIR = Path("out")


# =========================================================
# ATTACH ENTRY POINT
# =========================================================

def attach(profile: ConnectionProfile, build_path: Path | None = None) -> None:
    """
    Apply a Tarkin model to a live database.

    1. Find the build artifact
    2. Verify database state matches the build checksum
    3. Execute the SQL
    """

    # Step 1 — find artifact
    zip_path = build_path or _find_latest_artifact()
    print(f"Using build artifact: {zip_path}")

    # Step 2 — read metadata and SQL
    metadata, sql = _read_artifact(zip_path)

    # Step 3 — verify database state
    print("Inspecting current database state...", end="\r")
    try:
        current = inspect_database(profile)
    except Exception as exc:
        raise AttachError(f"Failed to inspect database: {exc}") from exc
    print("Inspecting current database state... Done.")

    print("Verifying database state...", end="\r")
    current_checksum = _project_checksum(current)
    build_checksum   = metadata.get("db_checksum")

    if current_checksum != build_checksum:
        raise AttachError(
            f"Database state has changed since the build was generated.\n"
            f"Build checksum:   {build_checksum}\n"
            f"Current checksum: {current_checksum}\n"
            f"Re-run 'tarkin build' to generate a fresh artifact."
        )
    print("Verifying database state... Done.")

    # Step 4 — execute SQL
    print("Applying build to database...", end="\r")
    try:
        engine = profile.engine()
        with engine.connect() as conn:
            conn.connection.execute(sql)
        engine.dispose()
    except Exception as exc:
        raise AttachError(
            f"Failed to apply build — database has been rolled back.\n"
            f"Error: {exc}"
        ) from exc
    print("Applying build to database... Done.")

    print("Tarkin model successfully attached.")


# =========================================================
# ARTIFACT HELPERS
# =========================================================

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


# =========================================================
# ERRORS
# =========================================================

class AttachError(Exception):
    pass
