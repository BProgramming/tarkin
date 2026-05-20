from __future__ import annotations
import json
import re
import zipfile
from pathlib import Path
from sqlalchemy import Connection, text

OUT_DIR = Path("out")
DEFAULT_CREDENTIALS_PATH = Path.home() / ".tarkin" / "credentials.toml"


def build_output_directory(out_dir: Path) -> Path:
    """Create *out_dir* (and parents) if it does not exist and return it.

    Note: this always treats its argument as a *directory*. Callers that hold a
    file path must pass ``path.parent`` — see the `output_file` / `output_directory`
    parameter naming used throughout the codebase.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def find_latest_artifact(out_dir: Path = OUT_DIR) -> Path | None:
    """Return the most recently created build/migrate artifact in *out_dir*, or None."""
    if not out_dir.exists():
        return None
    artifacts = sorted(
        list(out_dir.glob("tarkin_build_*.zip")) + list(out_dir.glob("tarkin_migrate_*.zip")),
        key=lambda p: p.name,
    )
    return artifacts[-1] if artifacts else None


def pg_version(version: str) -> str:
    """Extract a short numeric version (e.g. "16.2") from PostgreSQL's version() string."""
    # version() returns e.g. "PostgreSQL 16.2 on x86_64-pc-linux-gnu, ..."
    m = re.search(r'PostgreSQL\s+(\d+\.\d+)', version)
    if m:
        return m.group(1)
    else:
        parts = version.split()
        if len(parts) >= 2:
            return parts[1]
        else:
            return version


def sql_comment_block_section(title: str, subtitle: str = "") -> str:
    """Return a SQL comment block marking a named section."""
    line  = "-" * 60
    parts = [f"-- {line}", f"-- {title}"]
    if subtitle:
        parts.append(f"-- {subtitle}")
    parts.append(f"-- {line}")
    return "\n".join(parts)


def sql_safe_dollar_quote(yaml_str: str) -> tuple[str, str]:
    """Return a dollar-quote tag that does not appear anywhere in yaml_str."""
    base = "tarkin_yaml"
    tag  = base
    n    = 0
    while f"${tag}$" in yaml_str:
        n  += 1
        tag = f"{base}_{n}"
    return f"${tag}$", f"${tag}$"


def sql_safe_double_quote(name: str) -> str:
    """Double-quote a PostgreSQL identifier."""
    return f'"{name}"'


def sql_safe_escape_string(s: str) -> str:
    """Escape a string value for safe inclusion in a SQL single-quoted literal."""
    if not s:
        return ""
    return s.replace("'", "''")


def sql_select_single_scalar(conn: Connection, query: str) -> str:
    row = conn.execute(text(query)).fetchone()
    return row[0] if row else ""


def write_artifact(zip_path: Path, sql: str, metadata: dict) -> None:
    """Write an artifact to a zip file."""
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("tarkin_build.json", json.dumps(metadata, indent=2))
        zf.writestr("tarkin_build.sql",  sql)
