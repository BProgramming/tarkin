from __future__ import annotations
import hashlib
import json
import re
import zipfile
from pathlib import Path
from sqlalchemy import Connection, text

from .credentials import ConnectionProfile
from .model import GovernanceProject
from .serialize import Serializer

OUT_DIR = Path("out")
DEFAULT_CREDENTIALS_PATH = Path.home() / ".tarkin" / "credentials.toml"


def build_output_directory(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def check_pgcron_available(profile: ConnectionProfile) -> bool:
    """Return True if pg_cron is installed and preloaded on the live database."""
    engine = profile.engine()
    try:
        with engine.connect() as conn:
            result = sql_select_single_scalar(conn, """
                SELECT COUNT(*) > 0
                FROM pg_extension e, pg_settings s
                WHERE e.extname = 'pg_cron'
                  AND s.name = 'shared_preload_libraries'
                  AND s.setting LIKE '%pg_cron%'
            """)
            return bool(result)
    finally:
        engine.dispose()


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


def project_checksum(project: GovernanceProject) -> str:
    """Return a SHA-256 hex digest of the project's serialized YAML."""
    return hashlib.sha256(Serializer.to_yaml_string(project).encode()).hexdigest()


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