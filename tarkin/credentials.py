from __future__ import annotations
import tomllib
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, ConfigDict, SecretStr, field_validator

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError


# =========================================================
# DEFAULT CREDENTIALS FILE LOCATION
# =========================================================

DEFAULT_CREDENTIALS_PATH = Path.home() / ".tarkin" / "credentials.toml"


# =========================================================
# MODELS
# =========================================================

class ConnectionProfile(BaseModel):
    """
    A named connection profile from credentials.toml.
    Credentials never appear in the governance YAML — only the profile name does.
    """
    model_config = ConfigDict(extra="forbid")

    profile:  str
    host:     str        = "localhost"
    port:     int        = 5432
    database: str        = "postgres"
    username: str
    password: SecretStr
    sslmode:  str        = "prefer"

    @field_validator("port")
    @classmethod
    def port_in_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {v}.")
        return v

    def dsn(self) -> str:
        """Build a postgresql+psycopg DSN. Password is injected from SecretStr."""
        pw = self.password.get_secret_value()
        return (
            f"postgresql+psycopg://{self.username}:{pw}"
            f"@{self.host}:{self.port}/{self.database}"
            f"?sslmode={self.sslmode}"
        )

    def engine(self):
        """Return a SQLAlchemy engine for this profile."""
        return create_engine(self.dsn(), pool_pre_ping=True)

    def safe_repr(self) -> str:
        """Human-readable representation with password redacted."""
        return (
            f"{self.username}@{self.host}:{self.port}/{self.database} "
            f"[profile={self.profile!r}]"
        )


class CredentialsFile(BaseModel):
    """
    Parsed credentials.toml. Profiles are keyed by their [profile_name] section.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path:     Path
    profiles: dict[str, ConnectionProfile]

    @classmethod
    def load(cls, path: Path | None = None) -> "CredentialsFile":
        """
        Load and parse a credentials.toml file.

        File format:
            [dev]
            host     = "localhost"
            port     = 5432
            database = "mydb"
            username = "myuser"
            password = "mypassword"

            [prod]
            host     = "prod.example.com"
            ...
        """
        resolved = path or DEFAULT_CREDENTIALS_PATH

        if not resolved.exists():
            raise FileNotFoundError(
                f"Credentials file not found: {resolved}\n"
                f"Create it at {resolved} or pass --credentials <path>."
            )

        with resolved.open("rb") as f:
            raw = tomllib.load(f)

        profiles: dict[str, ConnectionProfile] = {}
        for name, values in raw.items():
            if not isinstance(values, dict):
                raise ValueError(
                    f"Credentials file section [{name}] must be a table, got {type(values).__name__}."
                )
            try:
                profiles[name] = ConnectionProfile(profile=name, **values)
            except Exception as exc:
                raise ValueError(f"Invalid profile [{name}]: {exc}") from exc

        return cls(path=resolved, profiles=profiles)

    def get(self, profile_name: str) -> ConnectionProfile:
        if profile_name not in self.profiles:
            available = ", ".join(repr(k) for k in self.profiles)
            raise KeyError(
                f"Profile {profile_name!r} not found in {self.path}. "
                f"Available profiles: {available}."
            )
        return self.profiles[profile_name]

    def profile_names(self) -> list[str]:
        return list(self.profiles.keys())


# =========================================================
# CONNECTION TEST
# =========================================================

class ConnectionResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    profile:        str
    success:        bool
    server_version: Optional[str] = None
    db_user:        Optional[str] = None
    error:          Optional[str] = None

    def __str__(self) -> str:
        if self.success:
            return (
                f"[ok] {self.profile!r} — "
                f"PostgreSQL {self.server_version}, "
                f"connected as {self.db_user!r}"
            )
        return f"[fail] {self.profile!r} — {self.error}"


def test_connection(profile: ConnectionProfile) -> ConnectionResult:
    """
    Open a connection, run a minimal probe query, return a ConnectionResult.
    Never raises — errors are captured in the result.
    """
    try:
        engine = profile.engine()
        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT current_user, version()"
            )).fetchone()
            db_user        = row[0]
            server_version = _parse_pg_version(row[1])
        engine.dispose()
        return ConnectionResult(
            profile=profile.profile,
            success=True,
            server_version=server_version,
            db_user=db_user,
        )
    except OperationalError as exc:
        return ConnectionResult(
            profile=profile.profile,
            success=False,
            error=_clean_error(str(exc)),
        )
    except SQLAlchemyError as exc:
        return ConnectionResult(
            profile=profile.profile,
            success=False,
            error=str(exc),
        )


def test_all_connections(creds: CredentialsFile) -> list[ConnectionResult]:
    return [test_connection(p) for p in creds.profiles.values()]


# =========================================================
# HELPERS
# =========================================================

def _parse_pg_version(version_str: str) -> str:
    """Extract the short version number from PostgreSQL's version() string."""
    # e.g. "PostgreSQL 16.2 on x86_64-pc-linux-gnu, compiled by gcc ..."
    parts = version_str.split()
    if len(parts) >= 2:
        return parts[1]
    return version_str


def _clean_error(msg: str) -> str:
    """Strip SQLAlchemy boilerplate from connection error messages."""
    for prefix in ["(psycopg.OperationalError)", "(sqlalchemy.exc.OperationalError)"]:
        msg = msg.replace(prefix, "").strip()
    # Trim to first meaningful line
    first_line = msg.splitlines()[0].strip() if msg.splitlines() else msg
    return first_line.lstrip("()")
