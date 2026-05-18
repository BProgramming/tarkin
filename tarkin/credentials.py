"""Load and validate database credentials."""
from __future__ import annotations
import sqlalchemy
import tomllib
from pathlib import Path
from pydantic import BaseModel, ConfigDict, SecretStr, field_validator
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from typing import Optional

from .utils import (
    DEFAULT_CREDENTIALS_PATH,
    pg_version,
)


class ConnectionProfile(BaseModel):
    """A named connection profile from credentials.toml."""
    model_config = ConfigDict(extra="forbid")

    profile:  str
    host:     str        = "localhost"
    port:     int        = 5432
    database: str        = "postgres"
    username: str
    password: SecretStr
    sslmode:  str        = "prefer"

    hmac_key: Optional[SecretStr] = None

    @field_validator("port")
    @classmethod
    def port_in_range(cls, v: int) -> int:
        """Validate port range."""
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

    def engine(self) -> sqlalchemy.Engine:
        """Return a SQLAlchemy engine for this profile."""
        return sqlalchemy.create_engine(self.dsn(), pool_pre_ping=True)

    def safe_repr(self) -> str:
        """Human-readable representation with password redacted."""
        return f"{self.username}@{self.host}:{self.port}/{self.database} [profile={self.profile!r}]"


class CredentialsFile(BaseModel):
    """Parsed credentials.toml. Profiles are keyed by their [profile_name] section."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path:     Path
    profiles: dict[str, ConnectionProfile]

    @classmethod
    def load(cls, path: Path | None = None) -> CredentialsFile:
        """Load and parse a credentials.toml file."""
        resolved = path or DEFAULT_CREDENTIALS_PATH

        if not resolved.exists():
            raise FileNotFoundError(
                f"Credentials file not found: {resolved}.\n"
                f"Create it at {resolved} or pass --credentials <path>."
            )

        with resolved.open("rb") as f:
            raw = tomllib.load(f)

        profiles: dict[str, ConnectionProfile] = {}
        for name, values in raw.items():
            if not isinstance(values, dict):
                raise ValueError(f"Credentials file section [{name}] must be a table, got {type(values).__name__}.")
            try:
                profiles[name] = ConnectionProfile(profile=name, **values)
            except Exception as exc:
                raise ValueError(f"Invalid profile [{name}]: {exc}") from exc

        return cls(path=resolved, profiles=profiles)

    def get(self, profile_name: str) -> ConnectionProfile:
        if profile_name not in self.profiles:
            available = "\n\t".join(repr(k) for k in self.profiles)
            raise KeyError(f"Profile {profile_name!r} not found in {self.path}.\nAvailable profiles:{available}")
        return self.profiles[profile_name]

    def profile_names(self) -> list[str]:
        return list(self.profiles.keys())


class ConnectionResult(BaseModel):
    """Result of a connection attempt."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    profile:        str
    success:        bool
    server_version: Optional[str] = None
    db_user:        Optional[str] = None
    error:          Optional[str] = None

    def __str__(self) -> str:
        if self.success:
            return f"PASS: {self.profile!r} connected to PostgreSQL {self.server_version} instance as {self.db_user!r}."
        return f"FAIL: {self.profile!r}, {self.error}"


def check_connection(profile: ConnectionProfile) -> ConnectionResult:
    """Open a connection, run a minimal probe query, and return a ConnectionResult."""
    try:
        engine = profile.engine()
        with engine.connect() as conn:
            row = conn.execute(sqlalchemy.text(
                "SELECT current_user, version()"
            )).fetchone()
            if row:
                db_user        = row[0]
                server_version = pg_version(row[1])
            else:
                db_user = None
                server_version = None
        engine.dispose()
        return ConnectionResult(
            profile        = profile.profile,
            success        = True,
            server_version = server_version,
            db_user        = db_user,
        )
    except OperationalError as exc:
        return ConnectionResult(
            profile = profile.profile,
            success = False,
            error   = _clean_error(str(exc)),
        )
    except SQLAlchemyError as exc:
        return ConnectionResult(
            profile = profile.profile,
            success = False,
            error   = str(exc),
        )


def test_all_connections(creds: CredentialsFile) -> list[ConnectionResult]:
    """Test all connections."""
    return [check_connection(p) for p in creds.profiles.values()]


def _clean_error(msg: str) -> str:
    """Strip SQLAlchemy boilerplate from connection error messages."""
    for prefix in ["(psycopg.OperationalError)", "(sqlalchemy.exc.OperationalError)"]:
        msg = str(msg.replace(prefix, "")).strip()
    first_line = msg.splitlines()[0].strip() if msg.splitlines() else msg
    return first_line.lstrip("()")
