"""Load and validate database credentials."""
from __future__ import annotations

import subprocess

import sqlalchemy
import tomllib
from pathlib import Path
from pydantic import BaseModel, ConfigDict, SecretStr, field_validator, model_validator, PrivateAttr
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from typing import Literal, Optional

from .utils import (
    DEFAULT_CREDENTIALS_PATH,
    pg_version, sql_select_single_scalar,
)


class AIProfile(BaseModel):
    """AI provider configuration from the [ai] section of credentials.toml.

    Supported providers:
        anthropic       — Anthropic Claude models
        openai          — OpenAI models, and any OpenAI-compatible endpoint
                          (Azure OpenAI, Mistral, Grok, Ollama, etc.) via base_url
    """
    model_config = ConfigDict(extra="forbid")

    provider: Literal["anthropic", "openai"]
    api_key:  SecretStr
    model:    str
    base_url: Optional[str] = None


class ConnectionProfile(BaseModel):
    """A named connection profile from credentials.toml."""
    model_config = ConfigDict(extra="forbid")

    profile:  str
    host:     str = "localhost"
    port:     int = 5432
    database: str = "postgres"

    hmac_key: Optional[SecretStr] = None

    # Login
    username: str
    password: Optional[SecretStr] = None

    # IAM / SSO auth
    iam_auth:      bool          = False
    aws_profile:   Optional[str] = None
    aws_region:    Optional[str] = None
    _cached_token: Optional[str] = PrivateAttr(default=None)

    # SSL client cert
    sslcert:     Optional[Path] = None
    sslkey:      Optional[Path] = None
    sslrootcert: Optional[Path] = None

    sslmode: Literal[
        "disable",
        "allow",
        "prefer",
        "require",
        "verify-ca",
        "verify-full",
    ] = "verify-full"

    @field_validator("port")
    @classmethod
    def port_in_range(cls, v: int) -> int:
        """Validate port range."""
        if not (1 <= v <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {v}.")
        return v

    def fallback_ssl(self):
        if self.sslmode == "verify-full" and self.password and not self.iam_auth and not self.sslcert:
            self.sslmode = "prefer"

    @model_validator(mode="after")
    def validate_auth(self) -> "ConnectionProfile":
        """Enforce auth consistency and set sslmode default."""
        if not self.password and not self.iam_auth and not self.sslcert:
            raise ValueError(
                "Profile must specify either a password, iam_auth=true, or sslcert/sslkey "
                "for certificate-based auth. For certificate-based auth, set username to "
                "the Common Name (CN) from your client certificate."
            )

        # Downgrade sslmode default for plain password profiles with no cert fields
        self.fallback_ssl()

        return self

    def token(self) -> str | None:
        """Generate and cache a temporary IAM auth token via boto3."""
        try:
            import boto3
        except ImportError:
            raise RuntimeError(
                "boto3 is a required dependency for IAM auth. Install it with: pip install tarkin[iam]"
            )
        session = boto3.Session(profile_name=self.aws_profile)
        client = session.client("rds", region_name=self.aws_region)
        self._cached_token = client.generate_db_auth_token(
            DBHostname = self.host,
            Port       = self.port,
            DBUsername = self.username,
        )
        return self._cached_token

    def dsn(self) -> str:
        """Build a postgresql+psycopg DSN."""
        if self.iam_auth:
            pw = self.token()
        elif self.password:
            pw = self.password.get_secret_value()
        else:
            pw = ""

        return (
            f"postgresql+psycopg://{self.username}:{pw}"
            f"@{self.host}:{self.port}/{self.database}"
            f"?sslmode={self.sslmode}"
        )

    def engine(self) -> sqlalchemy.Engine:
        """Return a SQLAlchemy engine for this profile."""
        connect_args: dict = {}
        if self.sslcert and self.sslkey and self.sslrootcert:
            connect_args["sslcert"]     = str(self.sslcert.expanduser())
            connect_args["sslkey"]      = str(self.sslkey.expanduser())
            connect_args["sslrootcert"] = str(self.sslrootcert.expanduser())

        return sqlalchemy.create_engine(
            self.dsn(),
            pool_pre_ping = True,
            connect_args  = connect_args,
        )

    def safe_repr(self) -> str:
        """Human-readable representation of the connection."""
        if self.iam_auth:
            auth = "IAM"
        elif self.sslcert:
            auth = "cert"
        else:
            auth = "pass"

        return (
            f"{self.username}@{self.host}:{self.port}/{self.database} "
            f"[profile={self.profile!r}, auth={auth}]"
        )


class CredentialsFile(BaseModel):
    """Parsed credentials.toml. Profiles are keyed by their [profile_name] section."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path:     Path
    profiles: dict[str, ConnectionProfile]
    ai:       Optional[AIProfile] = None

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

        ai_profile: Optional[AIProfile]          = None
        profiles:   dict[str, ConnectionProfile] = {}

        for name, values in raw.items():
            if not isinstance(values, dict):
                raise ValueError(f"Credentials file section [{name}] must be a table, got {type(values).__name__}.")
            if name == "ai":
                try:
                    ai_profile = AIProfile(**values)
                except Exception as exc:
                    raise ValueError(f"Invalid [ai] section: {exc}") from exc
            else:
                try:
                    profiles[name] = ConnectionProfile(profile=name, **values)
                except Exception as exc:
                    raise ValueError(f"Invalid profile [{name}]: {exc}") from exc

        return cls(path=resolved, profiles=profiles, ai=ai_profile)

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


def authorize_connection(profile: ConnectionProfile) -> None:
    """Run AWS SSO login for an IAM-authenticated profile."""
    if not profile.iam_auth:
        raise RuntimeError(
            f"Profile {profile.profile!r} does not use IAM auth. "
            f"'tarkin auth' is only applicable to iam_auth profiles."
        )

    cmd = ["aws", "sso", "login"]
    if profile.aws_profile:
        cmd += ["--profile", profile.aws_profile]

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        raise RuntimeError(
            "AWS CLI not found. Install it from https://aws.amazon.com/cli/ "
            "and ensure it is on your PATH."
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"AWS SSO login failed with exit code {exc.returncode}."
        )

    try:
        profile.token()
    except Exception as exc:
        raise RuntimeError(
            f"AWS SSO login succeeded but token generation failed: {exc}"
        ) from exc


def check_connection(profile: ConnectionProfile, reauth: bool = False, print_progress: bool = True) -> ConnectionResult:
    """Open a connection, run a minimal probe query, and return a ConnectionResult.

    If reauth=True and the profile uses IAM auth, a failed connection will
    prompt the user to re-authorize via authorize_connection before retrying.
    """

    def _attempt(p: ConnectionProfile) -> ConnectionResult:
        try:
            engine = p.engine()
            with engine.connect() as conn:
                row = conn.execute(sqlalchemy.text(
                    "SELECT current_user, version()"
                )).fetchone()
                if row:
                    db_user = row[0]
                    server_version = pg_version(row[1])
                else:
                    db_user = None
                    server_version = None
            engine.dispose()
            return ConnectionResult(
                profile        = p.profile,
                success        = True,
                server_version = server_version,
                db_user        = db_user,
            )
        except OperationalError as exc: # noqa
            return ConnectionResult(
                profile = p.profile,
                success = False,
                error   = _clean_error(str(exc)),
            )
        except SQLAlchemyError as exc: # noqa
            return ConnectionResult(
                profile = p.profile,
                success = False,
                error   = str(exc),
            )

    if print_progress:
        print("Connecting to database", end="")
        if profile.iam_auth:
            print(" with IAM auth...", end="\r")
        else:
            print(" with username and password...", end="\r")

    result = _attempt(profile)

    if result.success:
        if print_progress:
            print("Connecting to database", end="")
            if profile.iam_auth:
                print(" with IAM auth... Succeeded.")
            else:
                print(" with username and password... Succeeded.")
    else:
        if print_progress:
            print("Connecting to database", end="")
            if profile.iam_auth:
                print(" with IAM auth... Failed.")
            else:
                print(" with username and password... Failed.")
            print(f"{result.error}")

        if profile.iam_auth:
            if not result.success and reauth:
                refresh = bool(input(
                    f"Your credentials for profile {profile.safe_repr()} may have expired, would you like to re-authorize? "
                    "This will open a session in your default web browser. [Y/N] "
                ).strip().casefold() == "y")
                if refresh:
                    try:
                        authorize_connection(profile)
                    except RuntimeError as exc:
                        return ConnectionResult(
                            profile = profile.profile,
                            success = False,
                            error   = str(exc),
                        )
                    print("Re-authorization complete. Retrying connection...", end="\r")
                    result = _attempt(profile)
                    if result.success:
                        print("Re-authorization complete. Retrying connection... Succeeded.")
                    else:
                        print("Re-authorization complete. Retrying connection... Failed.")
                        print(f"{result.error}")
            if not result.success and profile.password:
                profile.iam_auth = False
                profile.fallback_ssl()
                print("Falling back to stored username/password. Retrying connection...", end="\r")
                result = _attempt(profile)
                if result.success:
                    print("Falling back to stored username/password. Retrying connection... Succeeded.")
                else:
                    print("Falling back to stored username/password. Retrying connection... Failed.")
                    print(f"{result.error}")

    if print_progress and result.success:
        print(f"Connected as {profile.safe_repr()} on PostgreSQL {result.server_version}.")

    return result


def test_all_connections(creds: CredentialsFile, reauth: bool = False) -> list[ConnectionResult]:
    """Test all connections."""
    return [check_connection(p, reauth=reauth, print_progress=False) for p in creds.profiles.values()]


def _clean_error(msg: str) -> str:
    """Strip SQLAlchemy boilerplate from connection error messages."""
    for prefix in ["(psycopg.OperationalError)", "(sqlalchemy.exc.OperationalError)"]:
        msg = str(msg.replace(prefix, "")).strip()
    first_line = msg.splitlines()[0].strip() if msg.splitlines() else msg
    return first_line.lstrip("()")


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
