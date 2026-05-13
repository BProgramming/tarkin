"""
Credential loading and connection tests.

Tests that don't require a live database use a mock credentials file written
to a temp directory. Tests that require a live connection are marked with
pytest.mark.integration and skipped unless TARKIN_TEST_DSN is set.

To run integration tests:
    TARKIN_TEST_DSN="host=localhost port=5432 database=mydb user=me password=pw" \
        python -m pytest tests/ -m integration
"""
from __future__ import annotations
import os
import textwrap
from pathlib import Path
import pytest
from pydantic import SecretStr

from tarkin.credentials import (
    CredentialsFile, ConnectionProfile, ConnectionResult, check_connection,
)


# =====================================================
# HELPERS
# =====================================================

def write_toml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "credentials.toml"
    p.write_text(textwrap.dedent(content))
    return p


# =====================================================
# CREDENTIALS FILE LOADING
# =====================================================

def test_load_single_profile(tmp_path: Path) -> None:
    p = write_toml(tmp_path, """
        [dev]
        host     = "localhost"
        port     = 5432
        database = "devdb"
        username = "devuser"
        password = "devpass"
    """)
    creds = CredentialsFile.load(p)
    assert "dev" in creds.profiles
    prof = creds.profiles["dev"]
    assert prof.host == "localhost"
    assert prof.port == 5432
    assert prof.database == "devdb"
    assert prof.username == "devuser"
    assert prof.password.get_secret_value() == "devpass"


def test_load_multiple_profiles(tmp_path: Path) -> None:
    p = write_toml(tmp_path, """
        [dev]
        host     = "localhost"
        port     = 5432
        database = "devdb"
        username = "devuser"
        password = "devpass"

        [prod]
        host     = "prod.example.com"
        port     = 5433
        database = "proddb"
        username = "produser"
        password = "supersecret"
        sslmode  = "require"
    """)
    creds = CredentialsFile.load(p)
    assert set(creds.profile_names()) == {"dev", "prod"}
    assert creds.profiles["prod"].host == "prod.example.com"
    assert creds.profiles["prod"].sslmode == "require"


def test_get_existing_profile(tmp_path: Path) -> None:
    p = write_toml(tmp_path, """
        [dev]
        host = "localhost"
        port = 5432
        database = "db"
        username = "u"
        password = "pw"
    """)
    creds = CredentialsFile.load(p)
    prof = creds.get("dev")
    assert prof.profile == "dev"


def test_get_missing_profile_raises(tmp_path: Path) -> None:
    p = write_toml(tmp_path, """
        [dev]
        host = "localhost"
        port = 5432
        database = "db"
        username = "u"
        password = "pw"
    """)
    creds = CredentialsFile.load(p)
    with pytest.raises(KeyError, match="ghost"):
        creds.get("ghost")


def test_load_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError, match="not found"):
        CredentialsFile.load(Path("/nonexistent/credentials.toml"))


def test_invalid_port_raises(tmp_path: Path) -> None:
    p = write_toml(tmp_path, """
        [dev]
        host = "localhost"
        port = 99999
        database = "db"
        username = "u"
        password = "pw"
    """)
    with pytest.raises(ValueError, match="Invalid profile"):
        CredentialsFile.load(p)


def test_missing_required_field_raises(tmp_path: Path) -> None:
    p = write_toml(tmp_path, """
        [dev]
        host = "localhost"
        port = 5432
        database = "db"
        password = "pw"
    """)
    with pytest.raises(ValueError, match="Invalid profile"):
        CredentialsFile.load(p)


def test_dsn_does_not_expose_password() -> None:
    prof = ConnectionProfile(
        profile="dev", host="localhost", port=5432,
        database="db", username="user", password=SecretStr("s3cr3t"),
    )
    # DSN itself will contain the password (it's passed to the driver) —
    # but safe_repr() must not
    assert "s3cr3t" not in prof.safe_repr()


def test_safe_repr_contains_key_fields() -> None:
    prof = ConnectionProfile(
        profile="dev", host="pg.example.com", port=5433,
        database="mydb", username="alice", password=SecretStr("pw"),
    )
    s = prof.safe_repr()
    assert "alice" in s
    assert "pg.example.com" in s
    assert "5433" in s
    assert "mydb" in s
    assert "dev" in s


# =====================================================
# MOCK CONNECTION TESTS (no live DB required)
# =====================================================

def test_connection_result_str_success() -> None:
    r = ConnectionResult(
        profile="dev", success=True,
        server_version="16.2", db_user="alice",
    )
    s = str(r)
    assert "PASS" in s
    assert "16.2" in s
    assert "alice" in s


def test_connection_result_str_failure() -> None:
    r = ConnectionResult(
        profile="prod", success=False,
        error="Connection refused",
    )
    s = str(r)
    assert "FAIL" in s
    assert "Connection refused" in s


def test_bad_host_returns_failed_result() -> None:
    """A profile pointing at a nonexistent host should return success=False, not raise."""
    prof = ConnectionProfile(
        profile="bad",
        host="this-host-does-not-exist.invalid",
        port=5432,
        database="db",
        username="u",
        password=SecretStr("pw"),
    )
    result = check_connection(prof)
    assert result.success is False
    assert result.error is not None


# =====================================================
# INTEGRATION TESTS (require live DB)
# =====================================================

def _integration_profile() -> ConnectionProfile | None:
    """
    Build a ConnectionProfile from TARKIN_TEST_* env vars.
    Returns None if vars are not set, causing the test to skip.
    """
    host     = os.environ.get("TARKIN_TEST_HOST")
    database = os.environ.get("TARKIN_TEST_DB")
    username = os.environ.get("TARKIN_TEST_USER")
    password = os.environ.get("TARKIN_TEST_PASSWORD")

    if not host or not database or not username or not password:
        return None
    else:
        return ConnectionProfile(
            profile="integration",
            host=host,
            port=int(os.environ.get("TARKIN_TEST_PORT", "5432")),
            database=database,
            username=username,
            password=SecretStr(password),
        )


@pytest.mark.integration
def test_live_connection_succeeds() -> None:
    prof = _integration_profile()
    if prof is None:
        pytest.skip("TARKIN_TEST_* env vars not set.")

    result = check_connection(prof)
    assert result.success, f"Connection failed: {result.error}"
    assert result.server_version is not None
    assert result.db_user == prof.username


@pytest.mark.integration
def test_live_connection_db_user_matches_profile() -> None:
    prof = _integration_profile()
    if prof is None:
        pytest.skip("TARKIN_TEST_* env vars not set.")

    result = check_connection(prof)
    assert result.db_user == prof.username, (
        f"Connected as {result.db_user!r} but profile username is {prof.username!r}. "
        f"The credentials file user must match the actual database user."
    )
