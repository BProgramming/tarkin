"""Credential loading and connection tests."""
from __future__ import annotations
import os
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from pydantic import SecretStr
from sqlalchemy.exc import OperationalError

from tarkin.credentials import (
    CredentialsFile,
    ConnectionProfile,
    ConnectionResult,
    authorize_connection,
    check_connection,
)

def write_toml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "credentials.toml"
    p.write_text(textwrap.dedent(content))
    return p

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
        host     = "localhost"
        port     = 5432
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
        host     = "localhost"
        port     = 5432
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
        host     = "localhost"
        port     = 99999
        database = "db"
        username = "u"
        password = "pw"
    """)
    with pytest.raises(ValueError, match="Invalid profile"):
        CredentialsFile.load(p)


def test_missing_required_field_raises(tmp_path: Path) -> None:
    p = write_toml(tmp_path, """
        [dev]
        host     = "localhost"
        port     = 5432
        database = "db"
        password = "pw"
    """)
    with pytest.raises(ValueError, match="Invalid profile"):
        CredentialsFile.load(p)


def test_dsn_does_not_expose_password() -> None:
    prof = ConnectionProfile(
        profile  = "dev",
        host     = "localhost",
        port     = 5432,
        database = "db",
        username = "user",
        password = SecretStr("s3cr3t"),
    )
    assert "s3cr3t" not in prof.safe_repr()


def test_safe_repr_contains_key_fields() -> None:
    prof = ConnectionProfile(
        profile  = "dev",
        host     = "pg.example.com",
        port     = 5433,
        database = "mydb",
        username = "alice",
        password = SecretStr("pw"),
    )
    s = prof.safe_repr()
    assert "alice" in s
    assert "pg.example.com" in s
    assert "5433" in s
    assert "mydb" in s
    assert "dev" in s

def test_connection_result_str_success() -> None:
    r = ConnectionResult(
        profile        = "dev",
        success        = True,
        server_version = "16.2",
        db_user        = "alice",
    )
    s = str(r)
    assert "PASS" in s
    assert "16.2" in s
    assert "alice" in s


def test_connection_result_str_failure() -> None:
    r = ConnectionResult(
        profile = "prod",
        success = False,
        error   = "Connection refused",
    )
    s = str(r)
    assert "FAIL" in s
    assert "Connection refused" in s


def test_bad_host_returns_failed_result() -> None:
    """A profile pointing at a nonexistent host should return success=False, not raise."""
    prof = ConnectionProfile(
        profile  = "bad",
        host     = "this-host-does-not-exist.invalid",
        port     = 5432,
        database = "db",
        username = "u",
        password = SecretStr("pw"),
    )
    result = check_connection(prof)
    assert result.success is False
    assert result.error is not None

# ---------------------------------------------------------------------------
# Auth profile parsing: IAM and certificate-based profiles
# ---------------------------------------------------------------------------

def test_iam_profile_loads(tmp_path: Path) -> None:
    """An iam_auth profile with no password parses and defaults sslmode to verify-full."""
    p = write_toml(tmp_path, """
        [iam]
        host       = "mydb.xxxx.us-east-1.rds.amazonaws.com"
        port       = 5432
        database   = "app"
        username   = "db_user"
        iam_auth   = true
        aws_region = "us-east-1"
    """)
    creds = CredentialsFile.load(p)
    prof = creds.get("iam")
    assert prof.iam_auth is True
    assert prof.password is None
    assert prof.aws_region == "us-east-1"
    assert prof.sslmode == "verify-full"


def test_cert_profile_loads(tmp_path: Path) -> None:
    """A certificate-based profile parses and defaults sslmode to verify-full."""
    p = write_toml(tmp_path, """
        [okta]
        host        = "mydb.example.com"
        port         = 5432
        database     = "app"
        username     = "alice"
        sslcert      = "~/.okta/client.crt"
        sslkey       = "~/.okta/client.key"
        sslrootcert  = "~/.okta/ca.crt"
    """)
    creds = CredentialsFile.load(p)
    prof = creds.get("okta")
    assert prof.password is None
    assert prof.sslcert == Path("~/.okta/client.crt")
    assert prof.sslkey == Path("~/.okta/client.key")
    assert prof.sslrootcert == Path("~/.okta/ca.crt")
    assert prof.sslmode == "verify-full"


def test_no_auth_method_raises(tmp_path: Path) -> None:
    """A profile with no password, no IAM, and no cert is rejected."""
    p = write_toml(tmp_path, """
        [bare]
        host     = "localhost"
        port     = 5432
        database = "db"
        username = "u"
    """)
    with pytest.raises(ValueError, match="Invalid profile"):
        CredentialsFile.load(p)


def test_password_profile_sslmode_downgraded() -> None:
    """A plain password profile downgrades the default verify-full to prefer."""
    prof = ConnectionProfile(
        profile  = "pw",
        host     = "localhost",
        database = "db",
        username = "u",
        password = SecretStr("pw"),
    )
    assert prof.sslmode == "prefer"


def test_password_profile_explicit_sslmode_preserved() -> None:
    """An explicitly set sslmode on a password profile is not downgraded."""
    prof = ConnectionProfile(
        profile  = "pw",
        host     = "localhost",
        database = "db",
        username = "u",
        password = SecretStr("pw"),
        sslmode  = "require",
    )
    assert prof.sslmode == "require"


def test_iam_profile_sslmode_stays_verify_full() -> None:
    """An IAM profile keeps the verify-full default (no downgrade)."""
    prof = ConnectionProfile(
        profile  = "iam",
        host     = "db.rds.amazonaws.com",
        database = "db",
        username = "u",
        iam_auth = True,
    )
    assert prof.sslmode == "verify-full"


def test_safe_repr_shows_auth_method() -> None:
    """safe_repr surfaces the auth method in use."""
    pw = ConnectionProfile(
        profile="pw", host="h", database="db", username="u", password=SecretStr("pw"),
    )
    iam = ConnectionProfile(
        profile="iam", host="h", database="db", username="u", iam_auth=True,
    )
    cert = ConnectionProfile(
        profile="cert", host="h", database="db", username="u",
        sslcert=Path("/tmp/c.crt"), sslkey=Path("/tmp/c.key"), sslrootcert=Path("/tmp/ca.crt"),
    )
    assert "auth=pass" in pw.safe_repr()
    assert "auth=IAM" in iam.safe_repr()
    assert "auth=cert" in cert.safe_repr()


# ---------------------------------------------------------------------------
# IAM token generation (boto3 mocked — never hits AWS)
# ---------------------------------------------------------------------------

def _mock_boto3(token: str = "fake-token") -> MagicMock:
    """Return a MagicMock standing in for the boto3 module."""
    fake = MagicMock()
    fake.Session.return_value.client.return_value.generate_db_auth_token.return_value = token
    return fake


def test_token_generates_and_caches() -> None:
    """token() calls boto3 with the right args and caches the result."""
    prof = ConnectionProfile(
        profile="iam", host="db.rds.amazonaws.com", port=5432,
        database="app", username="dbuser", iam_auth=True, aws_region="us-east-1",
    )
    fake = _mock_boto3("tok-abc")
    with patch.dict("sys.modules", {"boto3": fake}):
        tok = prof.token()

    assert tok == "tok-abc"
    assert prof._cached_token == "tok-abc"
    fake.Session.assert_called_once_with(profile_name=None)
    fake.Session.return_value.client.assert_called_once_with("rds", region_name="us-east-1")
    fake.Session.return_value.client.return_value.generate_db_auth_token.assert_called_once_with(
        DBHostname="db.rds.amazonaws.com", Port=5432, DBUsername="dbuser",
    )


def test_token_uses_aws_profile() -> None:
    """token() passes aws_profile through to the boto3 Session."""
    prof = ConnectionProfile(
        profile="iam", host="h", database="app", username="u",
        iam_auth=True, aws_profile="my-sso-profile",
    )
    fake = _mock_boto3()
    with patch.dict("sys.modules", {"boto3": fake}):
        prof.token()
    fake.Session.assert_called_once_with(profile_name="my-sso-profile")


# ---------------------------------------------------------------------------
# authorize_connection
# ---------------------------------------------------------------------------

def test_authorize_non_iam_raises() -> None:
    """authorize_connection rejects non-IAM profiles."""
    prof = ConnectionProfile(
        profile="pw", host="h", database="db", username="u", password=SecretStr("pw"),
    )
    with pytest.raises(RuntimeError, match="does not use IAM auth"):
        authorize_connection(prof)


def test_authorize_missing_aws_cli_raises() -> None:
    """A missing aws CLI surfaces a clear error."""
    prof = ConnectionProfile(profile="iam", host="h", database="db", username="u", iam_auth=True)
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(RuntimeError, match="AWS CLI not found"):
            authorize_connection(prof)


def test_authorize_login_failure_raises() -> None:
    """A non-zero exit from aws sso login surfaces a clear error."""
    prof = ConnectionProfile(profile="iam", host="h", database="db", username="u", iam_auth=True)
    with patch("subprocess.run", side_effect=subprocess.CalledProcessError(2, ["aws"])):
        with pytest.raises(RuntimeError, match="exit code 2"):
            authorize_connection(prof)


def test_authorize_success_invokes_login_and_token() -> None:
    """A successful login runs aws sso login then generates a token to verify it."""
    prof = ConnectionProfile(
        profile="iam", host="h", database="db", username="u",
        iam_auth=True, aws_profile="sso",
    )
    fake = _mock_boto3()
    with patch("subprocess.run") as run, patch.dict("sys.modules", {"boto3": fake}):
        authorize_connection(prof)
    # aws sso login was invoked with the profile flag
    run.assert_called_once()
    cmd = run.call_args[0][0]
    assert cmd[:3] == ["aws", "sso", "login"]
    assert "--profile" in cmd and "sso" in cmd
    # token generation was attempted to validate the refreshed session
    fake.Session.return_value.client.return_value.generate_db_auth_token.assert_called_once()


# ---------------------------------------------------------------------------
# check_connection: reauth and password fallback (engine mocked — no real DB)
# ---------------------------------------------------------------------------

def _ok_engine() -> MagicMock:
    """Return a mock engine whose probe query returns a healthy row."""
    eng = MagicMock()
    conn = eng.connect.return_value.__enter__.return_value
    conn.execute.return_value.fetchone.return_value = ("dbuser", "PostgreSQL 16.2 on x86_64")
    return eng


def test_iam_failure_falls_back_to_password() -> None:
    """When IAM auth fails and a password is present, the connection falls back."""
    prof = ConnectionProfile(
        profile="iam", host="db.rds.amazonaws.com", database="app",
        username="dbuser", password=SecretStr("fallbackpw"),
        iam_auth=True, aws_region="us-east-1",
    )

    def engine(self):
        if self.iam_auth:
            raise OperationalError("SELECT 1", {}, Exception("PAM auth failed"))
        return _ok_engine()

    with patch.object(ConnectionProfile, "engine", engine):
        result = check_connection(prof, reauth=False)

    assert result.success is True
    assert prof.iam_auth is False  # flipped during fallback


def test_iam_failure_no_password_no_fallback() -> None:
    """An IAM-only profile (no password) returns a failed result, no fallback."""
    prof = ConnectionProfile(
        profile="iam", host="db.rds.amazonaws.com", database="app",
        username="dbuser", iam_auth=True, aws_region="us-east-1",
    )

    def engine(self):
        raise OperationalError("SELECT 1", {}, Exception("PAM auth failed"))

    with patch.object(ConnectionProfile, "engine", engine):
        result = check_connection(prof, reauth=False)

    assert result.success is False
    assert result.error is not None


def test_reauth_prompt_yes_triggers_authorize() -> None:
    """reauth=True with a 'y' answer re-authorizes, then retries successfully."""
    prof = ConnectionProfile(
        profile="iam", host="db.rds.amazonaws.com", database="app",
        username="dbuser", iam_auth=True, aws_region="us-east-1",
    )

    state = {"authorized": False}

    def engine(self):
        if not state["authorized"]:
            raise OperationalError("SELECT 1", {}, Exception("token expired"))
        return _ok_engine()

    def fake_authorize(p):
        state["authorized"] = True

    with patch.object(ConnectionProfile, "engine", engine), \
         patch("tarkin.credentials.authorize_connection", side_effect=fake_authorize) as auth, \
         patch("builtins.input", return_value="y"):
        result = check_connection(prof, reauth=True)

    auth.assert_called_once()
    assert result.success is True


def test_reauth_prompt_no_skips_authorize() -> None:
    """reauth=True with a 'n' answer does not re-authorize."""
    prof = ConnectionProfile(
        profile="iam", host="db.rds.amazonaws.com", database="app",
        username="dbuser", iam_auth=True, aws_region="us-east-1",
    )

    def engine(self):
        raise OperationalError("SELECT 1", {}, Exception("token expired"))

    with patch.object(ConnectionProfile, "engine", engine), \
         patch("tarkin.credentials.authorize_connection") as auth, \
         patch("builtins.input", return_value="n"):
        result = check_connection(prof, reauth=True)

    auth.assert_not_called()
    assert result.success is False


def test_reauth_not_attempted_for_password_profile() -> None:
    """A non-IAM profile never enters the reauth path even with reauth=True."""
    prof = ConnectionProfile(
        profile="pw", host="localhost", database="db",
        username="u", password=SecretStr("pw"),
    )

    def engine(self):
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    with patch.object(ConnectionProfile, "engine", engine), \
         patch("tarkin.credentials.authorize_connection") as auth, \
         patch("builtins.input") as inp:
        result = check_connection(prof, reauth=True)

    auth.assert_not_called()
    inp.assert_not_called()
    assert result.success is False


def _integration_profile() -> ConnectionProfile | None:
    """Build a ConnectionProfile from TARKIN_TEST_* env vars."""
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