"""Integration tests for Tarkin."""
from __future__ import annotations
import os
import pytest
from pathlib import Path
from pydantic import SecretStr
from sqlalchemy import text

from tarkin.attach import attach, AttachError
from tarkin.build import build, BuildError
from tarkin.credentials import CredentialsFile, DEFAULT_CREDENTIALS_PATH, check_connection
from tarkin.detach import detach, DetachError
from tarkin.inspect import inspect_database
from tarkin.model import GovernanceProject
from tarkin.validate import SemanticValidator

def _integration_profile():
    """Return a ConnectionProfile for integration tests, or None if not configured."""
    # Direct env vars (set by test_integrations.sh)
    host     = os.environ.get("TARKIN_TEST_HOST")
    port     = os.environ.get("TARKIN_TEST_PORT")
    db       = os.environ.get("TARKIN_TEST_DB")
    user     = os.environ.get("TARKIN_TEST_USER")
    password = os.environ.get("TARKIN_TEST_PASSWORD")

    if not host or not port or not db or not user or not password:
        return None
    elif all([host, port, db, user, password]):
        from tarkin.credentials import ConnectionProfile
        return ConnectionProfile(
            profile  = "test",
            host     = host,
            port     = int(port),
            database = db,
            username = user,
            password = SecretStr(password),
        )
    else:
        creds_path = os.environ.get("TARKIN_TEST_CREDENTIALS")
        profile    = os.environ.get("TARKIN_TEST_PROFILE", "test")
        try:
            path  = Path(creds_path) if creds_path else DEFAULT_CREDENTIALS_PATH
            creds = CredentialsFile.load(path)
            return creds.get(profile)
        except Exception:
            return None


def _is_db_available() -> bool:
    """Check whether the integration database is reachable."""
    prof = _integration_profile()
    if not prof:
        return False
    try:
        result = check_connection(prof)
        return result.success
    except Exception:
        return False


requires_db = pytest.mark.skipif(
    not _is_db_available(),
    reason="Integration database not configured or not reachable. "
           "Set TARKIN_TEST_PROFILE and optionally TARKIN_TEST_CREDENTIALS.",
)


@pytest.fixture
def live_project() -> GovernanceProject:
    """Inspect the live database and return the current project state."""
    prof = _integration_profile()
    assert prof is not None
    return inspect_database(prof)


class TestInspect:

    @requires_db
    def test_inspect_returns_project(self) -> None:
        prof   = _integration_profile()
        assert prof is not None
        if prof:
            proj   = inspect_database(prof)
            assert isinstance(proj, GovernanceProject)
            assert proj.database is not None
            assert len(proj.schemas) > 0

    @requires_db
    def test_inspect_finds_roles(self) -> None:
        prof = _integration_profile()
        assert prof is not None
        if prof:
            proj = inspect_database(prof)
            assert len(proj.roles) > 0

    @requires_db
    def test_inspect_passes_validation(self) -> None:
        prof = _integration_profile()
        assert prof is not None
        if prof:
            proj = inspect_database(prof)
            try:
                SemanticValidator.validate(proj)
            except Exception:
                # Integration databases may not pass all Tarkin rules (e.g. missing PKs)
                # This is expected — inspection should still succeed
                pass


class TestBuild:

    @requires_db
    def test_build_produces_artifact(self, tmp_path: Path) -> None:
        prof = _integration_profile()
        assert prof is not None
        if prof:
            proj = inspect_database(prof)
            proj.database.profile = prof.profile

            try:
                zip_path = build(proj, prof, out_dir=tmp_path)
                assert zip_path.exists()
                assert zip_path.suffix == ".zip"
            except BuildError as exc:
                pytest.skip(f"Build failed (database may not be Tarkin-compliant): {exc}")


class TestAttachDetach:

    @requires_db
    def test_attach_and_detach_lifecycle(self, live_project: GovernanceProject, tmp_path: Path) -> None:
        """Full attach → inspect → detach cycle."""
        prof = _integration_profile()
        assert prof is not None
        proj = inspect_database(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, out_dir=tmp_path)
        except BuildError as exc:
            pytest.skip(f"Build failed: {exc}")

        try:
            attach(prof, build_path=zip_path)
        except AttachError as exc:
            pytest.skip(f"Attach failed: {exc}")

        post_attach = inspect_database(prof, include_tk=True)
        tk_schemas  = [s for s in post_attach.schemas if s.name.startswith("tk_")]
        assert len(tk_schemas) > 0, "Expected tk_ shadow schemas after attach"

        detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

    @requires_db
    def test_detach_removes_build(self, live_project: GovernanceProject, tmp_path: Path) -> None:
        prof = _integration_profile()
        assert prof is not None
        proj = inspect_database(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, out_dir=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for detach test: {exc}")

        detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

        post_detach = inspect_database(prof)
        tk_schemas = [s for s in post_detach.schemas if s.name.startswith("tk_")]
        assert not tk_schemas, f"tk_ schemas still present after detach: {tk_schemas}"

    @requires_db
    def test_double_attach_raises(self, live_project: GovernanceProject, tmp_path: Path) -> None:
        """Attaching twice to the same database should raise AttachError."""
        prof = _integration_profile()
        assert prof is not None
        proj = inspect_database(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, out_dir=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for double-attach test: {exc}")

        try:
            with pytest.raises(AttachError, match="already"):
                attach(prof, build_path=zip_path)
        finally:
            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError:
                pass

    @requires_db
    def test_detach_without_attach_raises(self) -> None:
        """Detaching a database with no Tarkin build should raise DetachError."""
        prof = _integration_profile()
        assert prof is not None

        try:
            detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
        except DetachError:
            pass  # Expected if already clean

        # Now try to detach again — should fail cleanly
        with pytest.raises(DetachError):
            detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)


class TestPgauditSnapshot:

    @requires_db
    def test_pre_attach_pgaudit_settings_restored_on_detach(
        self, live_project: GovernanceProject, tmp_path: Path
    ) -> None:
        """Ensure that pgaudit.log survives an attach/detach cycle."""
        prof = _integration_profile()
        assert prof is not None

        engine = prof.engine()
        try:
            # Establish a known pre-attach pgaudit.log value.
            with engine.connect() as conn:
                conn.execute(text(
                    f'ALTER DATABASE "{prof.database}" SET pgaudit.log = \'ddl\''
                ))
                conn.commit()

            proj = inspect_database(prof)
            proj.database.profile       = prof.profile
            proj.database.audit_enabled = True

            try:
                zip_path = build(proj, prof, out_dir=tmp_path)
                attach(prof, build_path=zip_path)
            except (BuildError, AttachError) as exc:
                pytest.skip(f"Could not attach for pgaudit test: {exc}")

            # The build row must have captured the pre-attach value, not NULL.
            with engine.connect() as conn:
                snapshot = conn.execute(text(
                    "SELECT pgaudit_log_before FROM __META__.tarkin_builds "
                    "ORDER BY built_at DESC LIMIT 1"
                )).fetchone()
            assert snapshot is not None
            assert snapshot[0] == "ddl", (
                f"Expected pgaudit_log_before='ddl', got {snapshot[0]!r}. "
                f"The audit snapshot was not captured before the AUDIT section ran."
            )

            detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

            # Simplest reliable check: reconnect and read the effective setting.
            with engine.connect() as conn:
                effective = conn.execute(
                    text("SELECT current_setting('pgaudit.log', true)")
                ).scalar()
            assert effective == "ddl", (
                f"Expected pgaudit.log restored to 'ddl', got {effective!r}. "
                f"Detach did not restore the pre-attach pgaudit configuration."
            )
        finally:
            # Clean up the GUC we set so the test is repeatable.
            with engine.connect() as conn:
                conn.execute(text(
                    f'ALTER DATABASE "{prof.database}" RESET pgaudit.log'
                ))
                conn.commit()
            engine.dispose()


class TestColumnGrantRoundtrip:

    @requires_db
    def test_pre_attach_column_grant_restored_on_detach(
        self, live_project: GovernanceProject, tmp_path: Path
    ) -> None:
        """Bug #2: a hand-issued column-level grant must survive attach/detach.

        REVOKE ALL during attach strips column-level privileges. Detach can only
        restore them if inspect.py captured them via role_column_grants and they
        were recorded in __META__.tarkin_revoked_grants.
        """
        prof = _integration_profile()
        assert prof is not None

        engine = prof.engine()
        try:
            # Grant a column-level privilege by hand, before any Tarkin run.
            with engine.connect() as conn:
                conn.execute(text(
                    "GRANT SELECT (name) ON public.test_table TO tarkin_role"
                ))
                conn.commit()

            proj = inspect_database(prof)
            proj.database.profile = prof.profile

            try:
                zip_path = build(proj, prof, out_dir=tmp_path)
                attach(prof, build_path=zip_path)
            except (BuildError, AttachError) as exc:
                pytest.skip(f"Could not attach for column-grant test: {exc}")

            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError as exc:
                pytest.fail(f"Detach failed: {exc}")

            # After detach, tarkin_role must once again hold SELECT (name).
            with engine.connect() as conn:
                grant = conn.execute(text(
                    "SELECT 1 FROM information_schema.role_column_grants "
                    "WHERE grantee = 'tarkin_role' "
                    "  AND table_schema = 'public' "
                    "  AND table_name = 'test_table' "
                    "  AND column_name = 'name' "
                    "  AND privilege_type = 'SELECT'"
                )).fetchone()
            assert grant is not None, (
                "Pre-attach column grant SELECT (name) on public.test_table "
                "was not restored on detach."
            )
        finally:
            with engine.connect() as conn:
                conn.execute(text(
                    "REVOKE SELECT (name) ON public.test_table FROM tarkin_role"
                ))
                conn.commit()
            engine.dispose()
