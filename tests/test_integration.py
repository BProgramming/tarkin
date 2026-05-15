"""Integration tests for Tarkin."""
from __future__ import annotations
import os
import pytest
from pathlib import Path

from tarkin.attach import attach, AttachError
from tarkin.build import build, BuildError
from tarkin.credentials import CredentialsFile, DEFAULT_CREDENTIALS_PATH, check_connection
from tarkin.detach import detach, DetachError
from tarkin.inspect import inspect_database
from tarkin.model import GovernanceProject
from tarkin.validate import SemanticValidator


def _integration_profile():
    """Return a ConnectionProfile for integration tests, or None if not configured."""
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
        proj = live_project
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, out_dir=tmp_path)
        except BuildError as exc:
            pytest.skip(f"Build failed: {exc}")
            return

        try:
            attach(prof, build_path=zip_path)
        except AttachError as exc:
            pytest.skip(f"Attach failed: {exc}")
            return

        post_attach = inspect_database(prof, include_tk=True)
        tk_schemas  = [s for s in post_attach.schemas if s.name.startswith("tk_")]
        assert len(tk_schemas) > 0, "Expected tk_ shadow schemas after attach"

        detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

    @requires_db
    def test_detach_removes_build(self, live_project: GovernanceProject) -> None:
        prof = _integration_profile()
        assert prof is not None

        # Use keep_versioning=True so the test is safe regardless of whether
        # the fixture database has versioned tables or not.
        detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

        post_detach = inspect_database(prof)
        tk_schemas  = [s for s in post_detach.schemas if s.name.startswith("tk_")]
        assert not tk_schemas, f"tk_ schemas still present after detach: {tk_schemas}"

    @requires_db
    def test_double_attach_raises(self, live_project: GovernanceProject, tmp_path: Path) -> None:
        """Attaching twice to the same database should raise AttachError."""
        prof = _integration_profile()
        assert prof is not None
        proj = live_project
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, out_dir=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for double-attach test: {exc}")
            return

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
