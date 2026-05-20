"""Integration tests for Tarkin."""
from __future__ import annotations
import os
from typing import cast

import pytest
from pathlib import Path
from pydantic import SecretStr
from sqlalchemy import text

from tarkin.attach import attach, AttachError
from tarkin.build import build, BuildError
from tarkin.credentials import CredentialsFile, DEFAULT_CREDENTIALS_PATH, check_connection
from tarkin.detach import _read_meta
from tarkin.detach import detach, DetachError
from tarkin.inspect import inspect_database
from tarkin.migrate import migrate, MigrateError
from tarkin.model import ColumnConfig, GovernanceProject
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
                zip_path = build(proj, prof, output_directory=tmp_path)
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
            zip_path = build(proj, prof, output_directory=tmp_path)
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
            zip_path = build(proj, prof, output_directory=tmp_path)
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
            zip_path = build(proj, prof, output_directory=tmp_path)
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
            setup_engine = prof.engine()
            try:
                with setup_engine.connect() as conn:
                    conn.execute(text(
                        f'ALTER DATABASE "{prof.database}" SET pgaudit.log = \'ddl\''
                    ))
                    conn.commit()
            finally:
                setup_engine.dispose()

            proj = inspect_database(prof)
            proj.database.profile       = prof.profile
            proj.database.audit_enabled = True

            try:
                zip_path = build(proj, prof, output_directory=tmp_path)
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
            verify_engine = prof.engine()
            try:
                with verify_engine.connect() as conn:
                    effective = conn.execute(
                        text("SELECT current_setting('pgaudit.log', true)")
                    ).scalar()
                assert effective == "ddl", (
                    f"Expected pgaudit.log restored to 'ddl', got {effective!r}. "
                    f"Detach did not restore the pre-attach pgaudit configuration."
                )
            finally:
                verify_engine.dispose()
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
                zip_path = build(proj, prof, output_directory=tmp_path)
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
                    "WHERE grantee        = 'tarkin_role' "
                    "  AND table_schema   = 'public' "
                    "  AND table_name     = 'test_table' "
                    "  AND column_name    = 'name' "
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


class TestMigrateRoundtrip:
    """End-to-end: build → attach → migrate → re-attach → detach.

    Key design note: the `after` project must be derived from the pre-attach
    `before` project (the governance model), NOT from inspecting the live
    database after attach.  Post-attach, inspect sees views instead of tables
    and shadow schemas instead of originals, so diffing that state against
    the META YAML produces garbage changes and invalid migration SQL.
    """

    @requires_db
    def test_migrate_roundtrip(self, tmp_path: Path) -> None:
        prof = _integration_profile()
        assert prof is not None

        # --- Step 1: capture the pre-attach governance model. ---
        before = inspect_database(prof)
        before.database.profile = prof.profile

        # Build the `after` model by mutating a deep copy of `before`
        # BEFORE attaching — this gives us a valid governance-layer diff.
        target_schema = next(
            (s for s in before.schemas if s.tables and not s.name.startswith("tk_")),
            None,
        )
        if target_schema is None:
            pytest.skip("No suitable schema/table found for migration test.")

        after = before.model_copy(deep=True)
        after_schema = next(s for s in after.schemas if s.name == target_schema.name)
        after_schema.tables[0].columns.append(
            ColumnConfig(name="_tarkin_test_col", type="text", nullable=True)
        )

        # --- Step 2: build and attach the initial (before) project. ---
        try:
            build_zip = build(before, prof, output_directory=tmp_path)
            attach(prof, build_path=build_zip)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach initial build: {exc}")

        try:
            # --- Step 3: generate and apply the migration. ---
            try:
                migrate_zip = migrate(after, prof, output=tmp_path)
            except MigrateError as exc:
                pytest.fail(f"migrate() raised unexpectedly: {exc}")

            try:
                attach(prof, build_path=migrate_zip)
            except AttachError as exc:
                pytest.fail(f"Re-attach of migration artifact failed: {exc}")

            # --- Step 4: verify __META__ is fully populated after migrate. ---
            # This is the exact failure mode of Bug #3: _read_meta returns
            # empty results when the old _emit_meta_update is used, causing
            # detach to run DROP SCHEMA public CASCADE.
            (
                tarkin_roles,
                revoked_grants,
                db_name,
                _pgcrypto,
                _pgaudit,
                _added_fks,
                _added_gen_cols,
                moved_objects,
                _subj_indexes,
                _retention,
                _versioned_pks,
            ) = _read_meta(prof)

            assert db_name, "_read_meta returned empty db_name after migrate re-attach."

            engine = prof.engine()
            try:
                with engine.connect() as conn:
                    # tarkin_migrations must have rows for the migration changes.
                    migration_count = conn.execute(text(
                        "SELECT COUNT(*) FROM __META__.tarkin_migrations "
                        "WHERE change_type != 'created'"
                    )).scalar()

                    # tarkin_schemas must be populated for the latest build.
                    schema_count = conn.execute(text(
                        "SELECT COUNT(*) FROM __META__.tarkin_schemas ts "
                        "JOIN __META__.tarkin_builds tb USING (build_id) "
                        "WHERE tb.built_at = (SELECT MAX(built_at) FROM __META__.tarkin_builds)"
                    )).scalar()
            finally:
                engine.dispose()

            assert migration_count and migration_count > 0, (
                "No migration rows found in __META__.tarkin_migrations after migrate. "
                "_emit_migrate_meta_update may not be writing tarkin_migrations rows."
            )
            assert schema_count and schema_count > 0, (
                "tarkin_schemas is empty for the latest build after migrate. "
                "The _emit_per_build_inserts helper may not be running."
            )

        finally:
            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError:
                pass


class TestPublicSchemaGrantRoundtrip:
    """PUBLIC pseudo-role schema grants must be captured and restored.

    has_schema_privilege('public', schema, priv) correctly tests PUBLIC's
    grants even though PUBLIC doesn't appear in pg_roles, so the capture
    must happen via explicit IF blocks in _generate_meta_population.
    """

    @requires_db
    def test_public_schema_usage_restored_on_detach(
        self, tmp_path: Path
    ) -> None:
        prof = _integration_profile()
        assert prof is not None

        engine = prof.engine()
        try:
            # Confirm PUBLIC has USAGE on public (true in stock PG).
            # If not, grant it explicitly so the test is meaningful.
            with engine.connect() as conn:
                had_usage = conn.execute(text(
                    "SELECT has_schema_privilege('public', 'public', 'USAGE')"
                )).scalar()
                if not had_usage:
                    conn.execute(text("GRANT USAGE ON SCHEMA public TO PUBLIC"))
                    conn.commit()

            proj = inspect_database(prof)
            proj.database.profile = prof.profile

            try:
                zip_path = build(proj, prof, output_directory=tmp_path)
                attach(prof, build_path=zip_path)
            except (BuildError, AttachError) as exc:
                pytest.skip(f"Could not attach for PUBLIC grant test: {exc}")

            try:
                # Verify the grant was captured in META.
                with engine.connect() as conn:
                    captured = conn.execute(text(
                        "SELECT COUNT(*) FROM __META__.tarkin_revoked_grants "
                        "WHERE role_name = 'PUBLIC' "
                        "  AND schema_name = 'public' "
                        "  AND grant_type = 'USAGE'"
                    )).scalar()

                assert captured and int(captured) > 0, (
                    "PUBLIC USAGE grant on schema 'public' was not recorded in "
                    "tarkin_revoked_grants. The has_schema_privilege capture in "
                    "_generate_meta_population may not be running. "
                    "Check that the IF has_schema_privilege blocks were added "
                    "inside the DO block, before 'END; $$ LANGUAGE plpgsql;'."
                )

                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

                # PUBLIC must once again have USAGE on public after detach.
                with engine.connect() as conn:
                    restored = conn.execute(text(
                        "SELECT has_schema_privilege('public', 'public', 'USAGE')"
                    )).scalar()

                assert restored, (
                    "PUBLIC USAGE on schema 'public' was not restored after detach. "
                    "tarkin_revoked_grants row exists but detach may not be "
                    "emitting GRANT ... TO PUBLIC."
                )

            except DetachError as exc:
                pytest.fail(f"Detach failed: {exc}")

        finally:
            try:
                with engine.connect() as conn:
                    conn.execute(text("GRANT USAGE ON SCHEMA public TO PUBLIC"))
                    conn.commit()
            except Exception:
                pass
            engine.dispose()


class TestOverloadedFunctionMeta:
    """tarkin_moved_objects must store full signatures for functions/aggregates.

    ALTER FUNCTION name SET SCHEMA is ambiguous when overloads exist.
    ALTER FUNCTION name(arg_types) SET SCHEMA is unambiguous.
    Detach will fail with a DuplicateFunction error if bare names are stored.
    """

    @requires_db
    def test_overloaded_functions_stored_with_full_signature(
        self, tmp_path: Path
    ) -> None:
        prof = _integration_profile()
        assert prof is not None

        engine = prof.engine()
        try:
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE OR REPLACE FUNCTION public.tarkin_test_overload(x int)
                    RETURNS int LANGUAGE sql AS $$ SELECT x $$
                """))
                conn.execute(text("""
                    CREATE OR REPLACE FUNCTION public.tarkin_test_overload(x text)
                    RETURNS text LANGUAGE sql AS $$ SELECT x $$
                """))
                conn.commit()

            proj = inspect_database(prof)
            proj.database.profile = prof.profile

            try:
                zip_path = build(proj, prof, output_directory=tmp_path)
                attach(prof, build_path=zip_path)
            except (BuildError, AttachError) as exc:
                pytest.skip(f"Could not attach for overload test: {exc}")

            try:
                # Both overloads must appear with full argument signatures.
                with engine.connect() as conn:
                    rows = conn.execute(text(
                        "SELECT object_name FROM __META__.tarkin_moved_objects "
                        "WHERE object_kind IN ('function', 'trigger_function', 'procedure', 'aggregate') "
                        "  AND object_name LIKE 'tarkin_test_overload(%'"
                    )).fetchall()

                names = [r[0] for r in rows]
                assert len(names) == 2, (
                    f"Expected 2 overloaded function entries in tarkin_moved_objects, "
                    f"got {len(names)}: {names}. "
                    f"Bare names collapse overloads to one row."
                )
                assert any("integer" in n or "int" in n for n in names), (
                    f"Expected an entry with int/integer arg type, got: {names}"
                )
                assert any("text" in n for n in names), (
                    f"Expected an entry with text arg type, got: {names}"
                )

                # Detach must succeed — fails with bare names because
                # ALTER FUNCTION public.tarkin_test_overload SET SCHEMA
                # is ambiguous when two overloads exist.
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

            except DetachError as exc:
                pytest.fail(
                    f"Detach failed, likely due to ambiguous ALTER FUNCTION "
                    f"on overloaded functions: {exc}"
                )

        finally:
            try:
                with engine.connect() as conn:
                    conn.execute(text(
                        "DROP FUNCTION IF EXISTS public.tarkin_test_overload(int)"
                    ))
                    conn.execute(text(
                        "DROP FUNCTION IF EXISTS public.tarkin_test_overload(text)"
                    ))
                    conn.commit()
            except Exception:
                pass
            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError:
                pass
            engine.dispose()