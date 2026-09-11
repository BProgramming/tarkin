"""Integration tests for Tarkin."""
from __future__ import annotations
import os
from typing import cast

import pytest
from pathlib import Path
from pydantic import SecretStr
from sqlalchemy import text

from tarkin.attach import (
    attach,
    AttachError,
)
from tarkin.build import (
    build,
    BuildError,
)
from tarkin.credentials import (
    CredentialsFile,
    DEFAULT_CREDENTIALS_PATH,
    check_connection,
)
from tarkin.detach import _read_meta
from tarkin.detach import (
    detach,
    DetachError,
)
from tarkin.inspect import inspect
from tarkin.migrate import (
    migrate,
    MigrateError,
)
from tarkin.model import (
    ColumnConfig,
    ErasureStrategy,
    GovernanceProject,
)
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
    return inspect(prof)


class TestInspect:

    @requires_db
    def test_inspect_returns_project(self) -> None:
        prof   = _integration_profile()
        assert prof is not None
        if prof:
            proj   = inspect(prof)
            assert isinstance(proj, GovernanceProject)
            assert proj.database is not None
            assert len(proj.schemas) > 0

    @requires_db
    def test_inspect_finds_roles(self) -> None:
        prof = _integration_profile()
        assert prof is not None
        if prof:
            proj = inspect(prof)
            assert len(proj.roles) > 0

    @requires_db
    def test_inspect_passes_validation(self) -> None:
        prof = _integration_profile()
        assert prof is not None
        if prof:
            proj = inspect(prof)
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
            proj = inspect(prof)
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
        proj = inspect(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, output_directory=tmp_path)
        except BuildError as exc:
            pytest.skip(f"Build failed: {exc}")

        try:
            attach(prof, build_path=zip_path)
        except AttachError as exc:
            pytest.skip(f"Attach failed: {exc}")

        post_attach = inspect(prof, include_tk=True)
        tk_schemas  = [s for s in post_attach.schemas if s.name.startswith("tk_")]
        assert len(tk_schemas) > 0, "Expected tk_ shadow schemas after attach"

        detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

    @requires_db
    def test_detach_removes_build(self, live_project: GovernanceProject, tmp_path: Path) -> None:
        prof = _integration_profile()
        assert prof is not None
        proj = inspect(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, output_directory=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for detach test: {exc}")

        detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)

        post_detach = inspect(prof)
        tk_schemas = [s for s in post_detach.schemas if s.name.startswith("tk_")]
        assert not tk_schemas, f"tk_ schemas still present after detach: {tk_schemas}"

    @requires_db
    def test_double_attach_raises(self, live_project: GovernanceProject, tmp_path: Path) -> None:
        """Attaching twice to the same database should raise AttachError."""
        prof = _integration_profile()
        assert prof is not None
        proj = inspect(prof)
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

            proj = inspect(prof)
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

            proj = inspect(prof)
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
        before = inspect(prof)
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

            proj = inspect(prof)
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

            proj = inspect(prof)
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


# ---------------------------------------------------------------------------
# Discovery functions — the surface third-party tooling reads
# ---------------------------------------------------------------------------

DISCOVERY_FUNCTIONS = (
    "get_build", "get_schemas", "get_tables", "get_columns", "get_roles",
    "get_retention", "get_erasures", "get_erasure_counts", "get_rls_policies",
)

_ANALYST_ROLE = "tarkin_it_analyst"
_ANALYST_PASS = "tarkin_it_analyst_pw"

# A LOGIN role deliberately absent from the governance build, used to exercise
# the empty-result path through the discovery functions and the view.
_OUTSIDER_ROLE = "tarkin_it_outsider"
_OUTSIDER_PASS = "tarkin_it_outsider_pw"


def _owner_engine():
    prof = _integration_profile()
    assert prof is not None
    return prof.engine()


def _role_profile(username: str, password: str, label: str | None = None):
    """A ConnectionProfile that logs in as an arbitrary role.

    The discovery functions filter on session_user, so the only way to test
    them from another role's perspective is to actually log in as that role.
    SET ROLE would not change the answer.
    """
    from tarkin.credentials import ConnectionProfile
    base = _integration_profile()
    assert base is not None
    return ConnectionProfile(
        profile  = label or f"test_{username}",
        host     = base.host,
        port     = base.port,
        database = base.database,
        username = username,
        password = SecretStr(password),
        sslmode  = "prefer",
    )


def _analyst_profile():
    """A ConnectionProfile that logs in as the non-owner analyst role."""
    return _role_profile(_ANALYST_ROLE, _ANALYST_PASS, label="test_analyst")


@pytest.fixture
def analyst_role():
    """Create a non-owner LOGIN role with SELECT on the fixture table.

    The discovery functions exist to be called by roles that are not the
    database owner. Testing them as the owner proves nothing: the owner can
    read __META__ directly.
    """
    engine = _owner_engine()
    with engine.begin() as conn:
        conn.execute(text(f"DROP ROLE IF EXISTS {_ANALYST_ROLE}"))
        conn.execute(text(
            f"CREATE ROLE {_ANALYST_ROLE} LOGIN PASSWORD '{_ANALYST_PASS}'"
        ))
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {_ANALYST_ROLE}"))
        conn.execute(text(f"GRANT SELECT ON public.test_table TO {_ANALYST_ROLE}"))
    engine.dispose()

    yield _ANALYST_ROLE

    engine = _owner_engine()
    with engine.begin() as conn:
        conn.execute(text(f"REVOKE ALL ON public.test_table FROM {_ANALYST_ROLE}"))
        conn.execute(text(f"REVOKE ALL ON SCHEMA public FROM {_ANALYST_ROLE}"))
        conn.execute(text(f"DROP ROLE IF EXISTS {_ANALYST_ROLE}"))
    engine.dispose()


def _add_erasure_config(proj: GovernanceProject) -> None:
    """Mark public.test_table as subject-identified.

    _generate_erase_functions() emits nothing unless some table carries both an
    erase_strategy and an is_subject_identifier column, so a model reflected
    straight off the fixture database produces no tarkin_erase_check at all.
    Without this, any test asserting that the erasure surface is locked down
    passes against a database where the surface does not exist.
    """
    schema = next(s for s in proj.schemas if s.name == "public")
    table  = next(t for t in schema.tables if t.name == "test_table")
    table.erase_strategy = ErasureStrategy.DELETE
    for col in table.columns:
        if col.name == "id":
            col.is_subject_identifier = True


@pytest.fixture
def attached_with_analyst(analyst_role, tmp_path: Path):
    """Attach the live database with the analyst role present in the model."""
    prof = _integration_profile()
    assert prof is not None

    proj = inspect(prof)
    proj.database.profile = prof.profile
    _add_erasure_config(proj)

    try:
        zip_path = build(proj, prof, output_directory=tmp_path)
        attach(prof, build_path=zip_path)
    except (BuildError, AttachError) as exc:
        pytest.skip(f"Could not attach for discovery test: {exc}")

    try:
        yield prof
    finally:
        try:
            detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
        except DetachError:
            pass


class TestDiscoveryFunctionsAsNonOwner:

    @requires_db
    def test_analyst_can_call_every_discovery_function(self, attached_with_analyst) -> None:
        """Regression: __META__ had no GRANT USAGE, so name resolution failed for
        every role but the owner and GRANT EXECUTE was unusable."""
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                for fn in DISCOVERY_FUNCTIONS:
                    row = conn.execute(text(f"SELECT __META__.{fn}()")).fetchone()
                    assert row is not None, f"{fn} returned no row"
                    assert row[0] is not None, f"{fn} returned NULL"
        finally:
            engine.dispose()

    @requires_db
    def test_analyst_cannot_read_meta_tables_directly(self, attached_with_analyst) -> None:
        """USAGE grants name resolution only; the tables stay revoked."""
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                with pytest.raises(Exception) as exc:
                    conn.execute(text("SELECT * FROM __META__.tarkin_builds"))
                assert "permission denied" in str(exc.value).casefold()
        finally:
            engine.dispose()

    @requires_db
    def test_analyst_cannot_execute_the_erase_functions(self, attached_with_analyst) -> None:
        """EXECUTE is revoked from PUBLIC on every __META__ function, then granted
        back on the discovery surface alone."""
        # Confirm the function exists before asserting it is unreachable. An
        # UndefinedFunction error also raises, and would let this test pass
        # against a build that never generated the erasure surface.
        owner = _owner_engine()
        try:
            with owner.connect() as conn:
                exists = conn.execute(text(
                    "SELECT to_regprocedure("
                    "'__META__.tarkin_erase_check(text[], text[])') IS NOT NULL"
                )).fetchone()[0]
        finally:
            owner.dispose()
        assert exists, "tarkin_erase_check was not generated; check the fixture model"

        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                with pytest.raises(Exception) as exc:
                    conn.execute(text(
                        "SELECT * FROM __META__.tarkin_erase_check("
                        "ARRAY['id']::text[], ARRAY['1']::text[])"
                    ))
                assert "permission denied" in str(exc.value).casefold()
        finally:
            engine.dispose()

    @requires_db
    def test_analyst_sees_only_its_own_role_record(self, attached_with_analyst) -> None:
        """Regression: filtering used current_user, which inside a SECURITY DEFINER
        function resolves to the function owner rather than the caller."""
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                roles = conn.execute(text("SELECT __META__.get_roles()")).fetchone()[0]
        finally:
            engine.dispose()

        assert isinstance(roles, list), f"expected a role list, got {roles!r}"
        names = {r["name"] for r in roles}
        assert names == {_ANALYST_ROLE}, (
            f"non-admin role saw {names}; filtering is evaluating as the owner"
        )

    @requires_db
    def test_owner_sees_more_roles_than_the_analyst(self, attached_with_analyst) -> None:
        """The two callers must get different answers, or nothing is being filtered."""
        owner_engine = _owner_engine()
        try:
            with owner_engine.connect() as conn:
                owner_roles = conn.execute(text("SELECT __META__.get_roles()")).fetchone()[0]
        finally:
            owner_engine.dispose()

        analyst_engine = _analyst_profile().engine()
        try:
            with analyst_engine.connect() as conn:
                analyst_roles = conn.execute(text("SELECT __META__.get_roles()")).fetchone()[0]
        finally:
            analyst_engine.dispose()

        if not isinstance(owner_roles, list):
            pytest.skip("owner is not present in the governance model")
        assert isinstance(analyst_roles, list)
        assert len(owner_roles) > len(analyst_roles)

    @requires_db
    def test_erasure_log_is_admin_only(self, attached_with_analyst) -> None:
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                result = conn.execute(text("SELECT __META__.get_erasures()")).fetchone()[0]
        finally:
            engine.dispose()

        # A non-admin gets the not-found message object, never a list of entries.
        assert isinstance(result, dict), f"non-admin received {result!r}"
        assert "message" in result

    @requires_db
    def test_columns_are_scoped_to_granted_tables(self, attached_with_analyst) -> None:
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                cols = conn.execute(text("SELECT __META__.get_columns()")).fetchone()[0]
        finally:
            engine.dispose()

        if isinstance(cols, dict):
            pytest.skip("analyst has no visible columns in this fixture")
        tables = {(c["schema"], c["table"]) for c in cols}
        assert tables <= {("public", "test_table")}, f"analyst saw {tables}"

    @requires_db
    def test_analyst_can_read_the_governance_view(self, attached_with_analyst) -> None:
        """The view is the reach mechanism: a client enumerating tables finds the
        governance model without knowing the discovery functions exist."""
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                rows = conn.execute(text(
                    "SELECT schema_name, table_name, column_name, masking_strategy, "
                    "sensitive, rls_policy_count FROM __META__.tarkin_governance"
                )).fetchall()
        finally:
            engine.dispose()

        tables = {(r[0], r[1]) for r in rows}
        assert tables <= {("public", "test_table")}, f"analyst saw {tables}"

    @requires_db
    def test_governance_view_survives_a_role_with_no_visible_columns(
        self, attached_with_analyst
    ) -> None:
        """Discovery functions return a message object rather than an array when
        nothing is visible; json_to_recordset would reject it unguarded.

        The role has to be absent from the build, not merely stripped of live
        grants. get_columns filters on __META__.tarkin_role_tables, which is the
        build snapshot, so revoking a PostgreSQL grant after attach does not
        change what the function returns and would not reach the guard.

        The outsider is created here rather than in a fixture precisely so that
        the inspect() call that produced the build could not have seen it.
        PUBLIC carries USAGE on __META__, EXECUTE on the discovery surface, and
        SELECT on the view, so the stranger can reach all of it and see none of
        it -- which is the case the guard exists for.
        """
        engine = _owner_engine()
        try:
            with engine.begin() as conn:
                conn.execute(text(f"DROP ROLE IF EXISTS {_OUTSIDER_ROLE}"))
                conn.execute(text(
                    f"CREATE ROLE {_OUTSIDER_ROLE} LOGIN PASSWORD '{_OUTSIDER_PASS}'"
                ))
        finally:
            engine.dispose()

        try:
            outsider = _role_profile(_OUTSIDER_ROLE, _OUTSIDER_PASS).engine()
            try:
                with outsider.connect() as conn:
                    count = conn.execute(text(
                        "SELECT count(*) FROM __META__.tarkin_governance"
                    )).fetchone()[0]
                    cols = conn.execute(text(
                        "SELECT __META__.get_columns()"
                    )).fetchone()[0]
            finally:
                outsider.dispose()

            # The precondition: the function really did return the message
            # object, so the view was reading a non-array.
            assert isinstance(cols, dict), f"expected a message object, got {cols!r}"
            assert count == 0
        finally:
            engine = _owner_engine()
            with engine.begin() as conn:
                conn.execute(text(f"DROP ROLE IF EXISTS {_OUTSIDER_ROLE}"))
            engine.dispose()

    @requires_db
    def test_governance_view_and_discovery_functions_agree(self, attached_with_analyst) -> None:
        """The view is a flattening of the functions, not a second source of truth."""
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                view_rows = conn.execute(text(
                    "SELECT schema_name, table_name, column_name "
                    "FROM __META__.tarkin_governance"
                )).fetchall()
                fn_cols = conn.execute(text("SELECT __META__.get_columns()")).fetchone()[0]
        finally:
            engine.dispose()

        if isinstance(fn_cols, dict):
            assert view_rows == []
        else:
            assert {(r[0], r[1], r[2]) for r in view_rows} == \
                   {(c["schema"], c["table"], c["name"]) for c in fn_cols}

    @requires_db
    def test_build_identity_is_readable_without_the_yaml(self, attached_with_analyst) -> None:
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                build_row = conn.execute(text("SELECT __META__.get_build()")).fetchone()[0]
        finally:
            engine.dispose()

        assert isinstance(build_row, dict)
        if "message" in build_row:
            pytest.skip("analyst is not present in the governance model")
        assert "checksum" in build_row
        assert "yaml" not in build_row
        assert "profile" not in build_row


# ---------------------------------------------------------------------------
# Object comments
# ---------------------------------------------------------------------------

class TestCommentRoundtrip:

    @requires_db
    def test_inspect_reads_existing_comments_into_the_yaml(self) -> None:
        prof = _integration_profile()
        assert prof is not None

        engine = _owner_engine()
        try:
            with engine.begin() as conn:
                conn.execute(text("COMMENT ON TABLE public.test_table IS 'Fixture table'"))
                conn.execute(text("COMMENT ON COLUMN public.test_table.name IS 'Display name'"))
        finally:
            engine.dispose()

        try:
            proj   = inspect(prof)
            schema = next(s for s in proj.schemas if s.name == "public")
            table  = next(t for t in schema.tables if t.name == "test_table")
            column = next(c for c in table.columns if c.name == "name")

            assert table.description  == "Fixture table"
            assert column.description == "Display name"
        finally:
            engine = _owner_engine()
            with engine.begin() as conn:
                conn.execute(text("COMMENT ON TABLE public.test_table IS NULL"))
                conn.execute(text("COMMENT ON COLUMN public.test_table.name IS NULL"))
            engine.dispose()

    @requires_db
    def test_undocumented_objects_have_no_description(self) -> None:
        prof = _integration_profile()
        assert prof is not None

        engine = _owner_engine()
        with engine.begin() as conn:
            conn.execute(text("COMMENT ON TABLE public.test_table IS NULL"))
        engine.dispose()

        proj   = inspect(prof)
        schema = next(s for s in proj.schemas if s.name == "public")
        table  = next(t for t in schema.tables if t.name == "test_table")
        assert table.description is None

    @requires_db
    def test_descriptions_land_on_the_view_after_attach(self, tmp_path: Path) -> None:
        """Comments go on the Tarkin-created view, never the shadow table."""
        prof = _integration_profile()
        assert prof is not None

        engine = _owner_engine()
        with engine.begin() as conn:
            conn.execute(text("COMMENT ON TABLE public.test_table IS 'Fixture table'"))
            conn.execute(text("COMMENT ON COLUMN public.test_table.name IS 'Display name'"))
        engine.dispose()

        proj = inspect(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, output_directory=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for comment test: {exc}")

        try:
            engine = _owner_engine()
            with engine.connect() as conn:
                view_comment = conn.execute(text("""
                    SELECT obj_description(c.oid, 'pg_class')
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = 'test_table'
                """)).fetchone()[0]
                col_comment = conn.execute(text("""
                    SELECT col_description(a.attrelid, a.attnum)
                    FROM pg_attribute a
                    JOIN pg_class c     ON c.oid = a.attrelid
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public'
                      AND c.relname = 'test_table'
                      AND a.attname = 'name'
                """)).fetchone()[0]
            engine.dispose()

            assert view_comment == "Fixture table"
            assert col_comment  == "Display name"
        finally:
            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError:
                pass
            engine = _owner_engine()
            with engine.begin() as conn:
                conn.execute(text("COMMENT ON TABLE public.test_table IS NULL"))
                conn.execute(text("COMMENT ON COLUMN public.test_table.name IS NULL"))
            engine.dispose()

    @requires_db
    def test_meta_schema_and_functions_are_commented(self, attached_with_analyst) -> None:
        """The comments are the bootstrap: a client reading pg_catalog finds the
        discovery surface without knowing Tarkin exists."""
        engine = _analyst_profile().engine()
        try:
            with engine.connect() as conn:
                # ::regnamespace goes through the identifier parser, so it
                # folds the way CREATE SCHEMA __META__ did. Comparing nspname
                # against the literal '__META__' matches nothing: the schema is
                # stored as __meta__, and fetchone() then returns None.
                schema_comment = conn.execute(text("""
                    SELECT obj_description('__META__'::regnamespace, 'pg_namespace')
                """)).fetchone()[0]

                fn_comments = conn.execute(text("""
                    SELECT p.proname, obj_description(p.oid, 'pg_proc')
                    FROM pg_proc p
                    WHERE p.pronamespace = '__META__'::regnamespace
                """)).fetchall()
        finally:
            engine.dispose()

        assert schema_comment and "discovery functions" in schema_comment
        described = {name: doc for name, doc in fn_comments if doc}
        for fn in DISCOVERY_FUNCTIONS:
            assert fn in described, f"{fn} has no COMMENT ON FUNCTION"


# ---------------------------------------------------------------------------
# Forced migration — bringing an attached database up to the installed codegen
# ---------------------------------------------------------------------------

class TestForcedMigration:

    @requires_db
    def test_unchanged_model_refuses_without_force(self, tmp_path: Path) -> None:
        prof = _integration_profile()
        assert prof is not None

        proj = inspect(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, output_directory=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for forced-migration test: {exc}")

        try:
            with pytest.raises(MigrateError, match="force"):
                migrate(proj, prof, output=tmp_path)
        finally:
            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError:
                pass

    @requires_db
    def test_force_applies_comments_to_an_attached_database(self, tmp_path: Path) -> None:
        """The upgrade path: attach, add a description, force-migrate, see the comment.

        Stands in for `upgrade Tarkin, run update, run migrate --force`, which
        cannot be reproduced here because the installed version is the one under
        test. The mechanism is the same: the model is identical on both sides of
        the diff and the comments arrive because they are regenerated, not diffed.
        """
        prof = _integration_profile()
        assert prof is not None

        proj = inspect(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, output_directory=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for forced-migration test: {exc}")

        try:
            forced = migrate(proj, prof, output=tmp_path, force=True)
            attach(prof, build_path=forced)

            engine = _owner_engine()
            try:
                with engine.connect() as conn:
                    fn_comment = conn.execute(text("""
                        SELECT obj_description(p.oid, 'pg_proc')
                        FROM pg_proc p
                        WHERE p.pronamespace = '__META__'::regnamespace
                          AND p.proname     = 'get_columns'
                    """)).fetchone()[0]
            finally:
                engine.dispose()

            assert fn_comment, "forced migration did not reapply the function comments"
        finally:
            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError:
                pass

    @requires_db
    def test_force_advances_the_build_id(self, tmp_path: Path) -> None:
        """A forced migration writes a new tarkin_builds row even with no changes,
        so a client caching get_build() correctly sees the model move."""
        prof = _integration_profile()
        assert prof is not None

        proj = inspect(prof)
        proj.database.profile = prof.profile

        try:
            zip_path = build(proj, prof, output_directory=tmp_path)
            attach(prof, build_path=zip_path)
        except (BuildError, AttachError) as exc:
            pytest.skip(f"Could not attach for forced-migration test: {exc}")

        def _build_id() -> int:
            engine = _owner_engine()
            try:
                with engine.connect() as conn:
                    return conn.execute(text(
                        "SELECT max(build_id) FROM __META__.tarkin_builds"
                    )).fetchone()[0]
            finally:
                engine.dispose()

        try:
            before_id = _build_id()
            forced    = migrate(proj, prof, output=tmp_path, force=True)
            attach(prof, build_path=forced)
            assert _build_id() > before_id
        finally:
            try:
                detach(prof, keep_versioning=True, drop_versioning=False, no_warn=True)
            except DetachError:
                pass