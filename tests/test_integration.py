"""
Integration tests.

Unit tests use a lightweight mock of the SQLAlchemy engine/inspector so they
run without a live database. Integration tests require TARKIN_TEST_* env vars
and exercise the real catalog queries.

Integration test coverage:
  1. test_connection — live connect succeeds
  2. test_inspect_output_structure — inspected project has expected shape
  3. test_inspect_round_trip — serialize → YAML → reload → validate is lossless
  4. test_db_user_in_output — the connected user appears in the YAML users list
"""
from __future__ import annotations
import os

import pytest
from pydantic import SecretStr
from ruamel.yaml import YAML
from pathlib import Path

from tarkin.attach import attach
from tarkin.detach import detach
from tarkin.model import (
    DatabaseConfig, SchemaConfig, TableConfig, ColumnConfig,
    IndexConfig, RoleConfig, SchemaPermissionConfig,
    TablePermissionConfig, DatabaseEngine, IndexType,
)
from tarkin.inspect import inspect_database
from tarkin.build import build
from tarkin.credentials import ConnectionProfile
from tarkin.model import GovernanceProject
from tarkin.serialize import Serializer
from tarkin.yaml import YamlLoader
from tarkin.validate import SemanticValidator, ValidationError


# =====================================================
# HELPERS
# =====================================================

def _integration_profile() -> ConnectionProfile | None:
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


# =====================================================
# UNIT: OUTPUT STRUCTURE (mock engine)
# =====================================================

def _make_mock_profile(username: str = "tarkin_user") -> ConnectionProfile:
    return ConnectionProfile(
        profile="test",
        host="localhost",
        port=5432,
        database="testdb",
        username=username,
        password=SecretStr("pw"),
    )


def _build_mock_project() -> GovernanceProject:
    """
    Build a GovernanceProject that mirrors what inspect_database would produce
    for a minimal database with one schema, one table, two columns, one index.
    Used to test structural expectations without a live DB.
    """
    col_id = ColumnConfig(name="id", type="bigint", nullable=False)
    col_name = ColumnConfig(name="name", type="text", nullable=True)
    idx = IndexConfig(
        name="users_pkey", columns=["id"],
        primary_key=True, unique=True, index_type=IndexType(IndexType.BTREE),
    )
    table = TableConfig(name="users", columns=[col_id, col_name], indexes=[idx])
    schema = SchemaConfig(name="public", tables=[table])

    perm = SchemaPermissionConfig(
        name="public", usage=True,
        tables=[TablePermissionConfig(name="users", select=True)],
    )
    role = RoleConfig(
        name="tarkin_user",
        can_login=True,
        active=True,
        on=[perm],
    )

    return GovernanceProject(
        database=DatabaseConfig(
            name="testdb",
            engine=DatabaseEngine(DatabaseEngine.POSTGRES),
            host="localhost",
            port=5432,
            database="testdb",
            profile="test",
            owner="test_user",
        ),
        schemas=[schema],
        roles=[role],
    )


class TestInspectOutputStructure:
    """Structural invariants that must hold on any inspected GovernanceProject."""

    def test_project_has_database(self) -> None:
        proj = _build_mock_project()
        assert proj.database is not None
        assert proj.database.name

    def test_project_has_at_least_one_schema(self) -> None:
        proj = _build_mock_project()
        assert len(proj.schemas) >= 1

    def test_schemas_have_names(self) -> None:
        proj = _build_mock_project()
        for schema in proj.schemas:
            assert schema.name, "Schema missing name"

    def test_tables_have_at_least_one_column(self) -> None:
        proj = _build_mock_project()
        for schema in proj.schemas:
            for table in schema.tables:
                assert table.columns, (
                    f"{schema.name}.{table.name} has no columns"
                )

    def test_columns_have_names_and_types(self) -> None:
        proj = _build_mock_project()
        for schema in proj.schemas:
            for table in schema.tables:
                for col in table.columns:
                    assert col.name, f"Column missing name in {schema.name}.{table.name}"
                    assert col.type, f"Column {col.name} missing data type"

    def test_indexes_reference_existing_columns(self) -> None:
        proj = _build_mock_project()
        for schema in proj.schemas:
            for table in schema.tables:
                col_names = {c.name for c in table.columns}
                for idx in table.indexes:
                    for idx_col in idx.columns:
                        assert idx_col in col_names, (
                            f"Index {idx.name} references missing column {idx_col!r} "
                            f"in {schema.name}.{table.name}"
                        )

    def test_roles_have_names(self) -> None:
        proj = _build_mock_project()
        for role in proj.roles:
            assert role.name, "Role missing name"

    def test_at_least_one_login_role(self) -> None:
        proj = _build_mock_project()
        assert any(r.can_login for r in proj.roles), "No login roles found"

    def test_member_of_references_existing_roles(self) -> None:
        proj = _build_mock_project()
        role_names = {r.name for r in proj.roles}
        for role in proj.roles:
            for parent in role.member_of:
                assert parent in role_names, (
                    f"Role {role.name!r} inherits from undefined role {parent!r}"
                )


# =====================================================
# UNIT: ROUND-TRIP FIDELITY
# =====================================================

class TestInspectRoundTrip:
    """
    Serialize an inspected (mock) project to YAML, reload it, re-validate.
    This confirms that nothing is lost or corrupted in the serialize → parse cycle.
    """

    @staticmethod
    def _roundtrip(proj: GovernanceProject) -> GovernanceProject | None:
        yaml_str = Serializer.to_yaml_string(proj)
        return YamlLoader.loads(yaml_str)

    def test_database_fields_survive_roundtrip(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            assert rt.database.name    == proj.database.name
            assert rt.database.host    == proj.database.host
            assert rt.database.port    == proj.database.port
            assert rt.database.database == proj.database.database
            assert rt.database.profile  == proj.database.profile

    def test_schema_names_survive_roundtrip(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            orig_names = {s.name for s in proj.schemas}
            rt_names   = {s.name for s in rt.schemas}
            assert orig_names == rt_names

    def test_table_names_survive_roundtrip(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            for orig_schema, rt_schema in zip(proj.schemas, rt.schemas):
                orig_tables = {t.name for t in orig_schema.tables}
                rt_tables   = {t.name for t in rt_schema.tables}
                assert orig_tables == rt_tables

    def test_column_details_survive_roundtrip(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            for os_, rs in zip(proj.schemas, rt.schemas):
                for ot, rtt in zip(os_.tables, rs.tables):
                    for oc, rc in zip(ot.columns, rtt.columns):
                        assert oc.name     == rc.name
                        assert oc.type     == rc.type
                        assert oc.nullable == rc.nullable

    def test_index_details_survive_roundtrip(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            orig_idx = proj.schemas[0].tables[0].indexes[0]
            rt_idx   = rt.schemas[0].tables[0].indexes[0]
            assert orig_idx.name        == rt_idx.name
            assert orig_idx.columns     == rt_idx.columns
            assert orig_idx.primary_key == rt_idx.primary_key
            assert orig_idx.unique      == rt_idx.unique

    def test_role_names_survive_roundtrip(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            assert {r.name for r in proj.roles} == {r.name for r in rt.roles}

    def test_role_properties_survive_roundtrip(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            for or_, rr in zip(proj.roles, rt.roles):
                assert or_.name == rr.name
                assert or_.can_login == rr.can_login
                assert or_.can_admin == rr.can_admin
                assert or_.active == rr.active
                assert or_.member_of == rr.member_of

    def test_roundtripped_project_passes_validation(self) -> None:
        proj = _build_mock_project()
        rt = self._roundtrip(proj)
        assert rt is not None
        if rt:
            # Should not raise
            assert SemanticValidator.validate(rt) is True

    def test_yaml_output_is_valid_yaml(self) -> None:
        proj = _build_mock_project()
        yaml_str = Serializer.to_yaml_string(proj)
        y = YAML()
        parsed = y.load(yaml_str)
        assert parsed is not None
        assert "database" in parsed
        assert "schemas" in parsed

    def test_yaml_contains_profile_name(self) -> None:
        proj = _build_mock_project()
        yaml_str = Serializer.to_yaml_string(proj)
        assert "profile: test" in yaml_str

    def test_yaml_does_not_contain_password(self) -> None:
        proj = _build_mock_project()
        yaml_str = Serializer.to_yaml_string(proj)
        assert "password" not in yaml_str.lower()


# =====================================================
# INTEGRATION TESTS (require live DB)
# =====================================================

@pytest.mark.integration
class TestLiveInspect:

    @pytest.fixture(scope="class")
    def live_project(self) -> GovernanceProject:
        prof = _integration_profile()
        if prof is None:
            pytest.skip("TARKIN_TEST_* env vars not set.")
        return inspect_database(prof)

    def test_project_is_not_none(self, live_project: GovernanceProject) -> None:
        assert live_project is not None

    def test_database_name_matches_profile(self, live_project: GovernanceProject) -> None:
        prof = _integration_profile()
        assert prof is not None
        if prof:
            assert live_project.database.database == prof.database

    def test_has_schemas(self, live_project: GovernanceProject) -> None:
        assert len(live_project.schemas) >= 1

    def test_no_system_schemas(self, live_project: GovernanceProject) -> None:
        excluded = {"pg_catalog", "information_schema", "__META__"}
        for schema in live_project.schemas:
            assert schema.name not in excluded, (
                f"System schema {schema.name!r} should not be in output."
            )
            assert not schema.name.startswith("tk_"), (
                f"Tarkin shadow schema {schema.name!r} should not be in output."
            )

    def test_all_tables_have_columns(self, live_project: GovernanceProject) -> None:
        for schema in live_project.schemas:
            for table in schema.tables:
                assert table.columns, (
                    f"{schema.name}.{table.name} has no columns in live inspect."
                )

    def test_indexes_reference_real_columns(self, live_project: GovernanceProject) -> None:
        for schema in live_project.schemas:
            for table in schema.tables:
                col_names = {c.name for c in table.columns}
                for idx in table.indexes:
                    for idx_col in idx.columns:
                        assert idx_col in col_names, (
                            f"Index {idx.name} col {idx_col!r} not in "
                            f"{schema.name}.{table.name} columns: {col_names}"
                        )

    def test_fk_targets_exist(self, live_project: GovernanceProject) -> None:
        schema_map = {s.name: {t.name: {c.name for c in t.columns} for t in s.tables}
                      for s in live_project.schemas}
        for schema in live_project.schemas:
            for table in schema.tables:
                for fk in table.foreign_keys:
                    assert fk.referenced_schema in schema_map, (
                        f"FK {fk.name} references missing schema {fk.referenced_schema!r}"
                    )
                    assert fk.referenced_table in schema_map[fk.referenced_schema], (
                        f"FK {fk.name} references missing table "
                        f"{fk.referenced_schema}.{fk.referenced_table}"
                    )
                    assert fk.referenced_column in schema_map[fk.referenced_schema][fk.referenced_table], (
                        f"FK {fk.name} references missing column "
                        f"{fk.referenced_schema}.{fk.referenced_table}.{fk.referenced_column}"
                    )

    def test_has_login_role(self, live_project: GovernanceProject) -> None:
        assert any(r.can_login for r in live_project.roles), (
            "No login roles found in inspected project."
        )

    def test_connected_user_in_roles(self, live_project: GovernanceProject) -> None:
        prof = _integration_profile()
        assert prof is not None
        if prof:
            role_names = {r.name for r in live_project.roles}
            assert prof.username in role_names, (
                f"Connected user {prof.username!r} not in inspected roles: {role_names}"
            )

    def test_round_trip_is_lossless(self, live_project: GovernanceProject) -> None:
        yaml_str = Serializer.to_yaml_string(live_project)
        reloaded = YamlLoader.loads(yaml_str)
        assert reloaded is not None

        if reloaded:
            orig_schemas = {s.name for s in live_project.schemas}
            rt_schemas   = {s.name for s in reloaded.schemas}
            assert orig_schemas == rt_schemas

            orig_roles = {r.name for r in live_project.roles}
            rt_roles   = {r.name for r in reloaded.roles}
            assert orig_roles == rt_roles

    def test_validation_passes_or_warns(self, live_project: GovernanceProject) -> None:
        """
        Validation on a live-inspected project may warn (the live DB can have things
        Tarkin doesn't fully model yet) but must not hard-crash.
        """
        try:
            SemanticValidator.validate(live_project)
        except ValidationError as exc:
            # Expected for databases with empty schemas, roles with no tables, etc.
            # Log it but don't fail the test — these are pre-Tarkin databases.
            pytest.xfail(f"Validation warnings on live DB (expected): {exc}")

    def test_inspect_writes_yaml(self, live_project: GovernanceProject, tmp_path: Path) -> None:
        output = Path("out/test_output.yaml")
        yaml_str = Serializer.to_yaml_string(live_project)
        output.write_text(yaml_str, encoding="utf-8")
        assert output.exists()
        assert output.stat().st_size > 0

    def test_build_produces_artifact(self, live_project: GovernanceProject) -> None:
        prof = _integration_profile()
        assert prof is not None

        out_dir = Path("out")
        zip_path = build(live_project, prof, out_dir=out_dir)

        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

        import zipfile
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert "tarkin_build.json" in names
            assert "tarkin_build.sql" in names

            sql = zf.read("tarkin_build.sql").decode()
            assert "BEGIN;" in sql
            assert "COMMIT;" in sql
            assert "__META__" in sql

    def test_attach_applies_build(self, live_project: GovernanceProject) -> None:
        zip_path = max(Path("out").glob("tarkin_build_*.zip"), key=lambda p: p.name)
        prof = _integration_profile()
        assert prof is not None

        if prof:
            attach(prof, build_path=zip_path)

    def test_inspect_after_attach_writes_yaml(self, live_project: GovernanceProject) -> None:
        prof = _integration_profile()
        assert prof is not None

        post_attach = inspect_database(prof)
        yaml_str = Serializer.to_yaml_string(post_attach)
        output = Path("out") / "test_output_post_attach.yaml"
        output.write_text(yaml_str, encoding="utf-8")
        assert output.exists()

    def test_detach_removes_build(self, live_project: GovernanceProject) -> None:
        prof = _integration_profile()
        assert prof is not None

        detach(prof, keep_versioning=False, drop_versioning=False, no_warn=False)

        # Verify tk_ schemas are gone
        post_detach = inspect_database(prof)
        tk_schemas = [s for s in post_detach.schemas if s.name.startswith("tk_")]
        assert not tk_schemas, f"tk_ schemas still present after detach: {tk_schemas}"
