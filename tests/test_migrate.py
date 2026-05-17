"""Tests for tarkin migrate — artifact generation and attach routing."""
from __future__ import annotations
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from tarkin.model import (
    GovernanceProject,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    IndexConfig,
    ForeignKeyConfig,
)
from tarkin.attach import _validate_for_build, _validate_for_migration, _read_artifact, AttachError
from tarkin.migrate import (
    migrate,
    MigrateError,
    _emit_drop_fks,
    _emit_drop_indexes,
    _emit_column_changes,
    _emit_add_indexes,
    _emit_add_fks,
    _emit_schema_changes,
    _emit_table_changes,
    _migration_metadata,
    _generate_migration_sql,
)
from tarkin.diff import diff_projects, Change, ChangeKind, ObjectType
from tarkin.build import _build_metadata
from tarkin.codegen import project_checksum
from .fixtures import make_database, make_role


def _col(name: str, type: str = "text", nullable: bool = True, **kw) -> ColumnConfig:
    return ColumnConfig(name=name, type=type, nullable=nullable, **kw)


def _pk_idx(col: str = "id", name: str | None = None) -> IndexConfig:
    return IndexConfig(name=name or f"pk_{col}", columns=[col], primary_key=True, unique=True)


def _simple_table(name: str = "users") -> TableConfig:
    return TableConfig(
        name    = name,
        columns = [_col("id", "bigint", nullable=False), _col("name")],
        indexes = [_pk_idx()],
    )


def _simple_project(table_name: str = "users", version: str = "16") -> GovernanceProject:
    return GovernanceProject(
        database = make_database(version=version),
        schemas  = [SchemaConfig(name="public", tables=[_simple_table(table_name)])],
        roles    = [make_role()],
    )


def _fake_profile(db_name: str = "testdb") -> MagicMock:
    prof = MagicMock()
    prof.profile  = "test"
    prof.host     = "localhost"
    prof.port     = 5432
    prof.database = db_name
    return prof


def _make_artifact(tmp_path: Path, metadata: dict, sql: str = "SELECT 1;") -> Path:
    """Write a fake artifact zip and return its path."""
    p = tmp_path / "tarkin_build_test.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("tarkin_build.json", json.dumps(metadata))
        zf.writestr("tarkin_build.sql",  sql)
    return p


class TestBuildMetadata:

    def test_build_metadata_includes_artifact_type(self) -> None:
        before   = _simple_project()
        after    = _simple_project()
        prof     = _fake_profile()
        prof.profile = "dev"
        metadata = _build_metadata(after, before, prof)
        assert metadata["artifact_type"] == "build"

    def test_build_metadata_has_db_checksum(self) -> None:
        before   = _simple_project()
        after    = _simple_project()
        prof     = _fake_profile()
        prof.profile = "dev"
        metadata = _build_metadata(after, before, prof)
        assert "db_checksum" in metadata


class TestAttachRouting:

    def test_validate_for_build_passes_when_no_tk_schemas(self) -> None:
        proj     = _simple_project()
        metadata = {"db_checksum": project_checksum(proj)}
        # Should not raise
        _validate_for_build(metadata, [], proj)

    def test_validate_for_build_raises_when_tk_schemas_present(self) -> None:
        proj     = _simple_project()
        metadata = {"db_checksum": project_checksum(proj)}
        with pytest.raises(AttachError, match="already has an active Tarkin build"):
            _validate_for_build(metadata, ["tk_public"], proj)

    def test_validate_for_build_raises_on_checksum_mismatch(self) -> None:
        proj     = _simple_project()
        other    = _simple_project("orders")
        metadata = {"db_checksum": project_checksum(other)}
        with pytest.raises(AttachError, match="Database state has changed"):
            _validate_for_build(metadata, [], proj)

    def test_validate_for_migration_raises_when_no_tk_schemas(self) -> None:
        prof     = _fake_profile()
        metadata = {"source_checksum": "abc123", "database": "testdb"}
        with pytest.raises(AttachError, match="No active Tarkin build found"):
            _validate_for_migration(prof, metadata, [])

    def test_read_artifact_returns_metadata_and_sql(self, tmp_path: Path) -> None:
        meta = {"artifact_type": "build", "db_checksum": "x"}
        p    = _make_artifact(tmp_path, meta, "SELECT 42;")
        result_meta, result_sql = _read_artifact(p)
        assert result_meta["artifact_type"] == "build"
        assert "SELECT 42;" in result_sql

    def test_read_artifact_raises_on_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(AttachError, match="not found"):
            _read_artifact(tmp_path / "nonexistent.zip")

    def test_read_artifact_raises_on_bad_zip(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.zip"
        p.write_bytes(b"not a zip file")
        with pytest.raises(AttachError, match="not a valid zip"):
            _read_artifact(p)


class TestMigrationMetadata:

    def test_migration_metadata_has_correct_artifact_type(self) -> None:
        proj     = _simple_project()
        prof     = _fake_profile()
        changes  = []
        metadata = _migration_metadata(proj, prof, "src_checksum", "testdb", changes)
        assert metadata["artifact_type"]   == "migrate"
        assert metadata["source_checksum"] == "src_checksum"
        assert metadata["target_checksum"] == project_checksum(proj)

    def test_migration_metadata_serialises_changes(self) -> None:
        proj    = _simple_project()
        prof    = _fake_profile()
        change  = Change(
            kind        = ChangeKind.ADDED,
            object_type = ObjectType.COLUMN,
            path        = "public.users.email",
            field       = None,
        )
        metadata = _migration_metadata(proj, prof, "x", "db", [change])
        assert metadata["change_count"] == 1
        assert metadata["changes"][0]["path"] == "public.users.email"
        assert metadata["changes"][0]["kind"] == "added"


class TestEmitDropFks:

    def test_drops_removed_fk(self) -> None:
        changes = [Change(
            kind=ChangeKind.REMOVED, object_type=ObjectType.FOREIGN_KEY,
            path="public.orders.fk_user",
        )]
        sql = _emit_drop_fks(changes)
        assert 'DROP CONSTRAINT IF EXISTS "fk_user"' in sql
        assert '"tk_public"."orders"' in sql

    def test_drops_modified_fk(self) -> None:
        changes = [Change(
            kind=ChangeKind.MODIFIED, object_type=ObjectType.FOREIGN_KEY,
            path="sales.items.fk_product", field="referenced_table",
            before="products_old", after="products",
        )]
        sql = _emit_drop_fks(changes)
        assert 'DROP CONSTRAINT IF EXISTS "fk_product"' in sql

    def test_ignores_added_fks(self) -> None:
        changes = [Change(
            kind=ChangeKind.ADDED, object_type=ObjectType.FOREIGN_KEY,
            path="public.orders.fk_new",
        )]
        assert _emit_drop_fks(changes).strip() == ""


class TestEmitDropIndexes:

    def test_drops_removed_index(self) -> None:
        changes = [Change(
            kind=ChangeKind.REMOVED, object_type=ObjectType.INDEX,
            path="public.users.idx_email",
        )]
        sql = _emit_drop_indexes(changes, {})
        assert 'DROP INDEX IF EXISTS "tk_public"."idx_email"' in sql

    def test_warns_on_pk_change(self) -> None:
        from tarkin.model import IndexConfig
        pk_idx = IndexConfig(name="pk_users", columns=["id"], primary_key=True, unique=True)
        table  = TableConfig(name="users", columns=[_col("id", "bigint")], indexes=[pk_idx])
        before_map = {("public", "users"): table}
        changes = [Change(
            kind=ChangeKind.REMOVED, object_type=ObjectType.INDEX,
            path="public.users.pk_users",
        )]
        sql = _emit_drop_indexes(changes, before_map)
        assert "WARNING" in sql
        assert "manual" in sql.lower()


class TestEmitColumnChanges:

    def test_add_column(self) -> None:
        after_table = TableConfig(
            name    = "users",
            columns = [_col("id", "bigint"), _col("email")],
            indexes = [_pk_idx()],
        )
        changes = [Change(
            kind=ChangeKind.ADDED, object_type=ObjectType.COLUMN,
            path="public.users.email",
        )]
        sql = _emit_column_changes(changes, {("public", "users"): after_table})
        assert 'ADD COLUMN "email"' in sql
        assert '"tk_public"."users"' in sql

    def test_drop_column_with_warning(self) -> None:
        changes = [Change(
            kind=ChangeKind.REMOVED, object_type=ObjectType.COLUMN,
            path="public.users.old_col",
        )]
        sql = _emit_column_changes(changes, {})
        assert "WARNING" in sql
        assert 'DROP COLUMN IF EXISTS "old_col"' in sql

    def test_type_change_with_warning(self) -> None:
        changes = [Change(
            kind=ChangeKind.MODIFIED, object_type=ObjectType.COLUMN,
            path="public.users.score", field="type",
            before="text", after="integer",
        )]
        sql = _emit_column_changes(changes, {})
        assert "WARNING" in sql
        assert "TYPE integer" in sql
        assert "USING" in sql

    def test_add_not_null_with_warning(self) -> None:
        changes = [Change(
            kind=ChangeKind.MODIFIED, object_type=ObjectType.COLUMN,
            path="public.users.email", field="nullable",
            before=True, after=False,
        )]
        sql = _emit_column_changes(changes, {})
        assert "WARNING" in sql
        assert "SET NOT NULL" in sql

    def test_drop_not_null(self) -> None:
        changes = [Change(
            kind=ChangeKind.MODIFIED, object_type=ObjectType.COLUMN,
            path="public.users.email", field="nullable",
            before=False, after=True,
        )]
        sql = _emit_column_changes(changes, {})
        assert "DROP NOT NULL" in sql
        assert "WARNING" not in sql

    def test_default_added(self) -> None:
        changes = [Change(
            kind=ChangeKind.MODIFIED, object_type=ObjectType.COLUMN,
            path="public.users.status", field="default",
            before=None, after="'active'",
        )]
        sql = _emit_column_changes(changes, {})
        assert "SET DEFAULT 'active'" in sql

    def test_default_dropped(self) -> None:
        changes = [Change(
            kind=ChangeKind.MODIFIED, object_type=ObjectType.COLUMN,
            path="public.users.status", field="default",
            before="'active'", after=None,
        )]
        sql = _emit_column_changes(changes, {})
        assert "DROP DEFAULT" in sql


class TestEmitAddIndexes:

    def test_adds_new_index(self) -> None:
        idx = IndexConfig(name="idx_email", columns=["email"], unique=True)
        table = TableConfig(name="users", columns=[_col("id", "bigint"), _col("email")], indexes=[idx])
        changes = [Change(
            kind=ChangeKind.ADDED, object_type=ObjectType.INDEX,
            path="public.users.idx_email",
        )]
        sql = _emit_add_indexes(changes, {("public", "users"): table})
        assert 'CREATE UNIQUE INDEX "idx_email"' in sql
        assert '"tk_public"."users"' in sql

    def test_pk_change_emits_warning(self) -> None:
        pk = IndexConfig(name="pk_users", columns=["id"], primary_key=True, unique=True)
        table = TableConfig(name="users", columns=[_col("id", "bigint")], indexes=[pk])
        changes = [Change(
            kind=ChangeKind.ADDED, object_type=ObjectType.INDEX,
            path="public.users.pk_users",
        )]
        sql = _emit_add_indexes(changes, {("public", "users"): table})
        assert "WARNING" in sql


class TestEmitAddFks:

    def test_adds_new_fk(self) -> None:
        fk = ForeignKeyConfig(
            name="fk_user", column="user_id",
            referenced_schema="public", referenced_table="users", referenced_column="id",
        )
        table = TableConfig(
            name="orders",
            columns=[_col("id", "bigint"), _col("user_id", "bigint")],
            indexes=[_pk_idx()],
            foreign_keys=[fk],
        )
        changes = [Change(
            kind=ChangeKind.ADDED, object_type=ObjectType.FOREIGN_KEY,
            path="public.orders.fk_user",
        )]
        sql = _emit_add_fks(changes, {("public", "orders"): table})
        assert 'ADD CONSTRAINT "fk_user"' in sql
        assert 'REFERENCES "tk_public"."users"' in sql


class TestEmitSchemaChanges:

    def test_added_schema(self) -> None:
        changes = [Change(kind=ChangeKind.ADDED, object_type=ObjectType.SCHEMA, path="analytics")]
        sql = _emit_schema_changes(changes)
        assert 'CREATE SCHEMA "analytics"' in sql
        assert 'CREATE SCHEMA "tk_analytics"' in sql

    def test_removed_schema_with_warning(self) -> None:
        changes = [Change(kind=ChangeKind.REMOVED, object_type=ObjectType.SCHEMA, path="legacy")]
        sql = _emit_schema_changes(changes)
        assert "WARNING" in sql
        assert "tk_legacy" in sql


class TestEmitTableChanges:

    def test_added_table(self) -> None:
        table = _simple_table("orders")
        after_schema = SchemaConfig(name="public", tables=[table])
        changes = [Change(kind=ChangeKind.ADDED, object_type=ObjectType.TABLE, path="public.orders")]
        sql = _emit_table_changes(changes, {"public": after_schema})
        assert 'CREATE TABLE "tk_public"."orders"' in sql

    def test_removed_table_with_warning(self) -> None:
        changes = [Change(kind=ChangeKind.REMOVED, object_type=ObjectType.TABLE, path="public.old_table")]
        sql = _emit_table_changes(changes, {})
        assert "WARNING" in sql
        assert "tk_public" in sql


class TestGenerateMigrationSql:

    @staticmethod
    def _build_before_after():
        before = _simple_project()
        after  = before.model_copy(deep=True)
        after.schemas[0].tables[0].columns.append(
            ColumnConfig(name="email", type="text")
        )
        return before, after

    def test_migration_sql_has_begin_and_commit(self) -> None:
        before, after = self._build_before_after()
        changes = diff_projects(before, after)
        sql = _generate_migration_sql(before, after, changes)
        assert "BEGIN;" in sql
        assert "COMMIT;" in sql

    def test_migration_sql_has_section_headers(self) -> None:
        before, after = self._build_before_after()
        changes = diff_projects(before, after)
        sql = _generate_migration_sql(before, after, changes)
        assert "TARKIN MIGRATION" in sql

    def test_migration_sql_updates_meta(self) -> None:
        before, after = self._build_before_after()
        changes = diff_projects(before, after)
        sql = _generate_migration_sql(before, after, changes)
        assert "tarkin_builds" in sql

    def test_migration_sql_contains_column_add(self) -> None:
        before, after = self._build_before_after()
        changes = diff_projects(before, after)
        sql = _generate_migration_sql(before, after, changes)
        assert 'ADD COLUMN "email"' in sql

    def test_no_changes_raises(self) -> None:
        proj = _simple_project()
        checksum = project_checksum(proj)
        prof = _fake_profile()

        with patch("tarkin.migrate._read_current_build") as mock_read:
            mock_read.return_value = (proj, checksum, "testdb")
            with pytest.raises(MigrateError, match="No differences"):
                migrate(proj, prof, out_dir=Path("/tmp"))


class TestMigrateFunction:

    @staticmethod
    def _mock_connection(yaml_str: str, checksum: str, db_name: str = "testdb"):
        """Return a mock engine/connection that returns the given build row."""
        mock_row      = MagicMock()
        mock_row.__getitem__ = lambda self, i: [yaml_str, checksum, db_name][i]
        mock_row.__iter__    = lambda self: iter([yaml_str, checksum, db_name])

        mock_conn = MagicMock()
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__  = MagicMock(return_value=False)
        mock_conn.execute.return_value.fetchone.return_value = mock_row

        mock_engine = MagicMock()
        mock_engine.connect.return_value = mock_conn
        return mock_engine

    def test_migrate_raises_when_no_changes(self, tmp_path: Path) -> None:
        proj     = _simple_project()
        checksum = project_checksum(proj)
        prof     = _fake_profile()

        with patch("tarkin.migrate._read_current_build") as mock_read:
            mock_read.return_value = (proj, checksum, "testdb")
            with pytest.raises(MigrateError, match="No differences"):
                migrate(proj, prof, out_dir=tmp_path)

    def test_migrate_produces_artifact(self, tmp_path: Path) -> None:
        before   = _simple_project()
        after    = before.model_copy(deep=True)
        after.schemas[0].tables[0].columns.append(_col("email"))
        checksum = project_checksum(before)
        prof     = _fake_profile()

        with patch("tarkin.migrate._read_current_build") as mock_read:
            mock_read.return_value = (before, checksum, "testdb")
            zip_path = migrate(after, prof, out_dir=tmp_path)

        assert zip_path.exists()
        assert zip_path.name.startswith("tarkin_migrate_")
        assert zip_path.suffix == ".zip"

    def test_migrate_artifact_has_correct_metadata(self, tmp_path: Path) -> None:
        before   = _simple_project()
        after    = before.model_copy(deep=True)
        after.schemas[0].tables[0].columns.append(_col("email"))
        checksum = project_checksum(before)
        prof     = _fake_profile()

        with patch("tarkin.migrate._read_current_build") as mock_read:
            mock_read.return_value = (before, checksum, "testdb")
            zip_path = migrate(after, prof, out_dir=tmp_path)

        with zipfile.ZipFile(zip_path) as zf:
            metadata = json.loads(zf.read("tarkin_build.json"))

        assert metadata["artifact_type"]   == "migrate"
        assert metadata["source_checksum"] == checksum
        assert metadata["target_checksum"] == project_checksum(after)
        assert metadata["change_count"]    >= 1

    def test_migrate_artifact_contains_sql(self, tmp_path: Path) -> None:
        before   = _simple_project()
        after    = before.model_copy(deep=True)
        after.schemas[0].tables[0].columns.append(_col("email"))
        checksum = project_checksum(before)
        prof     = _fake_profile()

        with patch("tarkin.migrate._read_current_build") as mock_read:
            mock_read.return_value = (before, checksum, "testdb")
            zip_path = migrate(after, prof, out_dir=tmp_path)

        with zipfile.ZipFile(zip_path) as zf:
            sql = zf.read("tarkin_build.sql").decode()

        assert "BEGIN;" in sql
        assert "COMMIT;" in sql
        assert 'ADD COLUMN "email"' in sql
