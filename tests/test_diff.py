"""
Tests for the Tarkin diff engine.

These tests are purely structural — no database connection required.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from tarkin.diff import (
    diff_projects, render_diff,
    Change, ChangeKind, ObjectType,
)
from tarkin.model import (
    GovernanceProject, SchemaConfig, TableConfig, ColumnConfig,
    IndexConfig, ForeignKeyConfig, RoleConfig,
    SchemaPermissionConfig, TablePermissionConfig,
    MaskingStrategy, FullMaskConfig,
)
from tests.fixtures import (
    build_minimal_project, build_clearance_project,
    build_masking_project, make_column, make_index, make_table,
    make_schema, make_role, make_database,
)


# =====================================================
# HELPERS
# =====================================================

def _clone(proj: GovernanceProject) -> GovernanceProject:
    """Return a deep copy of a project."""
    return proj.model_copy(deep=True)


def _changes_of(changes: list[Change], kind: ChangeKind) -> list[Change]:
    return [c for c in changes if c.kind == kind]


def _changes_for(changes: list[Change], object_type: ObjectType) -> list[Change]:
    return [c for c in changes if c.object_type == object_type]


# =====================================================
# IDENTICAL PROJECTS → NO CHANGES
# =====================================================

class TestNoDiff:

    def test_identical_minimal_project(self) -> None:
        proj = build_minimal_project()
        changes = diff_projects(proj, _clone(proj))
        assert changes == []

    def test_identical_clearance_project(self) -> None:
        proj = build_clearance_project()
        changes = diff_projects(proj, _clone(proj))
        assert changes == []

    def test_identical_masking_project(self) -> None:
        proj = build_masking_project()
        changes = diff_projects(proj, _clone(proj))
        assert changes == []


# =====================================================
# DATABASE-LEVEL CHANGES
# =====================================================

class TestDatabaseDiff:

    def test_audit_enabled_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.database.audit_enabled = True
        changes = diff_projects(before, after)
        db_changes = _changes_for(changes, ObjectType.DATABASE)
        assert len(db_changes) == 1
        assert db_changes[0].field == "audit_enabled"
        assert db_changes[0].before is False
        assert db_changes[0].after  is True

    def test_database_name_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.database.name = "renamed_db"
        changes = diff_projects(before, after)
        db_changes = _changes_for(changes, ObjectType.DATABASE)
        fields = [c.field for c in db_changes]
        assert "name" in fields


# =====================================================
# SCHEMA-LEVEL CHANGES
# =====================================================

class TestSchemaDiff:

    def test_schema_added(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.schemas.append(make_schema("new_schema"))
        # Add a role that references the new schema to pass validation
        after.roles[0].on.append(SchemaPermissionConfig(name="new_schema", usage=True))
        changes = diff_projects(before, after)
        schema_changes = _changes_for(changes, ObjectType.SCHEMA)
        added = [c for c in schema_changes if c.kind == ChangeKind.ADDED]
        assert any(c.path == "new_schema" for c in added)

    def test_schema_removed(self) -> None:
        before = build_minimal_project()
        before.schemas.append(make_schema("to_remove"))
        after  = _clone(before)
        after.schemas = [s for s in after.schemas if s.name != "to_remove"]
        after.roles[0].on = [sp for sp in after.roles[0].on if sp.name != "to_remove"]
        changes = diff_projects(before, after)
        schema_changes = _changes_for(changes, ObjectType.SCHEMA)
        removed = [c for c in schema_changes if c.kind == ChangeKind.REMOVED]
        assert any(c.path == "to_remove" for c in removed)

    def test_schema_clearance_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.schemas[0].clearance = 1
        # Bump column clearances to stay valid
        for table in after.schemas[0].tables:
            for col in table.columns:
                col.clearance = 1
        # Bump role clearance
        after.roles[0].clearance = 1
        changes = diff_projects(before, after)
        schema_changes = _changes_for(changes, ObjectType.SCHEMA)
        modified = [c for c in schema_changes if c.kind == ChangeKind.MODIFIED]
        assert any(c.field == "clearance" for c in modified)


# =====================================================
# TABLE-LEVEL CHANGES
# =====================================================

class TestTableDiff:

    def test_table_added(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.schemas[0].tables.append(make_table("new_table"))
        changes = diff_projects(before, after)
        table_changes = _changes_for(changes, ObjectType.TABLE)
        added = [c for c in table_changes if c.kind == ChangeKind.ADDED]
        assert any("new_table" in c.path for c in added)

    def test_table_removed(self) -> None:
        before = build_minimal_project()
        before.schemas[0].tables.append(make_table("to_remove"))
        after  = _clone(before)
        after.schemas[0].tables = [t for t in after.schemas[0].tables if t.name != "to_remove"]
        changes = diff_projects(before, after)
        table_changes = _changes_for(changes, ObjectType.TABLE)
        removed = [c for c in table_changes if c.kind == ChangeKind.REMOVED]
        assert any("to_remove" in c.path for c in removed)

    def test_table_audit_enabled_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.schemas[0].tables[0].audit_enabled = False
        changes = diff_projects(before, after)
        table_changes = _changes_for(changes, ObjectType.TABLE)
        modified = [c for c in table_changes if c.kind == ChangeKind.MODIFIED]
        assert any(c.field == "audit_enabled" for c in modified)


# =====================================================
# COLUMN-LEVEL CHANGES
# =====================================================

class TestColumnDiff:

    def test_column_added(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.schemas[0].tables[0].columns.append(
            ColumnConfig(name="new_col", type="text")
        )
        changes = diff_projects(before, after)
        col_changes = _changes_for(changes, ObjectType.COLUMN)
        added = [c for c in col_changes if c.kind == ChangeKind.ADDED]
        assert any("new_col" in c.path for c in added)

    def test_column_removed(self) -> None:
        before = build_minimal_project()
        before.schemas[0].tables[0].columns.append(
            ColumnConfig(name="to_remove", type="text")
        )
        after  = _clone(before)
        after.schemas[0].tables[0].columns = [
            c for c in after.schemas[0].tables[0].columns if c.name != "to_remove"
        ]
        changes = diff_projects(before, after)
        col_changes = _changes_for(changes, ObjectType.COLUMN)
        removed = [c for c in col_changes if c.kind == ChangeKind.REMOVED]
        assert any("to_remove" in c.path for c in removed)

    def test_column_type_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        # Add a non-PK text column to change
        before.schemas[0].tables[0].columns.append(ColumnConfig(name="val", type="text"))
        after.schemas[0].tables[0].columns.append(ColumnConfig(name="val", type="varchar(255)"))
        changes = diff_projects(before, after)
        col_changes = _changes_for(changes, ObjectType.COLUMN)
        modified = [c for c in col_changes if c.kind == ChangeKind.MODIFIED and c.field == "type"]
        assert len(modified) == 1
        assert modified[0].before == "text"
        assert modified[0].after  == "varchar(255)"

    def test_column_type_change_has_migration_note(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        before.schemas[0].tables[0].columns.append(ColumnConfig(name="val", type="text"))
        after.schemas[0].tables[0].columns.append(ColumnConfig(name="val", type="int"))
        changes = diff_projects(before, after)
        col_changes = _changes_for(changes, ObjectType.COLUMN)
        type_changes = [c for c in col_changes if c.field == "type"]
        assert all(c.note is not None for c in type_changes)

    def test_column_nullable_change_to_false_has_note(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        before.schemas[0].tables[0].columns.append(
            ColumnConfig(name="val", type="text", nullable=True)
        )
        after.schemas[0].tables[0].columns.append(
            ColumnConfig(name="val", type="text", nullable=False)
        )
        changes = diff_projects(before, after)
        col_changes = _changes_for(changes, ObjectType.COLUMN)
        nullable_changes = [c for c in col_changes if c.field == "nullable"]
        assert any(c.note is not None for c in nullable_changes)

    def test_column_masking_strategy_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        before.schemas[0].tables[0].columns.append(
            ColumnConfig(name="email", type="text", masking_strategy=MaskingStrategy.NONE)
        )
        after.schemas[0].tables[0].columns.append(
            ColumnConfig(name="email", type="text",
                         masking_strategy=MaskingStrategy.FULL,
                         mask_config=FullMaskConfig())
        )
        changes = diff_projects(before, after)
        col_changes = _changes_for(changes, ObjectType.COLUMN)
        strategy_changes = [c for c in col_changes if c.field == "masking_strategy"]
        assert len(strategy_changes) == 1
        mask_changes = [c for c in col_changes if c.field == "mask_config"]
        assert len(mask_changes) == 1

    def test_column_sensitive_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        before.schemas[0].tables[0].columns.append(
            ColumnConfig(name="phone", type="text", sensitive=False)
        )
        after.schemas[0].tables[0].columns.append(
            ColumnConfig(name="phone", type="text", sensitive=True)
        )
        changes = diff_projects(before, after)
        col_changes = _changes_for(changes, ObjectType.COLUMN)
        sensitive_changes = [c for c in col_changes if c.field == "sensitive"]
        assert len(sensitive_changes) == 1


# =====================================================
# ROLE-LEVEL CHANGES
# =====================================================

class TestRoleDiff:

    def test_role_added(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.roles.append(make_role(name="analyst"))
        changes = diff_projects(before, after)
        role_changes = _changes_for(changes, ObjectType.ROLE)
        added = [c for c in role_changes if c.kind == ChangeKind.ADDED]
        assert any(c.path == "analyst" for c in added)

    def test_role_removed(self) -> None:
        before = build_minimal_project()
        before.roles.append(make_role(name="to_remove"))
        after  = _clone(before)
        after.roles = [r for r in after.roles if r.name != "to_remove"]
        changes = diff_projects(before, after)
        role_changes = _changes_for(changes, ObjectType.ROLE)
        removed = [c for c in role_changes if c.kind == ChangeKind.REMOVED]
        assert any(c.path == "to_remove" for c in removed)

    def test_role_clearance_change(self) -> None:
        before = build_clearance_project()
        after  = _clone(before)
        phi_role = next(r for r in after.roles if r.name == "phi_reader")
        phi_role.clearance = 3
        changes = diff_projects(before, after)
        role_changes = _changes_for(changes, ObjectType.ROLE)
        modified = [c for c in role_changes if c.kind == ChangeKind.MODIFIED and c.field == "clearance"]
        assert any(c.path == "phi_reader" for c in modified)

    def test_role_can_login_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.roles[0].can_login = False
        changes = diff_projects(before, after)
        role_changes = _changes_for(changes, ObjectType.ROLE)
        modified = [c for c in role_changes if c.field == "can_login"]
        assert len(modified) == 1
        assert modified[0].before is True
        assert modified[0].after  is False


# =====================================================
# PERMISSION CHANGES
# =====================================================

class TestPermissionDiff:

    def test_permission_added(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        before.schemas.append(make_schema("extra"))
        after.schemas.append(make_schema("extra"))
        after.roles[0].on.append(
            SchemaPermissionConfig(name="extra", usage=True)
        )
        changes = diff_projects(before, after)
        perm_changes = _changes_for(changes, ObjectType.PERMISSION)
        added = [c for c in perm_changes if c.kind == ChangeKind.ADDED]
        assert any("extra" in c.path for c in added)

    def test_table_privilege_change(self) -> None:
        before = build_minimal_project()
        after  = _clone(before)
        after.roles[0].on[0].tables[0].insert = True
        changes = diff_projects(before, after)
        perm_changes = _changes_for(changes, ObjectType.PERMISSION)
        modified = [c for c in perm_changes if c.field == "insert"]
        assert len(modified) == 1
        assert modified[0].before is False
        assert modified[0].after  is True


# =====================================================
# RENDERER
# =====================================================

class TestRenderer:

    def test_render_no_changes(self, tmp_path: Path) -> None:
        proj    = build_minimal_project()
        output  = tmp_path / "diff.md"
        changes = diff_projects(proj, proj.model_copy(deep=True))
        render_diff(changes, output)
        assert output.exists()
        content = output.read_text()
        assert "No changes detected" in content

    def test_render_with_changes(self, tmp_path: Path) -> None:
        before = build_minimal_project()
        after  = before.model_copy(deep=True)
        after.database.audit_enabled = True
        changes = diff_projects(before, after)
        output  = tmp_path / "diff.md"
        render_diff(changes, output)
        assert output.exists()
        content = output.read_text()
        assert "audit_enabled" in content
        assert "modified" in content.lower()

    def test_render_creates_parent_dirs(self, tmp_path: Path) -> None:
        output = tmp_path / "subdir" / "nested" / "diff.md"
        render_diff([], output)
        assert output.exists()

    def test_render_summary_counts(self, tmp_path: Path) -> None:
        before = build_minimal_project()
        after  = before.model_copy(deep=True)
        # One modification
        after.database.name = "changed"
        # One addition
        after.schemas.append(make_schema("new"))
        after.roles[0].on.append(SchemaPermissionConfig(name="new", usage=True))
        changes = diff_projects(before, after)
        output  = tmp_path / "diff.md"
        render_diff(changes, output)
        content = output.read_text()
        assert "added" in content
        assert "modified" in content
