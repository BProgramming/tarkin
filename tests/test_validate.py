"""
Semantic validation tests.
Run with: python -m pytest tests/
"""
from __future__ import annotations
import pytest

from tarkin.validate import SemanticValidator, ValidationError
from tarkin.model import (
    GovernanceProject, SchemaConfig, TableConfig,
    ColumnConfig, IndexConfig, ForeignKeyConfig,
    SchemaPermissionConfig, RoleConfig,
)
from tests.fixtures import (
    build_minimal_project, build_cross_schema_project, build_clearance_project,
    make_schema, make_column, make_role, make_database,
)


# =====================================================
# HELPERS
# =====================================================

def assert_valid(project: GovernanceProject) -> None:
    assert SemanticValidator.validate(project) is True


def assert_invalid(project: GovernanceProject, fragment: str | None = None) -> None:
    with pytest.raises(ValidationError) as exc_info:
        SemanticValidator.validate(project)
    if fragment:
        assert fragment in str(exc_info.value), (
            f"Expected {fragment!r} in error message, got:\n{exc_info.value}"
        )


# =====================================================
# BASELINE
# =====================================================

def test_minimal_project_is_valid() -> None:
    assert_valid(build_minimal_project())


def test_cross_schema_project_is_valid() -> None:
    assert_valid(build_cross_schema_project())


def test_clearance_project_is_valid() -> None:
    assert_valid(build_clearance_project())


# =====================================================
# PROJECT STRUCTURE
# =====================================================

def test_no_schemas_is_invalid() -> None:
    proj = GovernanceProject(
        database=make_database(),
        schemas=[],
        roles=[make_role()],
    )
    assert_invalid(proj, "at least one schema")


# =====================================================
# SCHEMA RULES
# =====================================================

def test_empty_schema_is_invalid() -> None:
    proj = build_minimal_project()
    proj.schemas.append(SchemaConfig(name="empty"))
    assert_invalid(proj, "at least one table")


def test_duplicate_schema_names_are_invalid() -> None:
    s1 = make_schema(name="dup")
    s2 = make_schema(name="dup")
    proj = GovernanceProject(
        database=make_database(),
        schemas=[s1, s2],
        roles=[make_role()],
    )
    assert_invalid(proj, "Duplicate schema")


# =====================================================
# TABLE RULES
# =====================================================

def test_empty_table_is_invalid() -> None:
    table = TableConfig(name="empty", columns=[])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "at least one column")


def test_duplicate_column_names_are_invalid() -> None:
    col = make_column(name="id")
    table = TableConfig(name="dup_cols", columns=[col, col.model_copy()])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "Duplicate column")


# =====================================================
# COLUMN RULES
# =====================================================

def test_versioned_and_immutable_column_is_invalid() -> None:
    col = ColumnConfig(name="bad", type="text", versioned=True, immutable=True)
    table = TableConfig(name="t", columns=[col])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "versioned and immutable")


def test_encrypted_column_without_sensitivity_is_invalid() -> None:
    col = ColumnConfig(name="token", type="text", encrypted=True)
    table = TableConfig(name="t", columns=[col])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "encrypted but not marked sensitive")


def test_generated_and_default_column_is_invalid() -> None:
    col = ColumnConfig(name="g", type="text", generated_expression="1+1", default="0")
    table = TableConfig(name="t", columns=[col])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "cannot have both a default value and a generated expression")


# =====================================================
# CROSS REFERENCES
# =====================================================

def test_fk_to_missing_schema_is_invalid() -> None:
    fk = ForeignKeyConfig(
        name="bad_fk", column="id",
        referenced_schema="nonexistent", referenced_table="t", referenced_column="id",
    )
    table = TableConfig(name="orders", columns=[make_column()], foreign_keys=[fk])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "missing schema 'nonexistent'")


def test_fk_to_missing_table_is_invalid() -> None:
    fk = ForeignKeyConfig(
        name="bad_fk", column="id",
        referenced_schema="public", referenced_table="ghost", referenced_column="id",
    )
    table = TableConfig(name="orders", columns=[make_column()], foreign_keys=[fk])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "missing table 'public.ghost'")


def test_fk_to_missing_column_is_invalid() -> None:
    target_col = make_column(name="id")
    target_table = TableConfig(name="users", columns=[target_col])
    fk = ForeignKeyConfig(
        name="bad_fk", column="id",
        referenced_schema="public", referenced_table="users", referenced_column="ghost_col",
    )
    src_table = TableConfig(name="orders", columns=[make_column()], foreign_keys=[fk])
    schema = SchemaConfig(name="public", tables=[target_table, src_table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "missing column 'public.users.ghost_col'")


def test_index_referencing_missing_column_is_invalid() -> None:
    col = make_column(name="id")
    idx = IndexConfig(name="bad_idx", columns=["nonexistent"])
    table = TableConfig(name="t", columns=[col], indexes=[idx])
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "missing column 'nonexistent'")


# =====================================================
# CLEARANCE RULES
# =====================================================

def test_column_clearance_below_table_minimum_is_invalid() -> None:
    col = ColumnConfig(name="id", type="bigint", clearance=0)
    table = TableConfig(name="secure", columns=[col], clearance=1)
    schema = SchemaConfig(name="public", tables=[table])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[make_role()],
    )
    assert_invalid(proj, "clearance below required minimum")


# =====================================================
# ROLE RULES
# =====================================================

def test_role_with_no_schemas_is_invalid() -> None:
    role = RoleConfig(name="empty_role", on=[])
    proj = GovernanceProject(
        database=make_database(),
        schemas=[make_schema()],
        roles=[role],
    )
    assert_invalid(proj, "no assigned schemas")


def test_role_referencing_missing_schema_is_invalid() -> None:
    role = RoleConfig(
        name="bad_role",
        on=[SchemaPermissionConfig(name="ghost_schema")],
    )
    proj = GovernanceProject(
        database=make_database(),
        schemas=[make_schema()],
        roles=[role],
    )
    assert_invalid(proj, "ghost_schema")
