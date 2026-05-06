"""
Reusable test fixtures for Tarkin.

These replace the old test_model() function that lived in model.py.
Import what you need; build_minimal_project() is the safest baseline.
"""
from __future__ import annotations
from tarkin.model import (
    GovernanceProject, DatabaseConfig, SchemaConfig, TableConfig,
    ColumnConfig, IndexConfig, ForeignKeyConfig,
    TablePermissionConfig, SchemaPermissionConfig, RoleConfig, UserConfig,
)


def make_database(**kwargs) -> DatabaseConfig:
    return DatabaseConfig(**kwargs)


def make_column(name: str = "id", data_type: str = "bigint", **kwargs) -> ColumnConfig:
    return ColumnConfig(name=name, data_type=data_type, **kwargs)


def make_index(name: str = "pk_id", columns: list[str] | None = None, **kwargs) -> IndexConfig:
    return IndexConfig(name=name, columns=columns or ["id"], primary_key=True, **kwargs)


def make_table(name: str = "users", **kwargs) -> TableConfig:
    return TableConfig(
        name=name,
        columns=[make_column()],
        **kwargs,
    )


def make_schema(name: str = "public", **kwargs) -> SchemaConfig:
    return SchemaConfig(
        name=name,
        tables=[make_table()],
        **kwargs,
    )


def make_role(name: str = "reader", schema: str = "public", **kwargs) -> RoleConfig:
    perm = SchemaPermissionConfig(
        schema_name=schema,
        usage=True,
        tables=[TablePermissionConfig(table="users", select=True)],
    )
    return RoleConfig(name=name, on=[perm], **kwargs)


def make_user(username: str = "app_user", roles: list[str] | None = None, **kwargs) -> UserConfig:
    return UserConfig(username=username, roles=roles or ["reader"], **kwargs)


def build_minimal_project() -> GovernanceProject:
    """
    Smallest valid GovernanceProject: one schema, one table, one column,
    one role, one active user.
    """
    return GovernanceProject(
        database=make_database(),
        schemas=[make_schema()],
        roles=[make_role()],
        users=[make_user()],
    )


def build_cross_schema_project() -> GovernanceProject:
    """
    Two schemas with a cross-schema foreign key.
    Useful for testing FK validation logic.
    """
    orders_col = make_column(name="user_id", data_type="bigint")
    fk = ForeignKeyConfig(
        name="fk_orders_user_id",
        column="user_id",
        referenced_schema="public",
        referenced_table="users",
        referenced_column="id",
    )
    orders_table = TableConfig(name="orders", columns=[orders_col], foreign_keys=[fk])
    orders_schema = SchemaConfig(name="sales", tables=[orders_table])

    public_schema = make_schema(name="public")

    role = make_role(name="reader", schema="public")
    sales_perm = SchemaPermissionConfig(schema_name="sales", usage=True)
    role_with_sales = RoleConfig(
        name="reader",
        on=[
            SchemaPermissionConfig(schema_name="public", usage=True,
                                   tables=[TablePermissionConfig(table="users", select=True)]),
            sales_perm,
        ],
    )

    return GovernanceProject(
        database=make_database(),
        schemas=[public_schema, orders_schema],
        roles=[role_with_sales],
        users=[make_user()],
    )


def build_clearance_project() -> GovernanceProject:
    """
    Project with clearance levels set on columns and roles.
    Useful for testing clearance validation.
    """
    normal_col = make_column(name="id")
    phi_col = ColumnConfig(
        name="ssn",
        data_type="text",
        clearance=2,
        sensitive=True,
        encrypted=True,
    )
    table = TableConfig(name="patients", columns=[normal_col, phi_col])
    schema = SchemaConfig(name="clinical", clearance=0, tables=[table])

    low_role = make_role(name="basic_reader", schema="clinical")
    high_role = RoleConfig(
        name="phi_reader",
        clearance=2,
        can_read_sensitive=True,
        on=[SchemaPermissionConfig(
            schema_name="clinical",
            usage=True,
            tables=[TablePermissionConfig(table="patients", select=True)],
        )],
    )

    return GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[low_role, high_role],
        users=[
            make_user(username="app", roles=["basic_reader"]),
            make_user(username="clinician", roles=["phi_reader"]),
        ],
    )
