from __future__ import annotations

from tarkin.model import (
    GovernanceProject, DatabaseConfig, SchemaConfig, TableConfig,
    ColumnConfig, IndexConfig, ForeignKeyConfig,
    TablePermissionConfig, SchemaPermissionConfig, RoleConfig,
)


def make_database(**kwargs) -> DatabaseConfig:
    return DatabaseConfig(**kwargs)


def make_column(name: str = "id", type: str = "bigint", **kwargs) -> ColumnConfig:
    return ColumnConfig(name=name, type=type, **kwargs)


def make_index(name: str = "pk_id", columns: list[str] | None = None, **kwargs) -> IndexConfig:
    return IndexConfig(name=name, columns=columns or ["id"], primary_key=True, **kwargs)


def make_table(name: str = "users", **kwargs) -> TableConfig:
    return TableConfig(name=name, columns=[make_column()], **kwargs)


def make_schema(name: str = "public", **kwargs) -> SchemaConfig:
    return SchemaConfig(name=name, tables=[make_table()], **kwargs)


def make_role(
    name: str = "reader",
    schema: str = "public",
    can_login: bool = True,
    **kwargs
) -> RoleConfig:
    perm = SchemaPermissionConfig(
        name=schema,
        usage=True,
        tables=[TablePermissionConfig(name="users", select=True)],
    )
    return RoleConfig(name=name, can_login=can_login, active=True, on=[perm], **kwargs)



def build_minimal_project() -> GovernanceProject:
    """
    Smallest valid GovernanceProject: one schema, one table, one column,
    one role, one active user.
    """
    return GovernanceProject(
        database=make_database(),
        schemas=[make_schema()],
        roles=[make_role()],
    )


def build_cross_schema_project() -> GovernanceProject:
    """
    Two schemas with a cross-schema foreign key.
    Useful for testing FK validation logic.
    """
    orders_col = make_column(name="user_id", type="bigint")
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

    roles = RoleConfig(
        name="reader",
        can_login=True,
        on=[
            SchemaPermissionConfig(name="public", usage=True,
                                   tables=[TablePermissionConfig(name="users", select=True)]),
            SchemaPermissionConfig(name="sales", usage=True),
        ],
    )

    return GovernanceProject(
        database=make_database(),
        schemas=[public_schema, orders_schema],
        roles=[roles],
    )


def build_clearance_project() -> GovernanceProject:
    """
    Project with clearance levels set on columns and roles.
    Useful for testing clearance validation.
    """
    normal_col = make_column(name="id")
    phi_col = ColumnConfig(
        name="ssn",
        type="text",
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
        can_login=True,
        can_access_sensitive=True,
        on=[SchemaPermissionConfig(
            name="clinical",
            usage=True,
            tables=[TablePermissionConfig(name="patients", select=True)],
        )],
    )

    return GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[low_role, high_role],
    )
