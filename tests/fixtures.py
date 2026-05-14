from __future__ import annotations

from tarkin.model import (
    GovernanceProject, DatabaseConfig, SchemaConfig, TableConfig,
    ColumnConfig, IndexConfig, ForeignKeyConfig,
    TablePermissionConfig, SchemaPermissionConfig, RoleConfig,
    MaskingStrategy, FullMaskConfig, PartialMaskConfig, HashMaskConfig,
    EmailMaskConfig, PhoneMaskConfig, CreditCardMaskConfig,
    IpAddressMaskConfig, NameMaskConfig, PartialMaskVisibleSide, HashAlgorithm,
)


def make_database(**kwargs) -> DatabaseConfig:
    return DatabaseConfig(**kwargs)


def make_column(name: str = "id", type: str = "bigint", **kwargs) -> ColumnConfig:
    return ColumnConfig(name=name, type=type, **kwargs)


def make_index(name: str = "pk_id", columns: list[str] | None = None, **kwargs) -> IndexConfig:
    return IndexConfig(name=name, columns=columns or ["id"], primary_key=True, unique=True, **kwargs)


def make_table(name: str = "users", **kwargs) -> TableConfig:
    return TableConfig(name=name, columns=[make_column()], indexes=[make_index()], **kwargs)


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
    return GovernanceProject(
        database=make_database(),
        schemas=[make_schema()],
        roles=[make_role()],
    )


def build_cross_schema_project() -> GovernanceProject:
    orders_col = make_column(name="user_id", type="bigint")
    fk = ForeignKeyConfig(
        name="fk_orders_user_id",
        column="user_id",
        referenced_schema="public",
        referenced_table="users",
        referenced_column="id",
    )
    orders_table  = TableConfig(
        name="orders",
        columns=[orders_col],
        indexes=[make_index("pk_orders", ["user_id"])],
        foreign_keys=[fk],
    )
    orders_schema = SchemaConfig(name="sales", tables=[orders_table])
    public_schema = make_schema(name="public")

    role = RoleConfig(
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
        roles=[role],
    )


def build_clearance_project() -> GovernanceProject:
    normal_col = make_column(name="id")
    phi_col = ColumnConfig(
        name="ssn",
        type="text",
        clearance=2,
        sensitive=True,
    )
    table  = TableConfig(
        name="patients",
        columns=[normal_col, phi_col],
        indexes=[make_index()],
    )
    schema = SchemaConfig(name="clinical", clearance=0, tables=[table])

    low_role  = make_role(name="basic_reader", schema="clinical")
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


def build_masking_project() -> GovernanceProject:
    cols = [
        make_column(name="id"),
        ColumnConfig(
            name="full_name",
            type="text",
            masking_strategy=MaskingStrategy.FULL,
            mask_config=FullMaskConfig(mask_char="*"),
        ),
        ColumnConfig(
            name="partial_code",
            type="text",
            masking_strategy=MaskingStrategy.PARTIAL,
            mask_config=PartialMaskConfig(visible_length=4, visible_side=PartialMaskVisibleSide.RIGHT),
        ),
        ColumnConfig(
            name="hashed_value",
            type="text",
            masking_strategy=MaskingStrategy.HASH,
            mask_config=HashMaskConfig(),
        ),
        ColumnConfig(
            name="email",
            type="text",
            masking_strategy=MaskingStrategy.EMAIL,
            mask_config=EmailMaskConfig(),
        ),
        ColumnConfig(
            name="phone",
            type="text",
            masking_strategy=MaskingStrategy.PHONE,
            mask_config=PhoneMaskConfig(visible_digits=4),
        ),
        ColumnConfig(
            name="credit_card",
            type="text",
            masking_strategy=MaskingStrategy.CREDIT_CARD,
            mask_config=CreditCardMaskConfig(),
        ),
        ColumnConfig(
            name="ip_address",
            type="text",
            masking_strategy=MaskingStrategy.IP_ADDRESS,
            mask_config=IpAddressMaskConfig(visible_octets=2),
        ),
        ColumnConfig(
            name="display_name",
            type="text",
            masking_strategy=MaskingStrategy.NAME,
            mask_config=NameMaskConfig(),
        ),
        ColumnConfig(
            name="xxhash_value",
            type="text",
            masking_strategy=MaskingStrategy.HASH,
            mask_config=HashMaskConfig(algorithm=HashAlgorithm.XXHASH),
        ),
        ColumnConfig(
            name="sha256_value",
            type="text",
            masking_strategy=MaskingStrategy.HASH,
            mask_config=HashMaskConfig(algorithm=HashAlgorithm.SHA256),
        ),
        ColumnConfig(
            name="sha512_value",
            type="text",
            masking_strategy=MaskingStrategy.HASH,
            mask_config=HashMaskConfig(algorithm=HashAlgorithm.SHA512),
        ),
        ColumnConfig(
            name="hmac256_value",
            type="text",
            masking_strategy=MaskingStrategy.HASH,
            mask_config=HashMaskConfig(algorithm=HashAlgorithm.HMAC256),
        ),
    ]

    table  = TableConfig(name="contacts", columns=cols, indexes=[make_index()])
    schema = SchemaConfig(name="public", tables=[table])
    role   = make_role(name="reader", schema="public")
    role.on[0].tables[0].name = "contacts"

    return GovernanceProject(
        database=make_database(),
        schemas=[schema],
        roles=[role],
    )
