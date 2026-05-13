from __future__ import annotations
from enum import Enum
from typing import Optional, Union
from pydantic import BaseModel, ConfigDict, Field


# =========================================================
# ENUMS
# =========================================================


class StrEnum(str, Enum):
    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class DatabaseEngine(StrEnum):
    POSTGRES = "postgres"
    MYSQL    = "mysql"
    MARIADB  = "mariadb"
    SQLITE   = "sqlite"
    MSSQL    = "mssql"
    ORACLE   = "oracle"


class AuditLogLevel(StrEnum):
    READ     = "read"
    WRITE    = "write"
    FUNCTION = "function"
    ROLE     = "role"
    DDL      = "ddl"
    MISC     = "misc"
    ALL      = "all"


class MaskingStrategy(StrEnum):
    NONE        = "none"
    FULL        = "full"
    PARTIAL     = "partial"
    HASH        = "hash"
    EMAIL       = "email"
    PHONE       = "phone"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS  = "ip_address"
    NAME        = "name"


class PartialMaskVisibleSide(StrEnum):
    LEFT  = "left"
    RIGHT = "right"


class GeneratedColumnStorage(StrEnum):
    STORED  = "stored"
    VIRTUAL = "virtual"


class IndexType(StrEnum):
    BTREE = "btree"
    HASH  = "hash"
    GIN   = "gin"
    GIST  = "gist"
    BRIN  = "brin"


# =========================================================
# MASK CONFIGS
# =========================================================


class MaskConfig(BaseModel):
    """Base class for all masking configurations."""
    hide_null: bool = False


class FullMaskConfig(MaskConfig):
    """Replace entire value with mask_char repeated to match original length."""
    mask_char: str = "X"


class PartialMaskConfig(MaskConfig):
    """Show a portion of the value, mask the rest."""
    visible_length: int
    visible_side:   PartialMaskVisibleSide = PartialMaskVisibleSide.RIGHT
    mask_char:      str = "X"


class HashMaskConfig(MaskConfig):
    """
    Replace value with hashtextextended(value, 0).
    WARNING: This is NOT encryption. It masks data visibility for known users
    but is not cryptographically secure. Use encryption (coming in v2) for
    security requirements.
    """
    # seed is fixed at 0 — deterministic but not secure by design
    pass


class EmailMaskConfig(MaskConfig):
    """Mask everything left of the @ symbol: j***@example.com."""
    mask_char: str = "X"


class PhoneMaskConfig(MaskConfig):
    """Show last N digits, mask the rest: XXX-XXX-1234."""
    visible_digits: int = 4
    mask_char:      str = "X"


class CreditCardMaskConfig(MaskConfig):
    """Show last 4 digits in standard format: XXXX-XXXX-XXXX-1234."""
    mask_char: str = "X"


class IpAddressMaskConfig(MaskConfig):
    """Mask last N octets: 192.168.X.X."""
    visible_octets: int = 2
    mask_char:      str = "X"


class NameMaskConfig(MaskConfig):
    """Show first letter of each word, mask the rest: J*** S***."""
    mask_char: str = "*"


# Union type for mask_config field
AnyMaskConfig = Union[
    FullMaskConfig,
    PartialMaskConfig,
    HashMaskConfig,
    EmailMaskConfig,
    PhoneMaskConfig,
    CreditCardMaskConfig,
    IpAddressMaskConfig,
    NameMaskConfig,
]


# =========================================================
# BASE MODEL
# =========================================================


class TarkinBaseModel(BaseModel):
    """Shared model configuration for all Tarkin objects."""
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=True,
    )


# =========================================================
# DATABASE
# =========================================================


class DatabaseConfig(TarkinBaseModel):
    name:          str                  = "default_database"
    description:   Optional[str]        = None
    audit_enabled: bool                 = False
    audit_logged:  list[AuditLogLevel]  = Field(
        default_factory=lambda: [AuditLogLevel.DDL, AuditLogLevel.WRITE]
    )

    host:     str            = "localhost"
    port:     int            = 5432
    database: str            = "postgres"
    engine:   DatabaseEngine = DatabaseEngine.POSTGRES
    profile:  Optional[str]  = None


# =========================================================
# COLUMN
# =========================================================


class ColumnConfig(TarkinBaseModel):
    name:        str          = "default_column"
    clearance:   int          = 0
    description: Optional[str] = None
    audit_enabled: bool       = True

    type:    str           = "str"
    default: Optional[str] = None

    unique:    bool = False
    nullable:  bool = True
    immutable: bool = False
    versioned: bool = False

    sensitive: bool = False
    encrypted: bool = False

    masking_strategy: MaskingStrategy      = MaskingStrategy.NONE
    mask_config:      Optional[AnyMaskConfig] = None

    generated_expression: Optional[str]            = None
    generated_storage:    GeneratedColumnStorage    = GeneratedColumnStorage.STORED

    @property
    def is_generated(self) -> bool:
        return self.generated_expression is not None


# =========================================================
# INDEX
# =========================================================


class IndexConfig(TarkinBaseModel):
    name:           str       = "default_index"
    columns:        list[str]
    index_type:     IndexType = IndexType.BTREE
    unique:         bool      = False
    primary_key:    bool      = False
    partial_filter: str | None = None


# =========================================================
# FOREIGN KEY
# =========================================================


class ForeignKeyConfig(TarkinBaseModel):
    name:               str = "default_fk"
    column:             str
    referenced_schema:  str
    referenced_table:   str
    referenced_column:  str


# =========================================================
# TABLE
# =========================================================


class TableConfig(TarkinBaseModel):
    name:          str          = "default_table"
    clearance:     int          = 0
    description:   Optional[str] = None
    audit_enabled: bool         = True

    columns:      list[ColumnConfig]      = Field(default_factory=list)
    indexes:      list[IndexConfig]       = Field(default_factory=list)
    foreign_keys: list[ForeignKeyConfig]  = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        return min([c.clearance for c in self.columns], default=0)

    @property
    def clearance_max(self) -> int:
        return max([c.clearance for c in self.columns], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        return self.clearance_min, self.clearance_max


# =========================================================
# SCHEMA
# =========================================================


class SchemaConfig(TarkinBaseModel):
    name:          str          = "default_schema"
    clearance:     int          = 0
    description:   Optional[str] = None
    audit_enabled: bool         = True

    aggregates:         list[str] = Field(default_factory=list)  # not implemented
    collations:         list[str] = Field(default_factory=list)
    domains:            list[str] = Field(default_factory=list)
    fts_configurations: list[str] = Field(default_factory=list)  # not implemented
    fts_dictionaries:   list[str] = Field(default_factory=list)  # not implemented
    fts_parsers:        list[str] = Field(default_factory=list)  # not implemented
    fts_templates:      list[str] = Field(default_factory=list)  # not implemented
    foreign_tables:     list[str] = Field(default_factory=list)  # not implemented
    functions:          list[str] = Field(default_factory=list)
    materialized_views: list[str] = Field(default_factory=list)
    operators:          list[str] = Field(default_factory=list)  # not implemented
    procedures:         list[str] = Field(default_factory=list)  # not implemented
    sequences:          list[str] = Field(default_factory=list)
    tables:             list[TableConfig] = Field(default_factory=list)
    trigger_functions:  list[str] = Field(default_factory=list)
    types:              list[str] = Field(default_factory=list)
    views:              list[str] = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        return min([t.clearance_min for t in self.tables], default=0)

    @property
    def clearance_max(self) -> int:
        return max([t.clearance_max for t in self.tables], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        return self.clearance_min, self.clearance_max


# =========================================================
# PERMISSIONS
# =========================================================


class TablePermissionConfig(TarkinBaseModel):
    name:       str  = "-"
    select:     bool = True
    insert:     bool = False
    update:     bool = False
    delete:     bool = False
    truncate:   bool = False
    references: bool = False
    trigger:    bool = False
    maintain:   bool = False


class SchemaPermissionConfig(TarkinBaseModel):
    name:   str  = "-"
    tables: list[TablePermissionConfig] = Field(default_factory=list)
    usage:  bool = True
    create: bool = False


# =========================================================
# ROLES
# =========================================================


class RoleConfig(TarkinBaseModel):
    name:        str          = "default_role"
    clearance:   int          = 0
    description: Optional[str] = None

    can_login:            bool = False
    can_admin:            bool = False
    can_write:            bool = False
    can_maintain:         bool = False
    can_access_sensitive: bool = False

    active:    bool       = True
    member_of: list[str]  = Field(default_factory=list)
    on:        list[SchemaPermissionConfig] = Field(default_factory=list)


# =========================================================
# ROOT PROJECT
# =========================================================


class GovernanceProject(TarkinBaseModel):
    database: DatabaseConfig

    schemas: list[SchemaConfig] = Field(default_factory=list)
    roles:   list[RoleConfig]   = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        return min([s.clearance_min for s in self.schemas], default=0)

    @property
    def clearance_max(self) -> int:
        return max([s.clearance_max for s in self.schemas], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        return self.clearance_min, self.clearance_max
