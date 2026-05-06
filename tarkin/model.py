from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


# =========================================================
# ENUMS
# =========================================================


class DatabaseEngine(str, Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    SQLITE = "sqlite"
    MSSQL = "mssql"
    ORACLE = "oracle"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class MaskingStrategy(str, Enum):
    NONE = "none"
    FULL = "full"
    PARTIAL = "partial"
    HASH = "hash"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class PartialMaskVisibleSide(str, Enum):
    LEFT = "left"
    RIGHT = "right"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class GeneratedColumnStorage(str, Enum):
    STORED = "stored"
    VIRTUAL = "virtual"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


class IndexType(str, Enum):
    BTREE = "btree"
    HASH = "hash"
    GIN = "gin"
    GIST = "gist"
    BRIN = "brin"

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.value


# =========================================================
# MASK CONFIG
# =========================================================


class PartialMaskConfig(BaseModel):
    visible_length: int
    visible_side: PartialMaskVisibleSide = PartialMaskVisibleSide.RIGHT
    mask_char: str = "X"
    hide_null: bool = False


# =========================================================
# BASE MODEL
# =========================================================


class TarkinBaseModel(BaseModel):
    """
    Shared model configuration for all Tarkin objects.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=True,
    )


# =========================================================
# DATABASE
# =========================================================


class DatabaseConfig(TarkinBaseModel):
    name: str = "default_database"
    description: Optional[str] = None
    audit_enabled: bool = True

    host: str = "localhost"
    port: int = 5432
    database: str = "postgres"
    engine: DatabaseEngine = DatabaseEngine.POSTGRESQL

    # The credentials profile name from credentials.toml used to connect.
    # Credentials themselves never appear in the governance YAML.
    profile: Optional[str] = None


# =========================================================
# COLUMN
# =========================================================


class ColumnConfig(TarkinBaseModel):
    name: str = "default_column"
    clearance: int = 0
    description: Optional[str] = None
    audit_enabled: bool = True

    data_type: str = "str"
    default: Optional[str] = None

    unique:    bool = False
    nullable:  bool = True
    immutable: bool = False
    versioned: bool = False

    sensitive: bool = False
    encrypted: bool = False

    masking_strategy: MaskingStrategy = MaskingStrategy.NONE

    generated_expression: Optional[str] = None
    generated_storage: GeneratedColumnStorage = GeneratedColumnStorage.STORED

    @property
    def is_generated(self) -> bool:
        return self.generated_expression is not None


# =========================================================
# INDEX
# =========================================================


class IndexConfig(TarkinBaseModel):
    name: str = "default_index"
    columns: list[str]
    index_type: IndexType = IndexType.BTREE
    unique: bool = False
    primary_key: bool = False
    partial_filter: str | None = None


# =========================================================
# FOREIGN KEY
# =========================================================


class ForeignKeyConfig(TarkinBaseModel):
    name: str = "default_fk"
    column: str
    referenced_schema: str
    referenced_table: str
    referenced_column: str


# =========================================================
# TABLE
# =========================================================


class TableConfig(TarkinBaseModel):
    name: str = "default_table"
    clearance: int = 0
    description: Optional[str] = None
    audit_enabled: bool = True

    columns: list[ColumnConfig] = Field(default_factory=list)
    indexes: list[IndexConfig] = Field(default_factory=list)
    foreign_keys: list[ForeignKeyConfig] = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        return min([column.clearance for column in self.columns], default=0)

    @property
    def clearance_max(self) -> int:
        return max([column.clearance for column in self.columns], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        return self.clearance_min, self.clearance_max


# =========================================================
# SCHEMA
# =========================================================


class SchemaConfig(TarkinBaseModel):
    name: str = "default_schema"
    clearance: int = 0
    description: Optional[str] = None
    audit_enabled: bool = True

    aggregates: list[str] = Field(default_factory=list)          # not implemented
    collations: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    fts_configurations: list[str] = Field(default_factory=list)  # not implemented
    fts_dictionaries: list[str] = Field(default_factory=list)    # not implemented
    fts_parsers: list[str] = Field(default_factory=list)         # not implemented
    fts_templates: list[str] = Field(default_factory=list)       # not implemented
    foreign_tables: list[str] = Field(default_factory=list)      # not implemented
    functions: list[str] = Field(default_factory=list)
    materialized_views: list[str] = Field(default_factory=list)
    operators: list[str] = Field(default_factory=list)           # not implemented
    procedures: list[str] = Field(default_factory=list)          # not implemented
    sequences: list[str] = Field(default_factory=list)
    tables: list[TableConfig] = Field(default_factory=list)
    trigger_functions: list[str] = Field(default_factory=list)
    types: list[str] = Field(default_factory=list)
    views: list[str] = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        return min([table.clearance_min for table in self.tables], default=0)

    @property
    def clearance_max(self) -> int:
        return max([table.clearance_max for table in self.tables], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        return self.clearance_min, self.clearance_max


# =========================================================
# PERMISSIONS
# =========================================================


class TablePermissionConfig(TarkinBaseModel):
    table: str = "-"
    select: bool = True
    insert: bool = False
    update: bool = False
    delete: bool = False
    truncate: bool = False
    references: bool = False
    trigger: bool = False
    maintain: bool = False


class SchemaPermissionConfig(TarkinBaseModel):
    schema_name: str = "-"  # renamed from 'schema' to avoid shadowing BaseModel attribute
    tables: list[TablePermissionConfig] = Field(default_factory=list)
    usage: bool = True
    create: bool = False


# =========================================================
# ROLES / USERS
# =========================================================


class RoleConfig(TarkinBaseModel):
    name: str = "default_role"
    clearance: int = 0
    description: Optional[str] = None

    on: list[SchemaPermissionConfig] = Field(default_factory=list)

    can_read_sensitive: bool = False
    can_write: bool = False
    can_admin: bool = False


class UserConfig(TarkinBaseModel):
    username: str = "default_user"
    # Roles are referenced by name; resolved against the project's role list at validation time.
    roles: list[str] = Field(default_factory=list)
    active: bool = True


# =========================================================
# ROOT PROJECT
# =========================================================


class GovernanceProject(TarkinBaseModel):
    database: DatabaseConfig

    schemas: list[SchemaConfig] = Field(default_factory=list)
    roles: list[RoleConfig] = Field(default_factory=list)
    users: list[UserConfig] = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        return min([schema.clearance_min for schema in self.schemas], default=0)

    @property
    def clearance_max(self) -> int:
        return max([schema.clearance_max for schema in self.schemas], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        return self.clearance_min, self.clearance_max
