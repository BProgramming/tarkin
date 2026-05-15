"""The base logic for GovernanceProjects."""
from __future__ import annotations
from enum import Enum
from typing import Optional, Union
from pydantic import BaseModel, ConfigDict, Field


# =========================================================
# ENUMS
# =========================================================


class StrEnum(str, Enum):
    """Base class for string enumerations used throughout Tarkin."""

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return self.value


class DatabaseEngine(StrEnum):
    """Supported database engines. Only Postgres is supported currently, but future implementations are planned."""

    POSTGRES = "postgres"
    MYSQL    = "mysql"
    MARIADB  = "mariadb"
    SQLITE   = "sqlite"
    MSSQL    = "mssql"
    ORACLE   = "oracle"


class AuditLogLevel(StrEnum):
    """pgaudit log levels."""

    READ     = "read"
    WRITE    = "write"
    FUNCTION = "function"
    ROLE     = "role"
    DDL      = "ddl"
    MISC     = "misc"
    ALL      = "all"


class MaskingStrategy(StrEnum):
    """Available column masking strategies."""

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
    """Which side of the value remains visible in a partial mask."""

    LEFT  = "left"
    RIGHT = "right"


class GeneratedColumnStorage(StrEnum):
    """Storage type for generated columns."""

    STORED  = "stored"
    VIRTUAL = "virtual"


class IndexType(StrEnum):
    """PostgreSQL index access methods."""

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


class HashAlgorithm(StrEnum):
    """
    Hash algorithms available for column masking.

    Note: xxhash is non-cryptographic. sha256/sha512 are cryptographic but
    vulnerable to dictionary attacks on low-entropy data. hmac256 requires
    a secret key stored as the database setting tarkin.hmac_key.
    """
    XXHASH   = "xxhash"
    SHA256   = "sha256"
    SHA512   = "sha512"
    HMAC256  = "hmac256"


class HashMaskConfig(MaskConfig):
    """
    Configuration for hash-based masking.

    The HMAC key for hmac256 is never stored in the governance YAML.
    It is sourced from credentials.toml and stored as the database-level
    setting tarkin.hmac_key during 'tarkin attach'.
    """
    algorithm: HashAlgorithm = HashAlgorithm.XXHASH


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
# MODELS
# =========================================================


class TarkinBaseModel(BaseModel):
    """Shared model configuration for all Tarkin objects."""
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=True,
    )


class DatabaseConfig(TarkinBaseModel):
    """Top-level database configuration."""
    name:          str                 = "default_database"
    description:   Optional[str]       = None
    audit_enabled: bool                = False
    audit_logged:  list[AuditLogLevel] = Field(
        default_factory=lambda: [AuditLogLevel.DDL, AuditLogLevel.WRITE]
    )

    host:     str            = "localhost"
    port:     int            = 5432
    database: str            = "postgres"
    version:  str            = "14"
    engine:   DatabaseEngine = DatabaseEngine.POSTGRES
    profile:  Optional[str]  = None
    owner:    Optional[str]  = None


class ColumnConfig(TarkinBaseModel):
    """Configuration for a single database column."""
    name:          str           = "default_column"
    clearance:     int           = 0
    description:   Optional[str] = None
    audit_enabled: bool          = True

    type:    str           = "str"
    default: Optional[str] = None

    unique:    bool = False
    nullable:  bool = True
    immutable: bool = False
    versioned: bool = False

    sensitive: bool = False

    masking_strategy: MaskingStrategy         = MaskingStrategy.NONE
    mask_config:      Optional[AnyMaskConfig] = None

    generated_expression: Optional[str]         = None
    generated_storage:    GeneratedColumnStorage = GeneratedColumnStorage.STORED

    @property
    def is_generated(self) -> bool:
        """Return True if this column has a generated expression."""
        return self.generated_expression is not None


class IndexConfig(TarkinBaseModel):
    """Configuration for a database index."""
    name:           str        = "default_index"
    columns:        list[str]
    index_type:     IndexType  = IndexType.BTREE
    unique:         bool       = False
    primary_key:    bool       = False
    partial_filter: str | None = None


class ForeignKeyConfig(TarkinBaseModel):
    """Configuration for a foreign key constraint."""
    name:               str = "default_fk"
    column:             str
    referenced_schema:  str
    referenced_table:   str
    referenced_column:  str


class TableConfig(TarkinBaseModel):
    """Configuration for a database table."""
    name:          str           = "default_table"
    clearance:     int           = 0
    description:   Optional[str] = None
    audit_enabled: bool          = False

    columns:      list[ColumnConfig]     = Field(default_factory=list)
    indexes:      list[IndexConfig]      = Field(default_factory=list)
    foreign_keys: list[ForeignKeyConfig] = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        """Minimum clearance level across all columns."""
        return min([c.clearance for c in self.columns], default=0)

    @property
    def clearance_max(self) -> int:
        """Maximum clearance level across all columns."""
        return max([c.clearance for c in self.columns], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        """(min, max) clearance tuple across all columns."""
        return self.clearance_min, self.clearance_max


class SchemaConfig(TarkinBaseModel):
    """Configuration for a database schema."""
    name:          str           = "default_schema"
    clearance:     int           = 0
    description:   Optional[str] = None
    audit_enabled: bool          = True

    aggregates:         list[str]         = Field(default_factory=list)
    collations:         list[str]         = Field(default_factory=list)
    domains:            list[str]         = Field(default_factory=list)
    fts_configurations: list[str]         = Field(default_factory=list)
    fts_dictionaries:   list[str]         = Field(default_factory=list)
    fts_parsers:        list[str]         = Field(default_factory=list)
    fts_templates:      list[str]         = Field(default_factory=list)
    foreign_tables:     list[str]         = Field(default_factory=list)
    functions:          list[str]         = Field(default_factory=list)
    materialized_views: list[str]         = Field(default_factory=list)
    operators:          list[str]         = Field(default_factory=list)
    procedures:         list[str]         = Field(default_factory=list)
    sequences:          list[str]         = Field(default_factory=list)
    tables:             list[TableConfig] = Field(default_factory=list)
    trigger_functions:  list[str]         = Field(default_factory=list)
    types:              list[str]         = Field(default_factory=list)
    views:              list[str]         = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        """Minimum clearance level across all tables."""
        return min([t.clearance_min for t in self.tables], default=0)

    @property
    def clearance_max(self) -> int:
        """Maximum clearance level across all tables."""
        return max([t.clearance_max for t in self.tables], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        """(min, max) clearance tuple across all tables."""
        return self.clearance_min, self.clearance_max


class TablePermissionConfig(TarkinBaseModel):
    """Privilege configuration for a role on a specific table."""
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
    """Privilege configuration for a role on a specific schema."""
    name:   str                         = "-"
    tables: list[TablePermissionConfig] = Field(default_factory=list)
    usage:  bool                        = True
    create: bool                        = False


class RoleConfig(TarkinBaseModel):
    """
    Configuration for a database role.

    Roles that exist in the governance YAML but not in the live database
    at build time are created by Tarkin and will be dropped on detach.
    Roles that already exist are altered but not dropped on detach.
    """
    name:        str           = "default_role"
    clearance:   int           = 0
    description: Optional[str] = None

    can_login:            bool = False
    can_admin:            bool = False
    can_write:            bool = False
    can_maintain:         bool = False
    can_access_sensitive: bool = False

    member_of: list[str]                    = Field(default_factory=list)
    on:        list[SchemaPermissionConfig] = Field(default_factory=list)


class GovernanceProject(TarkinBaseModel):
    """Root object representing a full Tarkin governance specification."""
    database: DatabaseConfig

    schemas: list[SchemaConfig] = Field(default_factory=list)
    roles:   list[RoleConfig]   = Field(default_factory=list)

    @property
    def clearance_min(self) -> int:
        """Minimum clearance level across all schemas."""
        return min([s.clearance_min for s in self.schemas], default=0)

    @property
    def clearance_max(self) -> int:
        """Maximum clearance level across all schemas."""
        return max([s.clearance_max for s in self.schemas], default=0)

    @property
    def clearance_range(self) -> tuple[int, int]:
        """(min, max) clearance tuple across all schemas."""
        return self.clearance_min, self.clearance_max
