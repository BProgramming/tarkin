"""Loads a specification YAML for a GovernanceProject."""
from __future__ import annotations
from pathlib import Path
from ruamel.yaml import YAML

from .model import (
    GovernanceProject,
    DatabaseConfig,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    IndexConfig,
    ForeignKeyConfig,
    TablePermissionConfig,
    SchemaPermissionConfig,
    RoleConfig,
    DatabaseEngine,
    MaskingStrategy,
    GeneratedColumnStorage,
    IndexType,
    AuditLogLevel,
    FullMaskConfig,
    PartialMaskConfig,
    HashMaskConfig,
    EmailMaskConfig,
    PhoneMaskConfig,
    CreditCardMaskConfig,
    IpAddressMaskConfig,
    NameMaskConfig,
    PartialMaskVisibleSide,
    AnyMaskConfig,
    HashAlgorithm,
)


def _yaml() -> YAML:
    """Return a configured ruamel.yaml instance."""
    y = YAML()
    y.preserve_quotes = True
    return y


def _parse_mask_config(d: dict) -> AnyMaskConfig | None:
    """Parse a mask_config dict into the appropriate MaskConfig subclass."""
    if not d:
        return None

    cfg_type  = MaskingStrategy(d.get("type", "full"))
    hide_null = d.get("hide_null", False)
    mask_char = d.get("mask_char", "X")

    if cfg_type == MaskingStrategy.FULL:
        return FullMaskConfig(
            hide_null = hide_null,
            mask_char = mask_char,
        )
    elif cfg_type == MaskingStrategy.PARTIAL:
        return PartialMaskConfig(
            hide_null      = hide_null,
            mask_char      = mask_char,
            visible_length = d.get("visible_length", 4),
            visible_side   = PartialMaskVisibleSide(d.get("visible_side", "right")),
        )
    elif cfg_type == MaskingStrategy.HASH:
        return HashMaskConfig(
            hide_null = hide_null,
            algorithm = HashAlgorithm(d.get("algorithm", "xxhash")),
        )
    elif cfg_type == MaskingStrategy.EMAIL:
        return EmailMaskConfig(
            hide_null = hide_null,
            mask_char = mask_char,
        )
    elif cfg_type == MaskingStrategy.PHONE:
        return PhoneMaskConfig(
            hide_null      = hide_null,
            mask_char      = mask_char,
            visible_digits = d.get("visible_digits", 4),
        )
    elif cfg_type == MaskingStrategy.CREDIT_CARD:
        return CreditCardMaskConfig(
            hide_null = hide_null,
            mask_char = mask_char,
        )
    elif cfg_type == MaskingStrategy.IP_ADDRESS:
        return IpAddressMaskConfig(
            hide_null      = hide_null,
            mask_char      = mask_char,
            visible_octets = d.get("visible_octets", 2),
        )
    elif cfg_type == MaskingStrategy.NAME:
        return NameMaskConfig(
            hide_null = hide_null,
            mask_char = d.get("mask_char", "*"),
        )
    else:
        return None


class YamlLoader:
    """Parses a Tarkin governance YAML file into a GovernanceProject."""

    @classmethod
    def load(cls, path: Path) -> GovernanceProject | None:
        """Load and parse a governance YAML file from disk."""
        y = _yaml()
        with path.open("r", encoding="utf-8") as f:
            doc = y.load(f)
        return cls._parse_project(doc, path)

    @classmethod
    def loads(cls, text: str) -> GovernanceProject | None:
        """Load and parse a governance YAML string."""
        y = _yaml()
        doc = y.load(text)
        return cls._parse_project(doc, source="<string>")

    @classmethod
    def _parse_project(cls, doc: dict, source: object = None) -> GovernanceProject | None:
        """Parse the root project document."""
        if not source:
            raise ValueError("No YAML to load.")
        if "database" not in doc:
            raise ValueError(f"Tarkin YAML at {source!r} is missing required key 'database'.")
        return GovernanceProject(
            database = cls._parse_database(doc["database"]),
            schemas  = [cls._parse_schema(s) for s in doc.get("schemas", [])],
            roles    = [cls._parse_role(r) for r in doc.get("roles", [])],
        )

    @classmethod
    def _parse_database(cls, d: dict) -> DatabaseConfig:
        """Parse the database configuration block."""
        raw_logged = d.get("audit_logged", ["ddl", "write"])
        return DatabaseConfig(
            name          = d.get("name", "default_database"),
            description   = d.get("description"),
            audit_enabled = d.get("audit_enabled", False),
            audit_logged  = [AuditLogLevel(v) for v in raw_logged],
            host          = d.get("host", "localhost"),
            port          = d.get("port", 5432),
            database      = d.get("database", "postgres"),
            version       = d.get("version", ""),
            engine        = DatabaseEngine(d.get("engine", "postgres")),
            profile       = d.get("profile"),
            owner         = d.get("owner"),
        )

    @classmethod
    def _parse_schema(cls, d: dict) -> SchemaConfig:
        """Parse a schema configuration block."""
        return SchemaConfig(
            name               = d.get("name", "default_schema"),
            description        = d.get("description"),
            clearance          = d.get("clearance", 0),
            audit_enabled      = d.get("audit_enabled", True),
            tables             = [cls._parse_table(t) for t in d.get("tables", [])],
            aggregates         = d.get("aggregates", []),
            collations         = d.get("collations", []),
            domains            = d.get("domains", []),
            foreign_tables     = d.get("foreign_tables", []),
            fts_configurations = d.get("fts_configurations", []),
            fts_dictionaries   = d.get("fts_dictionaries", []),
            fts_parsers        = d.get("fts_parsers", []),
            fts_templates      = d.get("fts_templates", []),
            functions          = d.get("functions", []),
            materialized_views = d.get("materialized_views", []),
            operators          = d.get("operators", []),
            procedures         = d.get("procedures", []),
            sequences          = d.get("sequences", []),
            trigger_functions  = d.get("trigger_functions", []),
            types              = d.get("types", []),
            views              = d.get("views", []),
        )

    @classmethod
    def _parse_table(cls, d: dict) -> TableConfig:
        """Parse a table configuration block."""
        return TableConfig(
            name          = d.get("name", "default_table"),
            description   = d.get("description"),
            clearance     = d.get("clearance", 0),
            audit_enabled = d.get("audit_enabled", True),
            columns       = [cls._parse_column(c) for c in d.get("columns", [])],
            indexes       = [cls._parse_index(i) for i in d.get("indexes", [])],
            foreign_keys  = [cls._parse_fk(f) for f in d.get("foreign_keys", [])],
        )

    @classmethod
    def _parse_column(cls, d: dict) -> ColumnConfig:
        """Parse a column configuration block."""
        raw_mask    = d.get("mask_config") or {}
        mask_config = _parse_mask_config(raw_mask) if raw_mask else None

        return ColumnConfig(
            name                 = d.get("name", "default_column"),
            description          = d.get("description"),
            clearance            = d.get("clearance", 0),
            audit_enabled        = d.get("audit_enabled", True),
            type                 = d.get("type", "str"),
            default              = d.get("default"),
            unique               = d.get("unique", False),
            nullable             = d.get("nullable", True),
            immutable            = d.get("immutable", False),
            versioned            = d.get("versioned", False),
            sensitive            = d.get("sensitive", False),
            masking_strategy     = MaskingStrategy(d.get("masking_strategy", "none")),
            mask_config          = mask_config,
            generated_expression = d.get("generated_expression"),
            generated_storage    = GeneratedColumnStorage(d.get("generated_storage", "stored")),
        )

    @classmethod
    def _parse_index(cls, d: dict) -> IndexConfig:
        """Parse an index configuration block."""
        return IndexConfig(
            name           = d.get("name", "default_index"),
            columns        = list(d.get("columns", [])),
            index_type     = IndexType(d.get("index_type", "btree")),
            unique         = d.get("unique", False),
            primary_key    = d.get("primary_key", False),
            partial_filter = d.get("partial_filter"),
        )

    @classmethod
    def _parse_fk(cls, d: dict) -> ForeignKeyConfig:
        """Parse a foreign key configuration block."""
        return ForeignKeyConfig(
            name              = d.get("name", "default_fk"),
            column            = d["column"],
            referenced_schema = d["referenced_schema"],
            referenced_table  = d["referenced_table"],
            referenced_column = d["referenced_column"],
        )

    @classmethod
    def _parse_table_permission(cls, d: dict) -> TablePermissionConfig:
        """Parse a table-level permission block."""
        return TablePermissionConfig(
            name       = d.get("table", "-"),
            select     = d.get("select", True),
            insert     = d.get("insert", False),
            update     = d.get("update", False),
            delete     = d.get("delete", False),
            truncate   = d.get("truncate", False),
            references = d.get("references", False),
            trigger    = d.get("trigger", False),
            maintain   = d.get("maintain", False),
        )

    @classmethod
    def _parse_schema_permission(cls, d: dict) -> SchemaPermissionConfig:
        """Parse a schema-level permission block."""
        return SchemaPermissionConfig(
            name   = d.get("schema", "-"),
            usage  = d.get("usage", True),
            create = d.get("create", False),
            tables = [cls._parse_table_permission(t) for t in d.get("tables", [])],
        )

    @classmethod
    def _parse_role(cls, d: dict) -> RoleConfig:
        """Parse a role configuration block."""
        return RoleConfig(
            name                 = d.get("name", "default_role"),
            description          = d.get("description"),
            clearance            = d.get("clearance", 0),
            can_login            = d.get("can_login", False),
            can_admin            = d.get("can_admin", False),
            can_write            = d.get("can_write", False),
            can_maintain         = d.get("can_maintain", False),
            can_access_sensitive = d.get("can_access_sensitive", False),
            member_of            = list(d.get("member_of", [])),
            on                   = [cls._parse_schema_permission(o) for o in d.get("on", [])],
        )
