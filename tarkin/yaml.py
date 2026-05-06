from __future__ import annotations
from pathlib import Path
from ruamel.yaml import YAML
from .model import (
    GovernanceProject, DatabaseConfig, SchemaConfig, TableConfig,
    ColumnConfig, IndexConfig, ForeignKeyConfig,
    TablePermissionConfig, SchemaPermissionConfig, RoleConfig, UserConfig,
)


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    return y


class YamlLoader:
    """
    Parse a Tarkin governance YAML file into a GovernanceProject.

    The YAML schema mirrors the structure produced by Serializer.to_yaml_string(),
    so load(serialize(project)) round-trips cleanly.
    """

    @classmethod
    def load(cls, path: Path) -> GovernanceProject:
        y = _yaml()
        with path.open("r", encoding="utf-8") as f:
            doc = y.load(f)
        return cls._parse_project(doc, path)

    @classmethod
    def loads(cls, text: str) -> GovernanceProject:
        """Parse from a YAML string (useful for testing)."""
        y = _yaml()
        doc = y.load(text)
        return cls._parse_project(doc, source="<string>")

    # =====================================================
    # PROJECT
    # =====================================================

    @classmethod
    def _parse_project(cls, doc: dict, source: object = None) -> GovernanceProject:
        if "database" not in doc:
            raise ValueError(f"Tarkin YAML at {source!r} is missing required key 'database'.")

        return GovernanceProject(
            database=cls._parse_database(doc["database"]),
            schemas=[cls._parse_schema(s) for s in doc.get("schemas", [])],
            roles=[cls._parse_role(r) for r in doc.get("roles", [])],
            users=[cls._parse_user(u) for u in doc.get("users", [])],
        )

    # =====================================================
    # DATABASE
    # =====================================================

    @classmethod
    def _parse_database(cls, d: dict) -> DatabaseConfig:
        return DatabaseConfig(
            name=d.get("name", "default_database"),
            description=d.get("description"),
            audit_enabled=d.get("audit_enabled", True),
            host=d.get("host", "localhost"),
            port=d.get("port", 5432),
            database=d.get("database", "postgres"),
            engine=d.get("engine", "postgresql"),
            profile=d.get("profile"),
        )

    # =====================================================
    # SCHEMA
    # =====================================================

    @classmethod
    def _parse_schema(cls, d: dict) -> SchemaConfig:
        return SchemaConfig(
            name=d.get("name", "default_schema"),
            description=d.get("description"),
            clearance=d.get("clearance", 0),
            audit_enabled=d.get("audit_enabled", True),
            tables=[cls._parse_table(t) for t in d.get("tables", [])],
            collations=d.get("collations", []),
            domains=d.get("domains", []),
            functions=d.get("functions", []),
            materialized_views=d.get("materialized_views", []),
            sequences=d.get("sequences", []),
            trigger_functions=d.get("trigger_functions", []),
            types=d.get("types", []),
            views=d.get("views", []),
        )

    # =====================================================
    # TABLE
    # =====================================================

    @classmethod
    def _parse_table(cls, d: dict) -> TableConfig:
        return TableConfig(
            name=d.get("name", "default_table"),
            description=d.get("description"),
            clearance=d.get("clearance", 0),
            audit_enabled=d.get("audit_enabled", True),
            columns=[cls._parse_column(c) for c in d.get("columns", [])],
            indexes=[cls._parse_index(i) for i in d.get("indexes", [])],
            foreign_keys=[cls._parse_fk(f) for f in d.get("foreign_keys", [])],
        )

    # =====================================================
    # COLUMN
    # =====================================================

    @classmethod
    def _parse_column(cls, d: dict) -> ColumnConfig:
        return ColumnConfig(
            name=d.get("name", "default_column"),
            description=d.get("description"),
            clearance=d.get("clearance", 0),
            audit_enabled=d.get("audit_enabled", True),
            data_type=d.get("data_type", "str"),
            default=d.get("default"),
            unique=d.get("unique", False),
            nullable=d.get("nullable", True),
            immutable=d.get("immutable", False),
            versioned=d.get("versioned", False),
            sensitive=d.get("sensitive", False),
            encrypted=d.get("encrypted", False),
            masking_strategy=d.get("masking_strategy", "none"),
            generated_expression=d.get("generated_expression"),
            generated_storage=d.get("generated_storage", "stored"),
        )

    # =====================================================
    # INDEX
    # =====================================================

    @classmethod
    def _parse_index(cls, d: dict) -> IndexConfig:
        return IndexConfig(
            name=d.get("name", "default_index"),
            columns=list(d.get("columns", [])),
            index_type=d.get("index_type", "btree"),
            unique=d.get("unique", False),
            primary_key=d.get("primary_key", False),
            partial_filter=d.get("partial_filter"),
        )

    # =====================================================
    # FOREIGN KEY
    # =====================================================

    @classmethod
    def _parse_fk(cls, d: dict) -> ForeignKeyConfig:
        return ForeignKeyConfig(
            name=d.get("name", "default_fk"),
            column=d["column"],
            referenced_schema=d["referenced_schema"],
            referenced_table=d["referenced_table"],
            referenced_column=d["referenced_column"],
        )

    # =====================================================
    # PERMISSIONS
    # =====================================================

    @classmethod
    def _parse_table_permission(cls, d: dict) -> TablePermissionConfig:
        return TablePermissionConfig(
            table=d.get("table", "-"),
            select=d.get("select", True),
            insert=d.get("insert", False),
            update=d.get("update", False),
            delete=d.get("delete", False),
            truncate=d.get("truncate", False),
            references=d.get("references", False),
            trigger=d.get("trigger", False),
            maintain=d.get("maintain", False),
        )

    @classmethod
    def _parse_schema_permission(cls, d: dict) -> SchemaPermissionConfig:
        return SchemaPermissionConfig(
            schema_name=d.get("schema", "-"),
            usage=d.get("usage", True),
            create=d.get("create", False),
            tables=[cls._parse_table_permission(t) for t in d.get("tables", [])],
        )

    # =====================================================
    # ROLE
    # =====================================================

    @classmethod
    def _parse_role(cls, d: dict) -> RoleConfig:
        return RoleConfig(
            name=d.get("name", "default_role"),
            description=d.get("description"),
            clearance=d.get("clearance", 0),
            can_read_sensitive=d.get("can_read_sensitive", False),
            can_write=d.get("can_write", False),
            can_admin=d.get("can_admin", False),
            on=[cls._parse_schema_permission(o) for o in d.get("on", [])],
        )

    # =====================================================
    # USER
    # =====================================================

    @classmethod
    def _parse_user(cls, d: dict) -> UserConfig:
        return UserConfig(
            username=d.get("username", "default_user"),
            active=d.get("active", True),
            roles=list(d.get("roles", [])),
        )
