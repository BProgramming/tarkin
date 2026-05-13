from __future__ import annotations
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from io import StringIO

from .model import (
    GovernanceProject, DatabaseConfig, SchemaConfig, TableConfig,
    ColumnConfig, IndexConfig, ForeignKeyConfig,
    TablePermissionConfig, SchemaPermissionConfig, RoleConfig, StrEnum,
    MaskConfig, FullMaskConfig, PartialMaskConfig, HashMaskConfig,
    EmailMaskConfig, PhoneMaskConfig, CreditCardMaskConfig,
    IpAddressMaskConfig, NameMaskConfig,
)


def _yaml() -> YAML:
    y = YAML()
    y.default_flow_style = False
    y.allow_unicode = True
    y.width = 120
    return y


def _val(v) -> str:
    """Coerce enum values to their string representation for YAML output."""
    if isinstance(v, StrEnum):
        return str(v)
    return v


class Serializer:

    # =====================================================
    # PUBLIC
    # =====================================================

    @classmethod
    def to_yaml_string(cls, project: GovernanceProject) -> str:
        doc = cls.serialize(project)
        y = _yaml()
        buf = StringIO()
        y.dump(doc, buf)
        return buf.getvalue()

    @classmethod
    def serialize(cls, project: GovernanceProject) -> CommentedMap:
        return cls._serialize_project(project)

    # =====================================================
    # PROJECT
    # =====================================================

    @classmethod
    def _serialize_project(cls, project: GovernanceProject) -> CommentedMap:
        doc = CommentedMap()
        doc["database"] = cls._serialize_database(project.database)
        doc["schemas"]  = CommentedSeq([cls._serialize_schema(s) for s in project.schemas])
        doc["roles"]    = CommentedSeq([cls._serialize_role(r) for r in project.roles])
        return doc

    # =====================================================
    # DATABASE
    # =====================================================

    @classmethod
    def _serialize_database(cls, db: DatabaseConfig) -> CommentedMap:
        m = CommentedMap()
        m["name"]             = db.name
        if db.description:
            m["description"]  = db.description
        m["engine"]           = _val(db.engine)
        m["host"]             = db.host
        m["port"]             = db.port
        m["database"]         = db.database
        m["audit_enabled"]    = db.audit_enabled
        if db.audit_enabled:
            m["audit_logged"] = [_val(level) for level in db.audit_logged]
        if db.profile:
            m["profile"]      = db.profile
        if db.owner:
            m["owner"]         = db.owner
        return m

    # =====================================================
    # SCHEMA
    # =====================================================

    @classmethod
    def _serialize_schema(cls, schema: SchemaConfig) -> CommentedMap:
        m = CommentedMap()
        m["name"] = schema.name
        if schema.description:
            m["description"] = schema.description
        m["clearance"]     = schema.clearance
        m["audit_enabled"] = schema.audit_enabled
        m["tables"]        = CommentedSeq([cls._serialize_table(t) for t in schema.tables])
        if schema.views:
            m["views"] = list(schema.views)
        if schema.materialized_views:
            m["materialized_views"] = list(schema.materialized_views)
        if schema.functions:
            m["functions"] = list(schema.functions)
        if schema.trigger_functions:
            m["trigger_functions"] = list(schema.trigger_functions)
        if schema.sequences:
            m["sequences"] = list(schema.sequences)
        if schema.types:
            m["types"] = list(schema.types)
        if schema.collations:
            m["collations"] = list(schema.collations)
        if schema.domains:
            m["domains"] = list(schema.domains)
        if schema.aggregates:
            m["aggregates"] = list(schema.aggregates)
        if schema.operators:
            m["operators"] = list(schema.operators)
        if schema.procedures:
            m["procedures"] = list(schema.procedures)
        if schema.foreign_tables:
            m["foreign_tables"] = list(schema.foreign_tables)
        if schema.fts_configurations:
            m["fts_configurations"] = list(schema.fts_configurations)
        if schema.fts_dictionaries:
            m["fts_dictionaries"] = list(schema.fts_dictionaries)
        if schema.fts_parsers:
            m["fts_parsers"] = list(schema.fts_parsers)
        if schema.fts_templates:
            m["fts_templates"] = list(schema.fts_templates)
        return m

    # =====================================================
    # TABLE
    # =====================================================

    @classmethod
    def _serialize_table(cls, table: TableConfig) -> CommentedMap:
        m = CommentedMap()
        m["name"] = table.name
        if table.description:
            m["description"] = table.description
        m["clearance"]     = table.clearance
        m["audit_enabled"] = table.audit_enabled
        m["columns"]       = CommentedSeq([cls._serialize_column(c) for c in table.columns])
        if table.indexes:
            m["indexes"] = CommentedSeq([cls._serialize_index(i) for i in table.indexes])
        if table.foreign_keys:
            m["foreign_keys"] = CommentedSeq([cls._serialize_fk(f) for f in table.foreign_keys])
        return m

    # =====================================================
    # COLUMN
    # =====================================================

    @classmethod
    def _serialize_column(cls, col: ColumnConfig) -> CommentedMap:
        m = CommentedMap()
        m["name"] = col.name
        if col.description:
            m["description"] = col.description
        m["type"]             = col.type
        m["clearance"]        = col.clearance
        m["nullable"]         = col.nullable
        m["unique"]           = col.unique
        m["immutable"]        = col.immutable
        m["versioned"]        = col.versioned
        m["sensitive"]        = col.sensitive
        m["encrypted"]        = col.encrypted
        m["masking_strategy"] = _val(col.masking_strategy)
        if col.mask_config is not None:
            m["mask_config"] = cls._serialize_mask_config(col.mask_config)
        if col.default is not None:
            m["default"] = col.default
        if col.generated_expression is not None:
            m["generated_expression"] = col.generated_expression
            m["generated_storage"]    = _val(col.generated_storage)
        return m

    @classmethod
    def _serialize_mask_config(cls, cfg: MaskConfig) -> CommentedMap:
        m = CommentedMap()
        m["hide_null"] = cfg.hide_null

        if isinstance(cfg, PartialMaskConfig):
            m["type"]           = "partial"
            m["visible_length"] = cfg.visible_length
            m["visible_side"]   = _val(cfg.visible_side)
            m["mask_char"]      = cfg.mask_char
        elif isinstance(cfg, FullMaskConfig):
            m["type"]      = "full"
            m["mask_char"] = cfg.mask_char
        elif isinstance(cfg, HashMaskConfig):
            m["type"] = "hash"
        elif isinstance(cfg, EmailMaskConfig):
            m["type"]      = "email"
            m["mask_char"] = cfg.mask_char
        elif isinstance(cfg, PhoneMaskConfig):
            m["type"]           = "phone"
            m["visible_digits"] = cfg.visible_digits
            m["mask_char"]      = cfg.mask_char
        elif isinstance(cfg, CreditCardMaskConfig):
            m["type"]      = "credit_card"
            m["mask_char"] = cfg.mask_char
        elif isinstance(cfg, IpAddressMaskConfig):
            m["type"]            = "ip_address"
            m["visible_octets"]  = cfg.visible_octets
            m["mask_char"]       = cfg.mask_char
        elif isinstance(cfg, NameMaskConfig):
            m["type"]      = "name"
            m["mask_char"] = cfg.mask_char

        return m

    # =====================================================
    # INDEX
    # =====================================================

    @classmethod
    def _serialize_index(cls, idx: IndexConfig) -> CommentedMap:
        m = CommentedMap()
        m["name"]       = idx.name
        m["columns"]    = list(idx.columns)
        m["index_type"] = _val(idx.index_type)
        m["unique"]     = idx.unique
        m["primary_key"] = idx.primary_key
        if idx.partial_filter is not None:
            m["partial_filter"] = idx.partial_filter
        return m

    # =====================================================
    # FOREIGN KEY
    # =====================================================

    @classmethod
    def _serialize_fk(cls, fk: ForeignKeyConfig) -> CommentedMap:
        m = CommentedMap()
        m["name"]               = fk.name
        m["column"]             = fk.column
        m["referenced_schema"]  = fk.referenced_schema
        m["referenced_table"]   = fk.referenced_table
        m["referenced_column"]  = fk.referenced_column
        return m

    # =====================================================
    # PERMISSIONS
    # =====================================================

    @classmethod
    def _serialize_table_permission(cls, tp: TablePermissionConfig) -> CommentedMap:
        m = CommentedMap()
        m["table"]      = tp.name
        m["select"]     = tp.select
        m["insert"]     = tp.insert
        m["update"]     = tp.update
        m["delete"]     = tp.delete
        m["truncate"]   = tp.truncate
        m["references"] = tp.references
        m["trigger"]    = tp.trigger
        m["maintain"]   = tp.maintain
        return m

    @classmethod
    def _serialize_schema_permission(cls, sp: SchemaPermissionConfig) -> CommentedMap:
        m = CommentedMap()
        m["schema"] = sp.name
        m["usage"]  = sp.usage
        m["create"] = sp.create
        if sp.tables:
            m["tables"] = CommentedSeq([cls._serialize_table_permission(t) for t in sp.tables])
        return m

    # =====================================================
    # ROLE
    # =====================================================

    @classmethod
    def _serialize_role(cls, role: RoleConfig) -> CommentedMap:
        m = CommentedMap()
        m["name"] = role.name
        if role.description:
            m["description"] = role.description
        m["clearance"]            = role.clearance
        m["active"]               = role.active
        m["can_login"]            = role.can_login
        m["can_admin"]            = role.can_admin
        m["can_write"]            = role.can_write
        m["can_maintain"]         = role.can_maintain
        m["can_access_sensitive"] = role.can_access_sensitive
        if role.member_of:
            m["member_of"] = list(role.member_of)
        if role.on:
            m["on"] = CommentedSeq([cls._serialize_schema_permission(o) for o in role.on])
        return m
