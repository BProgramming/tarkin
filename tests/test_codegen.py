"""Unit tests for SQL code generation."""
from __future__ import annotations
import pytest

from tarkin.codegen import (
    _generate_comments,
    _generate_discovery_functions,
    _generate_governance_view,
    _generate_meta_schema,
    _generate_grants,
    _generate_audit,
    _generate_audit_grants,
    _generate_views,
    _generate_triggers,
    _generate_shadow_schemas,
    _generate_roles,
)
from tarkin.model import (
    GovernanceProject,
    DatabaseConfig,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    IndexConfig,
    RoleConfig,
    SchemaPermissionConfig,
    TablePermissionConfig,
    AuditLogLevel,
    MaskingStrategy,
    FullMaskConfig,
    HashMaskConfig,
    HashAlgorithm,
)
from tarkin.utils import (
    emit_per_build_inserts,
)


def _make_pk_column(name: str = "id") -> ColumnConfig:
    return ColumnConfig(name=name, type="bigint", nullable=False)


def _make_pk_index(col: str = "id") -> IndexConfig:
    return IndexConfig(name=f"pk_{col}", columns=[col], primary_key=True, unique=True)


def _make_table_with_pk(name: str = "users", extra_cols: list | None = None) -> TableConfig:
    cols = [_make_pk_column()]
    if extra_cols:
        cols.extend(extra_cols)
    return TableConfig(name=name, columns=cols, indexes=[_make_pk_index()])


def _make_project(
    owner:   str         = "admin",
    schemas: list | None = None,
    roles:   list | None = None,
) -> GovernanceProject:
    return GovernanceProject(
        database = DatabaseConfig(name="testdb", owner=owner),
        schemas  = schemas or [SchemaConfig(name="public", tables=[_make_table_with_pk()])],
        roles    = roles or [],
    )


def _make_full_role(
    name:   str,
    schema: str = "public",
    table:  str = "users",
    **perms,
) -> RoleConfig:
    tp = TablePermissionConfig(name=table, **perms)
    sp = SchemaPermissionConfig(name=schema, usage=True, tables=[tp])
    return RoleConfig(name=name, can_login=True, on=[sp])

class TestGenerateShadowSchemas:

    def test_renames_schema_to_shadow(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_shadow_schemas(proj)
        assert 'ALTER SCHEMA "public" RENAME TO "tk_public"' in sql

    def test_creates_new_schema(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_shadow_schemas(proj)
        assert 'CREATE SCHEMA "public"' in sql

    def test_multiple_schemas(self) -> None:
        schemas = [
            SchemaConfig(name="public", tables=[_make_table_with_pk()]),
            SchemaConfig(name="sales",  tables=[_make_table_with_pk("orders")]),
        ]
        proj = _make_project(schemas=schemas)
        sql  = _generate_shadow_schemas(proj)
        assert '"tk_public"' in sql
        assert '"tk_sales"' in sql

class TestGenerateGrants:

    def test_shadow_schema_revoked_for_non_owner(self) -> None:
        role = _make_full_role("reader", select=True)
        proj = _make_project(owner="admin", roles=[role])
        sql  = _generate_grants(proj)
        assert 'REVOKE ALL ON SCHEMA "tk_public" FROM "reader"' in sql
        assert 'REVOKE ALL ON ALL TABLES IN SCHEMA "tk_public" FROM "reader"' in sql

    def test_shadow_schema_not_revoked_for_owner(self) -> None:
        role = _make_full_role("admin", select=True)
        proj = _make_project(owner="admin", roles=[role])
        sql  = _generate_grants(proj)
        assert 'REVOKE ALL ON SCHEMA "tk_public" FROM "admin"' not in sql

    def test_schema_usage_grant(self) -> None:
        role = _make_full_role("reader", select=True)
        proj = _make_project(roles=[role])
        sql  = _generate_grants(proj)
        assert 'GRANT USAGE ON SCHEMA "public" TO "reader"' in sql

    def test_table_select_grant(self) -> None:
        role = _make_full_role("reader", select=True)
        proj = _make_project(roles=[role])
        sql  = _generate_grants(proj)
        assert 'GRANT SELECT ON "public"."users" TO "reader"' in sql

    def test_table_insert_grant(self) -> None:
        role = _make_full_role("writer", select=True, insert=True)
        proj = _make_project(roles=[role])
        sql  = _generate_grants(proj)
        assert "INSERT" in sql

    def test_table_skipped_when_clearance_insufficient(self) -> None:
        table = TableConfig(
            name      = "secrets",
            clearance = 5,
            columns   = [ColumnConfig(name="id", type="bigint", clearance=0)],
            indexes   = [_make_pk_index()],
        )
        schema = SchemaConfig(name="public", tables=[table])
        role   = _make_full_role("low_reader", table="secrets", select=True)
        role.clearance = 0
        proj   = _make_project(schemas=[schema], roles=[role])
        sql    = _generate_grants(proj)
        assert "SKIPPED" in sql
        assert 'GRANT SELECT ON "public"."secrets"' not in sql

    def test_column_level_select_restriction(self) -> None:
        normal_col = ColumnConfig(name="id",     type="bigint", clearance=0, nullable=False)
        high_col   = ColumnConfig(name="secret", type="text",   clearance=2)
        table      = TableConfig(name="data", columns=[normal_col, high_col], indexes=[_make_pk_index()])
        schema     = SchemaConfig(name="public", tables=[table])
        role       = _make_full_role("reader", table="data", select=True)
        role.clearance = 0
        proj       = _make_project(schemas=[schema], roles=[role])
        sql        = _generate_grants(proj)
        assert 'REVOKE SELECT ON "public"."data" FROM "reader"' in sql
        assert 'GRANT SELECT ("id") ON "public"."data" TO "reader"' in sql

    def test_column_level_update_restriction(self) -> None:
        normal_col = ColumnConfig(name="id",     type="bigint", clearance=0, nullable=False)
        high_col   = ColumnConfig(name="secret", type="text",   clearance=2)
        table      = TableConfig(name="data", columns=[normal_col, high_col], indexes=[_make_pk_index()])
        schema     = SchemaConfig(name="public", tables=[table])
        role       = _make_full_role("writer", table="data", select=True, update=True)
        role.clearance = 0
        proj       = _make_project(schemas=[schema], roles=[role])
        sql        = _generate_grants(proj)
        assert 'REVOKE UPDATE ON "public"."data" FROM "writer"' in sql
        assert 'GRANT UPDATE ("id") ON "public"."data" TO "writer"' in sql

    def test_column_level_references_restriction(self) -> None:
        normal_col = ColumnConfig(name="id",     type="bigint", clearance=0, nullable=False)
        high_col   = ColumnConfig(name="secret", type="text",   clearance=2)
        table      = TableConfig(name="data", columns=[normal_col, high_col], indexes=[_make_pk_index()])
        schema     = SchemaConfig(name="public", tables=[table])
        role       = _make_full_role("ref_role", table="data", select=True, references=True)
        role.clearance = 0
        proj       = _make_project(schemas=[schema], roles=[role])
        sql        = _generate_grants(proj)
        assert 'REVOKE REFERENCES ON "public"."data" FROM "ref_role"' in sql
        assert 'GRANT REFERENCES ("id") ON "public"."data" TO "ref_role"' in sql

    def test_insert_warning_when_restricted_columns(self) -> None:
        normal_col = ColumnConfig(name="id",     type="bigint", clearance=0, nullable=False)
        high_col   = ColumnConfig(name="secret", type="text",   clearance=2)
        table      = TableConfig(name="data", columns=[normal_col, high_col], indexes=[_make_pk_index()])
        schema     = SchemaConfig(name="public", tables=[table])
        role       = _make_full_role("writer", table="data", select=True, insert=True)
        role.clearance = 0
        proj       = _make_project(schemas=[schema], roles=[role])
        with pytest.warns(UserWarning, match="INSERT"):
            _generate_grants(proj)

    def test_owner_exempted_from_column_revokes_with_warning(self) -> None:
        normal_col = ColumnConfig(name="id",     type="bigint", clearance=0, nullable=False)
        high_col   = ColumnConfig(name="secret", type="text",   clearance=2)
        table      = TableConfig(name="data", columns=[normal_col, high_col], indexes=[_make_pk_index()])
        schema     = SchemaConfig(name="public", tables=[table])
        role       = _make_full_role("admin", table="data", select=True)
        role.clearance = 0
        proj       = _make_project(owner="admin", schemas=[schema], roles=[role])
        with pytest.warns(UserWarning, match="database owner"):
            sql = _generate_grants(proj)
        assert 'REVOKE SELECT ON "public"."data" FROM "admin"' not in sql

    def test_no_accessible_columns_skips_table(self) -> None:
        high_col = ColumnConfig(name="secret", type="text", clearance=5)
        table    = TableConfig(name="vault", columns=[high_col], indexes=[_make_pk_index()])
        schema   = SchemaConfig(name="public", tables=[table])
        role     = _make_full_role("reader", table="vault", select=True)
        role.clearance = 0
        proj     = _make_project(schemas=[schema], roles=[role])
        sql      = _generate_grants(proj)
        assert "SKIPPED" in sql
        assert 'GRANT SELECT ON "public"."vault"' not in sql

    def test_sensitive_column_restricted_without_can_access_sensitive(self) -> None:
        normal_col    = ColumnConfig(name="id",  type="bigint", clearance=0, nullable=False)
        sensitive_col = ColumnConfig(name="ssn", type="text",   clearance=0, sensitive=True)
        table         = TableConfig(name="patients", columns=[normal_col, sensitive_col], indexes=[_make_pk_index()])
        schema        = SchemaConfig(name="public", tables=[table])
        role          = _make_full_role("basic", table="patients", select=True)
        role.can_access_sensitive = False
        proj          = _make_project(schemas=[schema], roles=[role])
        sql           = _generate_grants(proj)
        assert 'REVOKE SELECT ON "public"."patients" FROM "basic"' in sql

    def test_sensitive_column_accessible_with_can_access_sensitive(self) -> None:
        normal_col    = ColumnConfig(name="id",  type="bigint", clearance=0, nullable=False)
        sensitive_col = ColumnConfig(name="ssn", type="text",   clearance=0, sensitive=True)
        table         = TableConfig(name="patients", columns=[normal_col, sensitive_col], indexes=[_make_pk_index()])
        schema        = SchemaConfig(name="public", tables=[table])
        role          = _make_full_role("phi_reader", table="patients", select=True)
        role.can_access_sensitive = True
        proj          = _make_project(schemas=[schema], roles=[role])
        sql           = _generate_grants(proj)
        assert 'REVOKE SELECT ON "public"."patients" FROM "phi_reader"' not in sql

    def test_sensitive_unmasked_column_emits_warning(self) -> None:
        sensitive_col = ColumnConfig(name="ssn", type="text", clearance=0, sensitive=True,
                                     masking_strategy=MaskingStrategy.NONE)
        normal_col    = ColumnConfig(name="id",  type="bigint", clearance=0, nullable=False)
        table         = TableConfig(name="t", columns=[normal_col, sensitive_col], indexes=[_make_pk_index()])
        schema        = SchemaConfig(name="public", tables=[table])
        role          = _make_full_role("r", table="t", select=True)
        role.can_access_sensitive = True
        proj          = _make_project(schemas=[schema], roles=[role])
        with pytest.warns(UserWarning, match="sensitive but has no masking strategy"):
            _generate_grants(proj)

    def test_all_roles_can_access_sensitive_emits_warning(self) -> None:
        sensitive_col = ColumnConfig(name="ssn", type="text", clearance=0, sensitive=True)
        normal_col    = ColumnConfig(name="id",  type="bigint", clearance=0, nullable=False)
        table         = TableConfig(name="t", columns=[normal_col, sensitive_col], indexes=[_make_pk_index()])
        schema        = SchemaConfig(name="public", tables=[table])
        role          = _make_full_role("r", table="t", select=True)
        role.can_access_sensitive = True
        proj          = _make_project(schemas=[schema], roles=[role])
        with pytest.warns(UserWarning, match="All roles have can_access_sensitive"):
            _generate_grants(proj)


class TestGenerateAudit:

    def test_returns_comment_when_disabled(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = False
        sql  = _generate_audit(proj)
        assert "not enabled" in sql
        assert "DO $tk_outer$" not in sql

    def test_contains_pgaudit_log_merge_block(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = True
        proj.database.audit_logged = [AuditLogLevel.DDL, AuditLogLevel.WRITE]
        sql  = _generate_audit(proj)
        assert "DO $tk_outer$" in sql
        assert "pgaudit.log" in sql
        assert "string_agg" in sql
        assert "ddl" in sql
        assert "write" in sql

    def test_log_catalog_block_present(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = True
        proj.database.audit_logged = [AuditLogLevel.DDL]
        sql  = _generate_audit(proj)
        assert "log_catalog" in sql

    def test_log_relation_block_present(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = True
        proj.database.audit_logged = [AuditLogLevel.DDL]
        sql  = _generate_audit(proj)
        assert "log_relation" in sql

    def test_excluded_tables_listed_as_comments(self) -> None:
        table = TableConfig(
            name          = "noisy",
            columns       = [ColumnConfig(name="id", type="bigint")],
            indexes       = [_make_pk_index()],
            audit_enabled = False,
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        proj.database.audit_enabled = True
        proj.database.audit_logged = [AuditLogLevel.DDL]
        sql    = _generate_audit(proj)
        assert "noisy" in sql
        assert "audit_enabled=false" in sql

    def test_is_additive_not_destructive(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = True
        proj.database.audit_logged = [AuditLogLevel.DDL]
        sql  = _generate_audit(proj)
        assert "current_setting" in sql
        assert "EXECUTE format(" in sql


class TestGenerateViews:

    def test_creates_view_for_each_table(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk("orders")])])
        sql  = _generate_views(proj)
        assert 'CREATE VIEW "public"."orders"' in sql

    def test_view_selects_from_shadow_schema(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk("orders")])])
        sql  = _generate_views(proj)
        assert '"tk_public"."orders"' in sql

    def test_versioned_table_gets_current_view(self) -> None:
        versioned_col = ColumnConfig(name="name", type="text", versioned=True)
        table         = _make_table_with_pk("events", extra_cols=[versioned_col])
        schema        = SchemaConfig(name="public", tables=[table])
        proj          = _make_project(schemas=[schema])
        sql           = _generate_views(proj)
        assert 'CREATE VIEW "public"."events_current"' in sql
        assert "__valid_to__" in sql

    def test_non_versioned_table_has_no_current_view(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_views(proj)
        assert '"users_current"' not in sql

    def test_masking_applied_in_view(self) -> None:
        id_col    = _make_pk_column()
        email_col = ColumnConfig(
            name             = "email",
            type             = "text",
            masking_strategy = MaskingStrategy.FULL,
            mask_config      = FullMaskConfig(mask_char="*"),
        )
        table  = TableConfig(name="contacts", columns=[id_col, email_col], indexes=[_make_pk_index()])
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_views(proj)
        assert "regexp_replace" in sql

    def test_multiple_schemas_produce_multiple_views(self) -> None:
        s1   = SchemaConfig(name="public", tables=[_make_table_with_pk("users")])
        s2   = SchemaConfig(name="sales",  tables=[_make_table_with_pk("orders")])
        proj = _make_project(schemas=[s1, s2])
        sql  = _generate_views(proj)
        assert '"public"."users"' in sql
        assert '"sales"."orders"' in sql
        assert '"tk_public"' in sql
        assert '"tk_sales"' in sql

    def test_xxhash_uses_hashtextextended(self) -> None:
        id_col   = _make_pk_column()
        hash_col = ColumnConfig(
            name             = "token",
            type             = "text",
            masking_strategy = MaskingStrategy.HASH,
            mask_config      = HashMaskConfig(algorithm=HashAlgorithm.XXHASH),
        )
        table  = TableConfig(name="users", columns=[id_col, hash_col], indexes=[_make_pk_index()])
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        with pytest.warns(UserWarning, match="non-cryptographic"):
            sql = _generate_views(proj)
        assert "hashtextextended" in sql
        assert "digest" not in sql

    def test_sha256_uses_digest(self) -> None:
        id_col   = _make_pk_column()
        hash_col = ColumnConfig(
            name             = "token",
            type             = "text",
            masking_strategy = MaskingStrategy.HASH,
            mask_config      = HashMaskConfig(algorithm=HashAlgorithm.SHA256),
        )
        table    = TableConfig(name="users", columns=[id_col, hash_col], indexes=[_make_pk_index()])
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = _make_project(schemas=[schema])
        with pytest.warns(UserWarning, match="dictionary attacks"):
            sql = _generate_views(proj)
        assert "digest" in sql
        assert "sha256" in sql
        assert "encode" in sql

    def test_sha512_uses_digest(self) -> None:
        id_col   = _make_pk_column()
        hash_col = ColumnConfig(
            name             = "token",
            type             = "text",
            masking_strategy = MaskingStrategy.HASH,
            mask_config      = HashMaskConfig(algorithm=HashAlgorithm.SHA512),
        )
        table    = TableConfig(name="users", columns=[id_col, hash_col], indexes=[_make_pk_index()])
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = _make_project(schemas=[schema])
        with pytest.warns(UserWarning, match="dictionary attacks"):
            sql = _generate_views(proj)
        assert "digest" in sql
        assert "sha512" in sql
        assert "encode" in sql

    def test_hmac256_uses_hmac_and_current_setting(self) -> None:
        id_col   = _make_pk_column()
        hash_col = ColumnConfig(
            name             = "token",
            type             = "text",
            masking_strategy = MaskingStrategy.HASH,
            mask_config      = HashMaskConfig(algorithm=HashAlgorithm.HMAC256),
        )
        table    = TableConfig(name="users", columns=[id_col, hash_col], indexes=[_make_pk_index()])
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = _make_project(schemas=[schema])
        sql      = _generate_views(proj)
        assert "hmac(" in sql
        assert "current_setting('tarkin.hmac_key')" in sql
        assert "sha256" in sql
        assert "encode" in sql

    def test_xxhash_hide_null_uses_hashtextextended(self) -> None:
        id_col   = _make_pk_column()
        hash_col = ColumnConfig(
            name             = "token",
            type             = "text",
            masking_strategy = MaskingStrategy.HASH,
            mask_config      = HashMaskConfig(algorithm=HashAlgorithm.XXHASH, hide_null=True),
        )
        table    = TableConfig(name="users", columns=[id_col, hash_col], indexes=[_make_pk_index()])
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = _make_project(schemas=[schema])
        with pytest.warns(UserWarning):
            sql = _generate_views(proj)
        assert "COALESCE" in sql
        assert "hashtextextended('', 0)" in sql

    def test_sha256_hide_null_uses_digest_empty_string(self) -> None:
        id_col   = _make_pk_column()
        hash_col = ColumnConfig(
            name             = "token",
            type             = "text",
            masking_strategy = MaskingStrategy.HASH,
            mask_config      = HashMaskConfig(algorithm=HashAlgorithm.SHA256, hide_null=True),
        )
        table    = TableConfig(name="users", columns=[id_col, hash_col], indexes=[_make_pk_index()])
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = _make_project(schemas=[schema])
        with pytest.warns(UserWarning):
            sql = _generate_views(proj)
        assert "COALESCE" in sql
        assert "digest('', 'sha256')" in sql

    def test_hmac256_hide_null_uses_hmac_empty_string(self) -> None:
        id_col   = _make_pk_column()
        hash_col = ColumnConfig(
            name             = "token",
            type             = "text",
            masking_strategy = MaskingStrategy.HASH,
            mask_config      = HashMaskConfig(algorithm=HashAlgorithm.HMAC256, hide_null=True),
        )
        table    = TableConfig(name="users", columns=[id_col, hash_col], indexes=[_make_pk_index()])
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = _make_project(schemas=[schema])
        sql = _generate_views(proj)
        assert "COALESCE" in sql
        assert "hmac(''" in sql
        assert "current_setting('tarkin.hmac_key')" in sql

    def test_current_view_uses_infinity_predicate(self) -> None:
        versioned_col = ColumnConfig(name="name", type="text", versioned=True)
        table         = _make_table_with_pk("events", extra_cols=[versioned_col])
        schema        = SchemaConfig(name="public", tables=[table])
        proj          = _make_project(schemas=[schema])
        sql           = _generate_views(proj)
        assert "__valid_to__ = 'infinity'::timestamptz" in sql
        assert "__valid_to__ >= now()" not in sql


class TestGenerateTriggers:

    def test_creates_trigger_function(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_triggers(proj)
        assert 'CREATE OR REPLACE FUNCTION "tk_public"."tr_users"()' in sql

    def test_creates_instead_of_trigger(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_triggers(proj)
        assert "INSTEAD OF INSERT OR UPDATE OR DELETE" in sql
        assert 'ON "public"."users"' in sql

    def test_trigger_function_handles_insert(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_triggers(proj)
        assert "TG_OP = 'INSERT'" in sql

    def test_trigger_function_handles_update(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_triggers(proj)
        assert "TG_OP = 'UPDATE'" in sql

    def test_trigger_function_handles_delete(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_triggers(proj)
        assert "TG_OP = 'DELETE'" in sql

    def test_delete_trigger_uses_old_pk(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_triggers(proj)
        delete_idx = sql.index("TG_OP = 'DELETE'")
        delete_section = sql[delete_idx:]
        assert 'OLD."id"' in delete_section
        assert 'WHERE "id" = OLD."id"' in delete_section

    def test_versioned_delete_trigger_uses_old_pk(self) -> None:
        """Issue 13: versioned DELETE (UPDATE __valid_to__) must also use OLD.pk."""
        versioned_col = ColumnConfig(name="value", type="text", versioned=True)
        table  = _make_table_with_pk("events", extra_cols=[versioned_col])
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_triggers(proj)
        delete_idx = sql.index("TG_OP = 'DELETE'")
        delete_section = sql[delete_idx:]
        assert 'OLD."id"' in delete_section

    def test_versioned_table_uses_valid_to_pattern(self) -> None:
        versioned_col = ColumnConfig(name="value", type="text", versioned=True)
        table  = _make_table_with_pk("events", extra_cols=[versioned_col])
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_triggers(proj)
        assert "__valid_from__" in sql
        assert "__valid_to__" in sql
        assert "'infinity'::timestamptz" in sql

    def test_non_versioned_table_uses_direct_update(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[_make_table_with_pk()])])
        sql  = _generate_triggers(proj)
        assert "__valid_to__" not in sql

    def test_immutable_column_generates_check(self) -> None:
        id_col  = _make_pk_column()
        imm_col = ColumnConfig(name="created_at", type="timestamptz", immutable=True)
        table   = TableConfig(name="ledger", columns=[id_col, imm_col], indexes=[_make_pk_index()])
        schema  = SchemaConfig(name="public", tables=[table])
        proj    = _make_project(schemas=[schema])
        sql     = _generate_triggers(proj)
        assert "created_at" in sql
        assert "RAISE EXCEPTION" in sql

    def test_no_pk_raises_value_error(self) -> None:
        col    = ColumnConfig(name="value", type="text")
        table  = TableConfig(name="no_pk_table", columns=[col], indexes=[])
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        with pytest.raises(ValueError, match="primary key"):
            _generate_triggers(proj)

    def test_pk_filter_uses_only_pk_column(self) -> None:
        id_col   = _make_pk_column("uuid")
        name_col = ColumnConfig(name="name", type="text")
        table    = TableConfig(
            name    = "things",
            columns = [id_col, name_col],
            indexes = [IndexConfig(name="pk_things", columns=["uuid"], primary_key=True, unique=True)],
        )
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = _make_project(schemas=[schema])
        sql      = _generate_triggers(proj)
        assert 'WHERE "uuid" = NEW."uuid"' in sql
        assert 'WHERE "name"' not in sql


class TestGenerateRoles:

    @staticmethod
    def _make_current(role_names: list[str]) -> GovernanceProject:
        roles = [
            RoleConfig(name=n, can_login=True, on=[SchemaPermissionConfig(name="public")])
            for n in role_names
        ]
        return _make_project(roles=roles)

    def test_creates_new_role(self) -> None:
        proj    = _make_project(roles=[_make_full_role("new_role")])
        current = _make_project(roles=[])
        sql     = _generate_roles(proj, current)
        assert 'CREATE ROLE "new_role"' in sql

    def test_alters_existing_role(self) -> None:
        role    = _make_full_role("existing")
        proj    = _make_project(roles=[role])
        current = _make_project(roles=[role])
        sql     = _generate_roles(proj, current)
        assert 'ALTER ROLE "existing"' in sql
        assert 'CREATE ROLE "existing"' not in sql

    def test_login_role_gets_login_clause(self) -> None:
        role    = _make_full_role("login_role")
        role.can_login = True
        proj    = _make_project(roles=[role])
        current = _make_project(roles=[])
        sql     = _generate_roles(proj, current)
        assert " LOGIN" in sql

    def test_nologin_role_gets_nologin_clause(self) -> None:
        role    = _make_full_role("svc_role")
        role.can_login = False
        proj    = _make_project(roles=[role])
        current = _make_project(roles=[])
        sql     = _generate_roles(proj, current)
        assert "NOLOGIN" in sql

    def test_member_of_grant_emitted(self) -> None:
        parent  = _make_full_role("parent_role")
        child   = _make_full_role("child_role")
        child.member_of = ["parent_role"]
        proj    = _make_project(roles=[parent, child])
        current = _make_project(roles=[])
        sql     = _generate_roles(proj, current)
        assert 'GRANT "parent_role" TO "child_role"' in sql

    def test_superuser_role_gets_superuser_clause(self) -> None:
        role    = _make_full_role("dba")
        role.can_admin = True
        proj    = _make_project(roles=[role])
        current = _make_project(roles=[])
        sql     = _generate_roles(proj, current)
        assert "SUPERUSER" in sql
        assert "NOSUPERUSER" not in sql


class TestGenerateAuditGrants:

    def test_returns_comment_when_audit_disabled(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = False
        sql  = _generate_audit_grants(proj)
        assert "GRANT" not in sql
        assert "skipped" in sql.casefold()

    def test_grants_on_audited_shadow_table(self) -> None:
        table  = TableConfig(
            name          = "orders",
            columns       = [ColumnConfig(name="id", type="bigint")],
            indexes       = [_make_pk_index()],
            audit_enabled = True,
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        proj.database.audit_enabled = True
        proj.database.audit_logged  = [AuditLogLevel.DDL]
        sql    = _generate_audit_grants(proj)
        assert 'GRANT SELECT, INSERT, UPDATE, DELETE ON "tk_public"."orders" TO tarkin_audit' in sql

    def test_skips_non_audited_table(self) -> None:
        audited     = TableConfig(
            name          = "audited",
            columns       = [ColumnConfig(name="id", type="bigint")],
            indexes       = [_make_pk_index()],
            audit_enabled = True,
        )
        not_audited = TableConfig(
            name          = "silent",
            columns       = [ColumnConfig(name="id", type="bigint")],
            indexes       = [_make_pk_index()],
            audit_enabled = False,
        )
        schema = SchemaConfig(name="public", tables=[audited, not_audited])
        proj   = _make_project(schemas=[schema])
        proj.database.audit_enabled = True
        proj.database.audit_logged  = [AuditLogLevel.DDL]
        sql    = _generate_audit_grants(proj)
        assert '"tk_public"."audited"' in sql
        assert '"tk_public"."silent"' not in sql

    def test_returns_no_tables_comment_when_all_disabled(self) -> None:
        table  = TableConfig(
            name          = "quiet",
            columns       = [ColumnConfig(name="id", type="bigint")],
            indexes       = [_make_pk_index()],
            audit_enabled = False,
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        proj.database.audit_enabled = True
        proj.database.audit_logged  = [AuditLogLevel.DDL]
        sql    = _generate_audit_grants(proj)
        assert "GRANT" not in sql
        assert "No tables" in sql


class TestGenerateRolesAudit:

    def test_tarkin_audit_role_created_when_audit_enabled(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = True
        proj.database.audit_logged  = [AuditLogLevel.DDL]
        current = _make_project()
        sql     = _generate_roles(proj, current)
        assert "CREATE ROLE tarkin_audit" in sql
        assert "pgaudit.role" in sql

    def test_tarkin_audit_role_not_created_when_audit_disabled(self) -> None:
        proj    = _make_project()
        proj.database.audit_enabled = False
        current = _make_project()
        sql     = _generate_roles(proj, current)
        assert "tarkin_audit" not in sql


class TestGenerateGrantsMaintain:

    def test_maintain_grant_emits_version_guard_block(self) -> None:
        role = _make_full_role("maintainer", maintain=True)
        role.can_maintain = True
        proj = _make_project(roles=[role])
        proj.database.version = "16"
        sql  = _generate_grants(proj)
        assert "server_version_num" in sql
        assert "160000" in sql
        assert "MAINTAIN" in sql

    def test_maintain_grant_quotes_schema_and_table(self) -> None:
        role = _make_full_role("maintainer", maintain=True)
        role.can_maintain = True
        proj = _make_project(roles=[role])
        proj.database.version = "16"
        sql  = _generate_grants(proj)
        assert 'GRANT MAINTAIN ON "public"."users"' in sql

    def test_maintain_skipped_when_can_maintain_false(self) -> None:
        role = _make_full_role("reader", maintain=True)
        role.can_maintain = False
        proj = _make_project(roles=[role])
        proj.database.version = "16"
        with pytest.warns(UserWarning, match="can_maintain=False"):
            sql = _generate_grants(proj)
        assert "GRANT MAINTAIN" not in sql
        assert "server_version_num" not in sql

    def test_maintain_skipped_with_warning_on_old_version(self) -> None:
        role = _make_full_role("maintainer", maintain=True)
        role.can_maintain = True
        proj = _make_project(roles=[role])
        proj.database.version = "15"
        with pytest.warns(UserWarning, match="MAINTAIN"):
            sql = _generate_grants(proj)
        assert "server_version_num" not in sql

    def test_version_string_with_patch_does_not_crash(self) -> None:
        role = _make_full_role("maintainer", maintain=True)
        role.can_maintain = True
        proj = _make_project(roles=[role])
        proj.database.version = "16.2"
        sql = _generate_grants(proj)
        assert "MAINTAIN" in sql


class TestDescriptionPersistence:
    """Descriptions on schemas, tables, columns, and roles are written to META INSERTs."""

    def _emit(self, project) -> str:
        return emit_per_build_inserts(project, "1")

    def test_schema_description_inserted(self) -> None:
        proj = _make_project(schemas=[
            SchemaConfig(
                name        = "public",
                description = "Primary public-facing schema",
                tables      = [_make_table_with_pk()],
            )
        ])
        sql = self._emit(proj)
        assert "Primary public-facing schema" in sql

    def test_schema_null_description_inserts_null(self) -> None:
        proj = _make_project()
        sql  = self._emit(proj)
        # description column should be present and NULL when not set
        assert "tarkin_schemas" in sql
        assert "NULL" in sql

    def test_table_description_inserted(self) -> None:
        table = TableConfig(
            name        = "users",
            description = "One row per registered user",
            columns     = [_make_pk_column()],
            indexes     = [_make_pk_index()],
        )
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[table])])
        sql  = self._emit(proj)
        assert "One row per registered user" in sql

    def test_column_description_inserted(self) -> None:
        col = ColumnConfig(
            name        = "email",
            type        = "text",
            description = "User email address, unique per account",
        )
        table = TableConfig(
            name    = "users",
            columns = [_make_pk_column(), col],
            indexes = [_make_pk_index()],
        )
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[table])])
        sql  = self._emit(proj)
        assert "User email address, unique per account" in sql

    def test_description_with_single_quote_is_escaped(self) -> None:
        table = TableConfig(
            name        = "users",
            description = "User's primary table",
            columns     = [_make_pk_column()],
            indexes     = [_make_pk_index()],
        )
        proj = _make_project(schemas=[SchemaConfig(name="public", tables=[table])])
        sql  = self._emit(proj)
        assert "User''s primary table" in sql

    def test_role_description_inserted(self) -> None:
        # Role descriptions are emitted in _generate_meta_population, not emit_per_build_inserts.
        # Verify the field is accessible on the model.
        role = RoleConfig(name="reader", description="Read-only analytics role", can_login=True)
        assert role.description == "Read-only analytics role"


# ---------------------------------------------------------------------------
# Discovery functions
# ---------------------------------------------------------------------------

_DISCOVERY_FUNCTIONS = (
    "get_schemas", "get_tables", "get_columns", "get_roles",
    "get_build", "get_retention", "get_erasures",
    "get_erasure_counts", "get_rls_policies",
)


def _function_body(fn: str) -> str:
    """Return the SQL between a function's CREATE and its closing $tk_outer$."""
    sql   = _generate_discovery_functions()
    start = sql.index(f"CREATE OR REPLACE FUNCTION __META__.{fn}(")
    return sql[start:sql.index("$tk_outer$;", start)]


def _squash(sql: str) -> str:
    """Collapse runs of intra-line whitespace.

    The generated SQL is column-aligned for readability. Asserting against the
    aligned form couples these tests to the alignment, so a predicate assertion
    breaks the next time a longer identifier shifts a column.
    """
    return "\n".join(" ".join(line.split()) for line in sql.splitlines())


def _strip_sql_comments(sql: str) -> str:
    """Drop whole-line ``--`` comments.

    Counting keyword occurrences across the raw string counts the comments that
    describe those keywords as well as the calls that use them.
    """
    return "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    )


class TestGenerateDiscoveryFunctions:

    def test_all_functions_are_created(self) -> None:
        sql = _generate_discovery_functions()
        for fn in _DISCOVERY_FUNCTIONS:
            assert f"CREATE OR REPLACE FUNCTION __META__.{fn}(" in sql

    def test_all_functions_are_granted_to_public(self) -> None:
        sql = _generate_discovery_functions()
        for fn in _DISCOVERY_FUNCTIONS:
            assert f"GRANT EXECUTE ON FUNCTION __META__.{fn}(" in sql

    def test_all_functions_are_security_definer_and_stable(self) -> None:
        for fn in _DISCOVERY_FUNCTIONS:
            body = _function_body(fn)
            assert "SECURITY DEFINER" in body
            assert "STABLE" in body

    def test_all_functions_return_json(self) -> None:
        for fn in _DISCOVERY_FUNCTIONS:
            assert "RETURNS json" in _function_body(fn)

    def test_all_functions_emit_a_not_found_message(self) -> None:
        sql = _generate_discovery_functions()
        for fn in _DISCOVERY_FUNCTIONS:
            assert f"No results found for {fn} with parameters" in sql

    def test_latest_build_id_helper_is_created(self) -> None:
        sql = _generate_discovery_functions()
        assert "CREATE OR REPLACE FUNCTION __META__.tarkin_latest_build_id()" in sql

    def test_build_scoped_functions_use_the_helper(self) -> None:
        """The erasure log spans builds and carries no build_id, so it is exempt."""
        for fn in _DISCOVERY_FUNCTIONS:
            if fn in ("get_erasures",):
                continue
            assert "tarkin_latest_build_id()" in _function_body(fn)


class TestDiscoveryVisibilityRules:

    def test_table_scoped_functions_enforce_select_and_clearance(self) -> None:
        for fn in ("get_tables", "get_columns", "get_retention",
                   "get_erasure_counts", "get_rls_policies"):
            body = _squash(_function_body(fn))
            assert "rt.role_name = session_user" in body
            assert "rt.select = true" in body
            assert "clearance" in body

    def test_get_columns_gates_sensitive_columns(self) -> None:
        body = _function_body("get_columns")
        assert "r.can_access_sensitive = true" in body

    def test_get_roles_is_admin_or_self(self) -> None:
        body = _squash(_function_body("get_roles"))
        assert "self.can_admin = true" in body
        assert "OR r.name = session_user" in body

    def test_no_discovery_function_filters_on_current_user(self) -> None:
        """Regression: inside a SECURITY DEFINER function current_user resolves
        to the function owner, so every caller receives the owner's view of the
        model. session_user is the authenticated login role and is unaffected
        by the definer context.

        This is the assertion that has teeth. The per-function checks above
        confirm the right predicate is present; this one confirms the wrong one
        is absent everywhere, including in functions added later.
        """
        for fn in _DISCOVERY_FUNCTIONS:
            assert "current_user" not in _function_body(fn), (
                f"{fn} filters on current_user"
            )

    def test_get_erasures_requires_can_admin(self) -> None:
        body = _function_body("get_erasures")
        assert "self.can_admin = true" in body

    def test_get_erasure_counts_does_not_require_can_admin(self) -> None:
        """Counts carry no identifiers, so they follow the get_tables rule instead."""
        assert "can_admin" not in _function_body("get_erasure_counts")


class TestDiscoveryDisclosureLimits:

    def test_get_build_withholds_the_governance_yaml(self) -> None:
        body = _function_body("get_build")
        assert "yaml" not in body
        assert "b.profile" not in body
        assert "'checksum'" in body

    def test_get_build_requires_the_caller_to_be_in_the_build(self) -> None:
        body = _squash(_function_body("get_build"))
        assert "self.name = session_user" in body

    def test_get_erasures_withholds_erased_values(self) -> None:
        body = _function_body("get_erasures")
        assert "column_values" not in body
        assert "e.column_names" in body

    def test_get_erasure_counts_withholds_identifiers_and_actors(self) -> None:
        body = _function_body("get_erasure_counts")
        for leak in ("column_values", "column_names", "erased_by"):
            assert leak not in body


class TestDiscoveryRlsPolicies:

    def test_reads_live_policies_from_the_catalog(self) -> None:
        """Policies are emitted by _generate_rls but never persisted to __META__."""
        body = _function_body("get_rls_policies")
        assert "FROM pg_policies p" in body

    def test_maps_shadow_schema_back_to_public_name(self) -> None:
        body = _function_body("get_rls_policies")
        assert "s.shadow_name = p.schemaname" in body
        assert "'schema',     s.name" in body

    def test_exposes_both_policy_expressions(self) -> None:
        body = _function_body("get_rls_policies")
        assert "'using_expr', p.qual" in body
        assert "'check_expr', p.with_check" in body


# ---------------------------------------------------------------------------
# __META__ privileges
# ---------------------------------------------------------------------------

class TestMetaSchemaPrivileges:

    def test_meta_tables_are_revoked_from_public(self) -> None:
        sql = _generate_meta_schema()
        assert "REVOKE ALL ON SCHEMA __META__ FROM PUBLIC;" in sql
        assert "REVOKE ALL ON ALL TABLES IN SCHEMA __META__ FROM PUBLIC;" in sql

    def test_usage_is_granted_so_the_functions_are_reachable(self) -> None:
        """GRANT EXECUTE is unusable without schema USAGE — the name cannot resolve."""
        sql = _generate_meta_schema()
        assert "GRANT USAGE ON SCHEMA __META__ TO PUBLIC;" in sql

    def test_usage_grant_follows_the_revokes(self) -> None:
        sql = _generate_meta_schema()
        assert sql.index("REVOKE ALL ON SCHEMA __META__ FROM PUBLIC;") < \
               sql.index("GRANT USAGE ON SCHEMA __META__ TO PUBLIC;")

    def test_meta_schema_is_commented(self) -> None:
        sql = _generate_meta_schema()
        assert "COMMENT ON SCHEMA __META__ IS" in sql
        for fn in _DISCOVERY_FUNCTIONS:
            assert fn in sql


class TestDiscoveryFunctionPrivileges:

    def test_execute_is_revoked_from_public_before_being_granted(self) -> None:
        """USAGE on __META__ would otherwise expose the erase functions by name."""
        sql = _generate_discovery_functions()
        assert sql.index("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA __META__ FROM PUBLIC;") < \
               sql.index("GRANT EXECUTE ON FUNCTION")

    def test_latest_build_id_helper_is_not_granted(self) -> None:
        """Callers reach it through the definer-owned functions, never directly."""
        sql = _generate_discovery_functions()
        assert "REVOKE ALL ON FUNCTION __META__.tarkin_latest_build_id() FROM PUBLIC;" in sql
        assert "GRANT EXECUTE ON FUNCTION __META__.tarkin_latest_build_id()" not in sql

    def test_every_granted_function_is_commented(self) -> None:
        import re
        sql      = _generate_discovery_functions()
        granted  = set(re.findall(r"GRANT EXECUTE ON FUNCTION (__META__\.\w+)\(", sql))
        commented = set(re.findall(r"COMMENT ON FUNCTION (__META__\.\w+)\(", sql))
        assert granted == commented

    def test_comments_describe_the_governance_semantics(self) -> None:
        sql = _generate_discovery_functions()
        assert "can_access_sensitive" in sql
        assert "masked" in sql
        assert "partial result is expected" in sql


# ---------------------------------------------------------------------------
# COMMENT ON generation
# ---------------------------------------------------------------------------

def _described_project() -> GovernanceProject:
    col = ColumnConfig(name="id", type="bigint", nullable=False, description="Primary key")
    eml = ColumnConfig(name="email", type="text", description="Contact address")
    tbl = TableConfig(
        name        = "users",
        description = "Registered accounts",
        columns     = [col, eml],
        indexes     = [_make_pk_index()],
    )
    schema = SchemaConfig(name="app", description="Application schema", tables=[tbl])
    return _make_project(schemas=[schema])


class TestGenerateComments:

    def test_schema_description_is_emitted(self) -> None:
        sql = _generate_comments(_described_project())
        assert """COMMENT ON SCHEMA "app" IS 'Application schema';""" in sql

    def test_table_description_lands_on_the_view(self) -> None:
        """Comments go on the Tarkin-created view, never the shadow table."""
        sql = _generate_comments(_described_project())
        assert """COMMENT ON VIEW "app"."users" IS 'Registered accounts';""" in sql
        assert "tk_app" not in sql

    def test_column_descriptions_are_emitted(self) -> None:
        sql = _generate_comments(_described_project())
        assert """COMMENT ON COLUMN "app"."users"."id" IS 'Primary key';""" in sql
        assert """COMMENT ON COLUMN "app"."users"."email" IS 'Contact address';""" in sql

    def test_single_quotes_are_escaped(self) -> None:
        tbl = TableConfig(
            name        = "users",
            description = "User's accounts",
            columns     = [_make_pk_column()],
            indexes     = [_make_pk_index()],
        )
        proj = _make_project(schemas=[SchemaConfig(name="app", tables=[tbl])])
        assert "User''s accounts" in _generate_comments(proj)

    def test_missing_descriptions_are_skipped_by_default(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="app", tables=[_make_table_with_pk()])])
        assert "IS NULL" not in _generate_comments(proj)

    def test_missing_descriptions_are_cleared_when_requested(self) -> None:
        """Migration replays comments, so a removed description must converge."""
        proj = _make_project(schemas=[SchemaConfig(name="app", tables=[_make_table_with_pk()])])
        sql  = _generate_comments(proj, clear_missing=True)
        assert """COMMENT ON VIEW "app"."users" IS NULL;""" in sql
        assert """COMMENT ON COLUMN "app"."users"."id" IS NULL;""" in sql

    def test_versioned_table_current_view_is_commented(self) -> None:
        versioned = ColumnConfig(name="value", type="text", versioned=True, description="Payload")
        table  = _make_table_with_pk("events", extra_cols=[versioned])
        table  = table.model_copy(update={"description": "Event log"})
        proj   = _make_project(schemas=[SchemaConfig(name="app", tables=[table])])
        sql    = _generate_comments(proj)
        assert """COMMENT ON VIEW "app"."events" IS 'Event log';""" in sql
        assert """COMMENT ON VIEW "app"."events_current" IS 'Event log';""" in sql
        assert """COMMENT ON COLUMN "app"."events_current"."value" IS 'Payload';""" in sql

    def test_project_without_descriptions_emits_a_placeholder(self) -> None:
        proj = _make_project(schemas=[SchemaConfig(name="app", tables=[_make_table_with_pk()])])
        assert _generate_comments(proj).startswith("-- No descriptions")


# ---------------------------------------------------------------------------
# __META__.tarkin_governance
# ---------------------------------------------------------------------------

class TestGovernanceView:

    def test_view_is_created_and_granted(self) -> None:
        sql = _generate_governance_view()
        assert "CREATE OR REPLACE VIEW __META__.tarkin_governance AS" in sql
        assert "GRANT SELECT ON __META__.tarkin_governance TO PUBLIC;" in sql

    def test_view_is_dropped_before_replacement(self) -> None:
        """Replacing a view cannot change its column list, so a future column
        addition would fail against an existing install."""
        sql = _generate_governance_view()
        assert sql.index("DROP VIEW IF EXISTS __META__.tarkin_governance;") < \
               sql.index("CREATE OR REPLACE VIEW __META__.tarkin_governance")

    def test_view_reads_the_discovery_functions_unfiltered(self) -> None:
        """No schema argument, so the view spans everything the caller can see."""
        sql = _generate_governance_view()
        for fn in ("get_build", "get_columns", "get_tables",
                   "get_retention", "get_rls_policies"):
            assert f"__META__.{fn}()" in sql

    def test_every_json_source_is_guarded(self) -> None:
        """Discovery functions return a message object, not an array, when the
        role can see nothing; json_to_recordset rejects a non-array."""
        sql = _strip_sql_comments(_generate_governance_view())
        assert sql.count("json_to_recordset(") == sql.count("json_typeof(")
        assert sql.count("json_to_recordset(") == 4

    def test_view_exposes_the_governance_attributes(self) -> None:
        sql = _generate_governance_view()
        for col in ("build_id", "schema_name", "table_name", "column_name",
                    "data_type", "sensitive", "masking_strategy",
                    "column_clearance", "table_clearance", "audit_enabled",
                    "retention_days", "erase_strategy", "rls_policy_count",
                    "rls_predicates"):
            assert f"AS {col}" in sql, f"{col} missing from the view"

    def test_rls_is_aggregated_not_joined_per_policy(self) -> None:
        """A table with three policies must not produce three rows per column."""
        sql = _generate_governance_view()
        assert "count(*)" in sql
        assert "string_agg(" in sql
        assert "GROUP BY" in sql

    def test_table_attributes_are_left_joined(self) -> None:
        """A column whose table row is not visible must still appear."""
        sql = _generate_governance_view()
        assert sql.count("LEFT JOIN") == 3

    def test_view_needs_no_security_invoker(self) -> None:
        """Filtering is on session_user, immune to both view-owner and definer context."""
        sql = _generate_governance_view()
        assert "security_invoker" not in sql

    def test_view_is_commented(self) -> None:
        sql = _generate_governance_view()
        assert "COMMENT ON VIEW __META__.tarkin_governance IS" in sql
        assert "masking_strategy" in sql
        assert "rls_policy_count" in sql

    def test_view_ships_with_the_discovery_functions(self) -> None:
        """Folding it into that block gives build, migrate, and update coverage
        without separate wiring."""
        assert "CREATE OR REPLACE VIEW __META__.tarkin_governance" in _generate_discovery_functions()