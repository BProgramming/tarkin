"""Unit tests for SQL code generation."""
from __future__ import annotations
import pytest

from tarkin.codegen import (
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
        assert "DO $$" not in sql

    def test_contains_pgaudit_log_merge_block(self) -> None:
        proj = _make_project()
        proj.database.audit_enabled = True
        proj.database.audit_logged = [AuditLogLevel.DDL, AuditLogLevel.WRITE]
        sql  = _generate_audit(proj)
        assert "DO $$" in sql
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
        assert "skipped" in sql.lower()

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
