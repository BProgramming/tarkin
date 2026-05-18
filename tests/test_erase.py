"""Tests for subject identifier erasure configuration and codegen."""
from __future__ import annotations

import warnings

import pytest

from tarkin.model import (
    GovernanceProject,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    ForeignKeyConfig,
    ErasureStrategy,
    RLSPolicyConfig,
)
from tarkin.codegen import (
    _generate_subject_identifier_indexes,
    _generate_erase_functions,
    _generate_rls,
    _generate_views,
    _needs_pgcrypto,
)
from tarkin.validate import SemanticValidator, ValidationError
from tarkin.serialize import Serializer
from tarkin.yaml import YamlLoader
from .fixtures import make_database, make_role, make_index


def _make_subject_table(
    name: str = "patients",
    strategy: ErasureStrategy = ErasureStrategy.DELETE,
    extra_cols: list[ColumnConfig] | None = None,
    fks: list[ForeignKeyConfig] | None = None,
) -> TableConfig:
    cols = [
        ColumnConfig(name="id", type="bigint", nullable=False, is_subject_identifier=True),
        ColumnConfig(name="name", type="text"),
    ]
    if extra_cols:
        cols += extra_cols
    return TableConfig(
        name           = name,
        columns        = cols,
        indexes        = [make_index("pk_" + name, ["id"])],
        foreign_keys   = fks or [],
        erase_strategy = strategy,
    )


def _make_project(schemas=None, roles=None, version="16") -> GovernanceProject:
    return GovernanceProject(
        database = make_database(version=version),
        schemas  = schemas or [SchemaConfig(name="public", tables=[_make_subject_table()])],
        roles    = roles   or [make_role()],
    )


def _rls_table(
    name: str = "patients",
    force: bool = False,
    barrier: bool = False,
    policies: list[RLSPolicyConfig] | None = None,
) -> TableConfig:
    return TableConfig(
        name                 = name,
        columns              = [ColumnConfig(name="id", type="bigint", nullable=False)],
        indexes              = [make_index("pk_" + name, ["id"])],
        rls_enabled          = True,
        rls_force            = force,
        rls_security_barrier = barrier,
        rls_policies         = policies or [
            RLSPolicyConfig(roles=["reader"], using_expr="owner_id = current_user_id()")
        ],
    )


def _rls_project(table: TableConfig | None = None, version: str = "15") -> GovernanceProject:
    t      = table or _rls_table()
    schema = SchemaConfig(name="public", tables=[t])
    return GovernanceProject(
        database = make_database(version=version),
        schemas  = [schema],
        roles    = [make_role()],
    )


class TestErasureModel:

    def test_column_is_subject_identifier_defaults_false(self) -> None:
        col = ColumnConfig(name="id", type="bigint")
        assert col.is_subject_identifier is False

    def test_column_is_subject_identifier_set(self) -> None:
        col = ColumnConfig(name="id", type="bigint", is_subject_identifier=True)
        assert col.is_subject_identifier is True

    def test_table_erase_strategy_defaults_none(self) -> None:
        table = TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")])
        assert table.erase_strategy is None

    def test_table_erase_strategy_set(self) -> None:
        table = _make_subject_table(strategy=ErasureStrategy.NULLIFY)
        assert table.erase_strategy == ErasureStrategy.NULLIFY

    def test_all_erasure_strategies(self) -> None:
        for strategy in ErasureStrategy:
            table = _make_subject_table(strategy=strategy)
            assert table.erase_strategy == strategy


class TestErasureValidation:

    def test_valid_subject_table_passes(self) -> None:
        assert SemanticValidator.validate(_make_project()) is True

    def test_identifier_without_strategy_is_invalid(self) -> None:
        table = TableConfig(
            name    = "t",
            columns = [ColumnConfig(name="id", type="bigint", is_subject_identifier=True),],
            indexes = [make_index()],
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = GovernanceProject(database=make_database(), schemas=[schema], roles=[make_role()])
        with pytest.raises(ValidationError, match="no erase_strategy"):
            SemanticValidator.validate(proj)

    def test_strategy_without_identifier_is_invalid(self) -> None:
        table = TableConfig(
            name           = "t",
            columns        = [ColumnConfig(name="id", type="bigint")],
            indexes        = [make_index()],
            erase_strategy = ErasureStrategy.DELETE,
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = GovernanceProject(database=make_database(), schemas=[schema], roles=[make_role()])
        with pytest.raises(ValidationError, match="unreachable"):
            SemanticValidator.validate(proj)

    def test_fk_pointing_at_subject_table_without_strategy_is_invalid(self) -> None:
        subject_table = _make_subject_table(name="patients", strategy=ErasureStrategy.DELETE)
        fk = ForeignKeyConfig(
            name              = "fk_patient",
            column            = "patient_id",
            referenced_schema = "public",
            referenced_table  = "patients",
            referenced_column = "id",
        )
        ref_table = TableConfig(
            name         = "appointments",
            columns      = [
                ColumnConfig(name="id", type="bigint"),
                ColumnConfig(name="patient_id", type="bigint"),
            ],
            indexes      = [make_index()],
            foreign_keys = [fk],
        )
        schema = SchemaConfig(name="public", tables=[subject_table, ref_table])
        proj   = GovernanceProject(database=make_database(), schemas=[schema], roles=[make_role()])
        with pytest.raises(ValidationError, match="erase_strategy"):
            SemanticValidator.validate(proj)

    def test_fk_with_strategy_is_valid(self) -> None:
        subject_table = _make_subject_table(name="patients", strategy=ErasureStrategy.DELETE)
        fk = ForeignKeyConfig(
            name              = "fk_patient",
            column            = "patient_id",
            referenced_schema = "public",
            referenced_table  = "patients",
            referenced_column = "id",
        )
        ref_table = TableConfig(
            name           = "appointments",
            columns        = [
                ColumnConfig(name="id", type="bigint", is_subject_identifier=True),
                ColumnConfig(name="patient_id", type="bigint"),
            ],
            indexes        = [make_index()],
            foreign_keys   = [fk],
            erase_strategy = ErasureStrategy.DELETE,
        )
        schema = SchemaConfig(name="public", tables=[subject_table, ref_table])
        proj   = GovernanceProject(database=make_database(), schemas=[schema], roles=[make_role()])
        assert SemanticValidator.validate(proj) is True

    def test_obfuscate_non_nullable_non_text_emits_warning(self) -> None:
        table = TableConfig(
            name    = "t",
            columns = [
                ColumnConfig(name="id",    type="bigint", nullable=False, is_subject_identifier=True),
                ColumnConfig(name="score", type="integer", nullable=False),
            ],
            indexes        = [make_index()],
            erase_strategy = ErasureStrategy.OBFUSCATE,
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = GovernanceProject(database=make_database(), schemas=[schema], roles=[make_role()])
        with pytest.warns(UserWarning, match="score"):
            SemanticValidator.validate(proj)


class TestSubjectIdentifierIndexes:

    def test_no_subject_columns_returns_comment(self) -> None:
        table  = TableConfig(
            name    = "t",
            columns = [ColumnConfig(name="id", type="bigint")],
            indexes = [make_index()],
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_subject_identifier_indexes(proj)
        assert "No subject identifier" in sql
        assert "CREATE INDEX" not in sql

    def test_subject_column_creates_index_on_shadow(self) -> None:
        proj = _make_project()
        sql  = _generate_subject_identifier_indexes(proj)
        assert 'CREATE INDEX' in sql
        assert '"tarkin_subject_patients_id"' in sql
        assert '"tk_public"."patients"' in sql

    def test_multiple_subject_columns_create_separate_indexes(self) -> None:
        table = TableConfig(
            name    = "t",
            columns = [
                ColumnConfig(name="user_id",   type="bigint", is_subject_identifier=True),
                ColumnConfig(name="device_id", type="text",   is_subject_identifier=True),
            ],
            indexes        = [make_index()],
            erase_strategy = ErasureStrategy.DELETE,
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_subject_identifier_indexes(proj)
        assert '"tarkin_subject_t_user_id"' in sql
        assert '"tarkin_subject_t_device_id"' in sql


class TestEraseFunctions:

    def test_no_subject_tables_returns_comment(self) -> None:
        table  = TableConfig(
            name    = "t",
            columns = [ColumnConfig(name="id", type="bigint")],
            indexes = [make_index()],
        )
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_erase_functions(proj)
        assert "skipped" in sql.lower()
        assert "CREATE OR REPLACE FUNCTION" not in sql

    def test_erase_check_function_created(self) -> None:
        proj = _make_project()
        sql  = _generate_erase_functions(proj)
        assert "__META__.tarkin_erase_check" in sql

    def test_erase_apply_function_created(self) -> None:
        proj = _make_project()
        sql  = _generate_erase_functions(proj)
        assert "__META__.tarkin_erase_apply" in sql

    def test_both_functions_take_text_array_params(self) -> None:
        proj = _make_project()
        sql  = _generate_erase_functions(proj)
        assert "p_columns text[]" in sql
        assert "p_values  text[]" in sql

    def test_erase_apply_inserts_to_tarkin_erasures(self) -> None:
        proj = _make_project()
        sql  = _generate_erase_functions(proj)
        assert "tarkin_erasures" in sql

    def test_delete_strategy_emits_delete(self) -> None:
        proj = _make_project()  # default strategy is DELETE
        sql  = _generate_erase_functions(proj)
        assert "DELETE FROM" in sql

    def test_nullify_strategy_emits_update(self) -> None:
        table  = _make_subject_table(strategy=ErasureStrategy.NULLIFY)
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_erase_functions(proj)
        assert "UPDATE" in sql

    def test_obfuscate_strategy_emits_sha256(self) -> None:
        table  = _make_subject_table(strategy=ErasureStrategy.OBFUSCATE)
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        sql    = _generate_erase_functions(proj)
        assert "sha256" in sql


class TestNeedsPgcrypto:

    def test_obfuscate_strategy_requires_pgcrypto(self) -> None:
        table  = _make_subject_table(strategy=ErasureStrategy.OBFUSCATE)
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        assert _needs_pgcrypto(proj) is True

    def test_delete_strategy_does_not_require_pgcrypto(self) -> None:
        proj = _make_project()  # DELETE strategy
        assert _needs_pgcrypto(proj) is False

    def test_nullify_strategy_does_not_require_pgcrypto(self) -> None:
        table  = _make_subject_table(strategy=ErasureStrategy.NULLIFY)
        schema = SchemaConfig(name="public", tables=[table])
        proj   = _make_project(schemas=[schema])
        assert _needs_pgcrypto(proj) is False


class TestErasureRoundtrip:

    def test_erase_strategy_roundtrips(self) -> None:
        for strategy in ErasureStrategy:
            table    = _make_subject_table(strategy=strategy)
            schema   = SchemaConfig(name="public", tables=[table])
            proj     = _make_project(schemas=[schema])
            yaml_str = Serializer.to_yaml_string(proj)
            restored = YamlLoader.loads(yaml_str)
            assert restored is not None
            assert restored.schemas[0].tables[0].erase_strategy == strategy

    def test_is_subject_identifier_roundtrips(self) -> None:
        proj     = _make_project()
        yaml_str = Serializer.to_yaml_string(proj)
        restored = YamlLoader.loads(yaml_str)
        assert restored is not None
        id_col   = next(
            c for c in restored.schemas[0].tables[0].columns
            if c.name == "id"
        )
        assert id_col.is_subject_identifier is True

    def test_non_subject_column_roundtrips_false(self) -> None:
        proj     = _make_project()
        yaml_str = Serializer.to_yaml_string(proj)
        restored = YamlLoader.loads(yaml_str)
        assert restored is not None
        name_col = next(
            c for c in restored.schemas[0].tables[0].columns
            if c.name == "name"
        )
        assert name_col.is_subject_identifier is False

    def test_no_erase_strategy_omitted_from_yaml(self) -> None:
        table    = TableConfig(
            name    = "t",
            columns = [ColumnConfig(name="id", type="bigint")],
            indexes = [make_index()],
        )
        schema   = SchemaConfig(name="public", tables=[table])
        proj     = GovernanceProject(
            database = make_database(),
            schemas  = [schema],
            roles    = [make_role()],
        )
        yaml_str = Serializer.to_yaml_string(proj)
        assert "erase_strategy" not in yaml_str


class TestRLSModel:

    def test_rls_enabled_defaults_false(self) -> None:
        assert TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")]).rls_enabled is False

    def test_rls_force_defaults_false(self) -> None:
        assert TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")]).rls_force is False

    def test_rls_security_barrier_defaults_false(self) -> None:
        assert TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")]).rls_security_barrier is False

    def test_rls_policies_defaults_empty(self) -> None:
        assert TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")]).rls_policies == []

    def test_rls_policy_config_fields(self) -> None:
        p = RLSPolicyConfig(roles=["reader"], using_expr="owner_id = 1")
        assert p.roles == ["reader"]
        assert p.using_expr == "owner_id = 1"
        assert p.check_expr is None

    def test_rls_policy_with_check_expr(self) -> None:
        p = RLSPolicyConfig(roles=["writer"], using_expr="x = 1", check_expr="status != 'locked'")
        assert p.check_expr == "status != 'locked'"


class TestRLSValidation:

    def test_valid_rls_config_passes(self) -> None:
        assert SemanticValidator.validate(_rls_project()) is True

    def test_policies_without_rls_enabled_is_invalid(self) -> None:
        table = TableConfig(
            name         = "t",
            columns      = [ColumnConfig(name="id", type="bigint")],
            indexes      = [make_index()],
            rls_enabled  = False,
            rls_policies = [RLSPolicyConfig(roles=["reader"], using_expr="true")],
        )
        proj = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        with pytest.raises(ValidationError, match="rls_enabled=false"):
            SemanticValidator.validate(proj)

    def test_rls_force_without_rls_enabled_is_invalid(self) -> None:
        table = TableConfig(
            name="t", columns=[ColumnConfig(name="id", type="bigint")],
            indexes=[make_index()], rls_enabled=False, rls_force=True,
        )
        proj = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        with pytest.raises(ValidationError, match="rls_force"):
            SemanticValidator.validate(proj)

    def test_rls_security_barrier_without_rls_enabled_is_invalid(self) -> None:
        table = TableConfig(
            name="t", columns=[ColumnConfig(name="id", type="bigint")],
            indexes=[make_index()], rls_enabled=False, rls_security_barrier=True,
        )
        proj = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        with pytest.raises(ValidationError, match="rls_security_barrier"):
            SemanticValidator.validate(proj)

    def test_empty_using_expr_is_invalid(self) -> None:
        table = _rls_table(policies=[RLSPolicyConfig(roles=["reader"], using_expr="   ")])
        proj  = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        with pytest.raises(ValidationError, match="using_expr cannot be empty"):
            SemanticValidator.validate(proj)

    def test_empty_roles_is_invalid(self) -> None:
        table = _rls_table(policies=[RLSPolicyConfig(roles=[], using_expr="true")])
        proj  = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        with pytest.raises(ValidationError, match="roles list cannot be empty"):
            SemanticValidator.validate(proj)

    def test_undefined_role_is_invalid(self) -> None:
        table = _rls_table(policies=[RLSPolicyConfig(roles=["ghost_role"], using_expr="true")])
        proj  = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        with pytest.raises(ValidationError, match="ghost_role"):
            SemanticValidator.validate(proj)

    def test_public_role_is_valid(self) -> None:
        proj = _rls_project(table=_rls_table(policies=[RLSPolicyConfig(roles=["PUBLIC"], using_expr="true")]))
        assert SemanticValidator.validate(proj) is True

    def test_rls_enabled_with_no_policies_passes(self) -> None:
        table = TableConfig(
            name="t", columns=[ColumnConfig(name="id", type="bigint")],
            indexes=[make_index()], rls_enabled=True,
        )
        proj  = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert SemanticValidator.validate(proj) is True

    def test_pre_pg15_rls_emits_warning(self) -> None:
        proj = _rls_project(version="14")
        with pytest.warns(UserWarning, match="PG15"):
            SemanticValidator.validate(proj)

    def test_pg15_rls_does_not_warn(self) -> None:
        proj = _rls_project(version="15")
        with warnings.catch_warnings(record=False):
            warnings.simplefilter("error", UserWarning)
            SemanticValidator.validate(proj)  # must not raise

    def test_pg16_rls_does_not_warn(self) -> None:
        proj = _rls_project(version="16")
        with warnings.catch_warnings(record=False):
            warnings.simplefilter("error", UserWarning)
            SemanticValidator.validate(proj)


class TestGenerateRLS:

    def test_no_rls_tables_returns_comment(self) -> None:
        table  = TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")], indexes=[make_index()])
        proj   = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert "No row-level security" in _generate_rls(proj)

    def test_enable_rls_on_shadow_table(self) -> None:
        proj = _rls_project()
        assert 'ALTER TABLE "tk_public"."patients" ENABLE ROW LEVEL SECURITY' in _generate_rls(proj)

    def test_force_rls_emitted_when_set(self) -> None:
        proj = _rls_project(table=_rls_table(force=True))
        assert "FORCE ROW LEVEL SECURITY" in _generate_rls(proj)

    def test_force_rls_not_emitted_when_false(self) -> None:
        proj = _rls_project(table=_rls_table(force=False))
        assert "FORCE ROW LEVEL SECURITY" not in _generate_rls(proj)

    def test_policy_named_tarkin_rls_table_index(self) -> None:
        proj = _rls_project()
        assert '"tarkin_rls_patients_0"' in _generate_rls(proj)

    def test_using_expr_in_policy(self) -> None:
        proj = _rls_project()
        assert "owner_id = current_user_id()" in _generate_rls(proj)

    def test_check_expr_present_when_set(self) -> None:
        table = _rls_table(policies=[
            RLSPolicyConfig(roles=["reader"], using_expr="x = 1", check_expr="status != 'locked'")
        ])
        sql = _generate_rls(_rls_project(table=table))
        assert "WITH CHECK" in sql
        assert "status != 'locked'" in sql

    def test_check_expr_absent_when_not_set(self) -> None:
        assert "WITH CHECK" not in _generate_rls(_rls_project())

    def test_multiple_policies_sequential_names(self) -> None:
        table = _rls_table(policies=[
            RLSPolicyConfig(roles=["reader"], using_expr="a = 1"),
            RLSPolicyConfig(roles=["writer"], using_expr="b = 2"),
        ])
        sql = _generate_rls(_rls_project(table=table))
        assert '"tarkin_rls_patients_0"' in sql
        assert '"tarkin_rls_patients_1"' in sql

    def test_public_role_not_quoted(self) -> None:
        table = _rls_table(policies=[RLSPolicyConfig(roles=["PUBLIC"], using_expr="true")])
        sql   = _generate_rls(_rls_project(table=table))
        assert "TO PUBLIC" in sql
        assert 'TO "PUBLIC"' not in sql

    def test_pre_pg15_emits_warning(self) -> None:
        proj = _rls_project(version="14")
        with pytest.warns(UserWarning, match="PG15"):
            _generate_rls(proj)

    def test_pg15_does_not_warn(self) -> None:
        proj = _rls_project(version="15")
        with warnings.catch_warnings(record=False):
            warnings.simplefilter("error", UserWarning)
            _generate_rls(proj)


class TestRLSViews:

    def test_security_invoker_added_on_pg15(self) -> None:
        table  = _rls_table()
        proj   = GovernanceProject(database=make_database(version="15"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert "security_invoker = true" in _generate_views(proj)

    def test_security_invoker_added_on_pg16(self) -> None:
        table  = _rls_table()
        proj   = GovernanceProject(database=make_database(version="16"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert "security_invoker = true" in _generate_views(proj)

    def test_security_invoker_not_added_on_pg14(self) -> None:
        table  = _rls_table()
        proj   = GovernanceProject(database=make_database(version="14"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert "security_invoker" not in _generate_views(proj)

    def test_security_invoker_not_added_when_rls_disabled(self) -> None:
        table  = TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")], indexes=[make_index()], rls_enabled=False)
        proj   = GovernanceProject(database=make_database(version="15"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert "security_invoker" not in _generate_views(proj)

    def test_security_barrier_added_when_set(self) -> None:
        table  = _rls_table(barrier=True)
        proj   = GovernanceProject(database=make_database(version="15"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert "security_barrier = true" in _generate_views(proj)

    def test_security_barrier_not_added_when_false(self) -> None:
        table  = _rls_table(barrier=False)
        proj   = GovernanceProject(database=make_database(version="15"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        assert "security_barrier" not in _generate_views(proj)

    def test_both_options_combined(self) -> None:
        table  = _rls_table(barrier=True)
        proj   = GovernanceProject(database=make_database(version="15"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        sql    = _generate_views(proj)
        assert "security_invoker = true" in sql
        assert "security_barrier = true" in sql

    def test_no_rls_no_extra_options(self) -> None:
        table  = TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")], indexes=[make_index()])
        proj   = GovernanceProject(database=make_database(version="15"), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        sql    = _generate_views(proj)
        assert "WITH (" not in sql


class TestRLSRoundtrip:

    def test_rls_fields_roundtrip(self) -> None:
        table = TableConfig(
            name                 = "t",
            columns              = [ColumnConfig(name="id", type="bigint")],
            indexes              = [make_index()],
            rls_enabled          = True,
            rls_force            = True,
            rls_security_barrier = True,
            rls_policies         = [
                RLSPolicyConfig(
                    roles      = ["reader", "PUBLIC"],
                    using_expr = "tenant_id = current_setting('app.tenant')::bigint",
                    check_expr = "tenant_id = current_setting('app.tenant')::bigint",
                )
            ],
        )
        proj     = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        restored = YamlLoader.loads(Serializer.to_yaml_string(proj))
        assert restored is not None
        rt = restored.schemas[0].tables[0]
        assert rt.rls_enabled          is True
        assert rt.rls_force            is True
        assert rt.rls_security_barrier is True
        assert len(rt.rls_policies)    == 1
        p = rt.rls_policies[0]
        assert p.roles      == ["reader", "PUBLIC"]
        assert "tenant_id"  in p.using_expr
        assert p.check_expr is not None

    def test_no_rls_omitted_from_yaml(self) -> None:
        table    = TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")], indexes=[make_index()])
        proj     = GovernanceProject(database=make_database(), schemas=[SchemaConfig(name="public", tables=[table])], roles=[make_role()])
        yaml_str = Serializer.to_yaml_string(proj)
        assert "rls_enabled"          not in yaml_str
        assert "rls_force"            not in yaml_str
        assert "rls_security_barrier" not in yaml_str
        assert "rls_policies"         not in yaml_str
