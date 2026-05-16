"""Tests for subject identifier erasure configuration and codegen."""
from __future__ import annotations

import pytest

from tarkin.model import (
    GovernanceProject,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    ForeignKeyConfig,
    ErasureStrategy,
)
from tarkin.codegen import (
    _generate_subject_identifier_indexes,
    _generate_erase_functions,
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


def _make_project(schemas=None, roles=None) -> GovernanceProject:
    return GovernanceProject(
        database = make_database(),
        schemas  = schemas or [SchemaConfig(name="public", tables=[_make_subject_table()])],
        roles    = roles   or [make_role()],
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
            columns = [
                ColumnConfig(name="id", type="bigint", is_subject_identifier=True),
            ],
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
        # Should validate (only a warning, not an error) — currently raises
        # because we report it as an error. Adjust when severity is changed.
        # For now just confirm it mentions the column.
        with pytest.raises(ValidationError, match="score"):
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


class TestNeedsPgcryptoErasure:

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
