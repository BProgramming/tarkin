"""Tests for retention configuration, validation, and codegen."""
from __future__ import annotations
import warnings
import pytest

from tarkin.model import (
    GovernanceProject,
    DatabaseConfig,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    ErasureStrategy,
)
from tarkin.codegen import (
    _generate_retention_columns,
    _generate_retention,
)
from tarkin.validate import SemanticValidator, ValidationError
from tarkin.serialize import Serializer
from tarkin.yaml import YamlLoader
from tarkin.diff import diff_projects, ObjectType

from .fixtures import make_database, make_role, make_index, make_schema

def _retained_table(
    name: str = "events",
    retention_days: int = 90,
    strategy: ErasureStrategy = ErasureStrategy.DELETE,
) -> TableConfig:
    return TableConfig(
        name           = name,
        columns        = [
            ColumnConfig(name="id",         type="bigint", nullable=False, is_subject_identifier=True),
            ColumnConfig(name="created_at", type="timestamptz"),
            ColumnConfig(name="payload",    type="text"),
        ],
        indexes        = [make_index("pk_" + name, ["id"])],
        erase_strategy = strategy,
        retention_days = retention_days,
    )


def _project(
    tables: list[TableConfig] | None = None,
    retention_schedule: str | None = None,
    version: str = "16",
) -> GovernanceProject:
    schema = SchemaConfig(name="public", tables=tables or [_retained_table()])
    return GovernanceProject(
        database = make_database(version=version, retention_schedule=retention_schedule),
        schemas  = [schema],
        roles    = [make_role()],
    )


def _empty_project() -> GovernanceProject:
    """A valid project with no retention configured."""
    return GovernanceProject(
        database = make_database(),
        schemas  = [make_schema()],
        roles    = [make_role()],
    )


class TestRetentionModel:

    def test_retention_days_defaults_none(self) -> None:
        assert TableConfig(name="t", columns=[ColumnConfig(name="id", type="bigint")]).retention_days is None

    def test_retention_schedule_defaults_none(self) -> None:
        assert DatabaseConfig().retention_schedule is None

    def test_retention_days_set(self) -> None:
        t = _retained_table(retention_days=30)
        assert t.retention_days == 30

    def test_retention_schedule_set(self) -> None:
        db = make_database(retention_schedule="0 3 * * *")
        assert db.retention_schedule == "0 3 * * *"


class TestRetentionValidation:

    def test_valid_retention_config_passes(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        assert SemanticValidator.validate(proj) is True

    def test_retention_days_without_erase_strategy_is_invalid(self) -> None:
        table = TableConfig(
            name           = "t",
            columns        = [ColumnConfig(name="id", type="bigint")],
            indexes        = [make_index()],
            retention_days = 30,
            # no erase_strategy
        )
        proj = GovernanceProject(
            database = make_database(),
            schemas  = [SchemaConfig(name="public", tables=[table])],
            roles    = [make_role()],
        )
        with pytest.raises(ValidationError, match="erase_strategy"):
            SemanticValidator.validate(proj)

    def test_retention_days_zero_is_invalid(self) -> None:
        table = _retained_table(retention_days=0)
        proj  = GovernanceProject(
            database = make_database(),
            schemas  = [SchemaConfig(name="public", tables=[table])],
            roles    = [make_role()],
        )
        with pytest.raises(ValidationError, match="positive integer"):
            SemanticValidator.validate(proj)

    def test_retention_days_negative_is_invalid(self) -> None:
        table = _retained_table(retention_days=-7)
        proj  = GovernanceProject(
            database = make_database(),
            schemas  = [SchemaConfig(name="public", tables=[table])],
            roles    = [make_role()],
        )
        with pytest.raises(ValidationError, match="positive integer"):
            SemanticValidator.validate(proj)

    def test_existing_expires_at_column_is_invalid(self) -> None:
        table = TableConfig(
            name           = "t",
            columns        = [
                ColumnConfig(name="id",          type="bigint", nullable=False, is_subject_identifier=True),
                ColumnConfig(name="__expires_at__", type="timestamptz"),
            ],
            indexes        = [make_index()],
            erase_strategy = ErasureStrategy.DELETE,
            retention_days = 30,
        )
        proj = GovernanceProject(
            database = make_database(),
            schemas  = [SchemaConfig(name="public", tables=[table])],
            roles    = [make_role()],
        )
        with pytest.raises(ValidationError, match="__expires_at__"):
            SemanticValidator.validate(proj)

    def test_existing_erase_on_expiry_column_is_invalid(self) -> None:
        table = TableConfig(
            name           = "t",
            columns        = [
                ColumnConfig(name="id",                  type="bigint", nullable=False, is_subject_identifier=True),
                ColumnConfig(name="__erase_on_expiry__", type="bool"),
            ],
            indexes        = [make_index()],
            erase_strategy = ErasureStrategy.DELETE,
            retention_days = 30,
        )
        proj = GovernanceProject(
            database = make_database(),
            schemas  = [SchemaConfig(name="public", tables=[table])],
            roles    = [make_role()],
        )
        with pytest.raises(ValidationError, match="__erase_on_expiry__"):
            SemanticValidator.validate(proj)

    def test_schedule_without_retention_days_emits_warning(self) -> None:
        proj = GovernanceProject(
            database = make_database(retention_schedule="0 2 * * *"),
            schemas  = [make_schema()],
            roles    = [make_role()],
        )
        with pytest.warns(UserWarning, match="nothing to process"):
            SemanticValidator.validate(proj)

    def test_retention_days_without_schedule_emits_warning(self) -> None:
        proj = _project(retention_schedule=None)
        with pytest.warns(UserWarning, match="retention_schedule"):
            SemanticValidator.validate(proj)

    def test_both_set_no_warning(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        with warnings.catch_warnings(record=False):
            warnings.simplefilter("error", UserWarning)
            SemanticValidator.validate(proj)  # must not warn


class TestRetentionColumns:

    def _make_current(self) -> GovernanceProject:
        """An 'empty' current state with no retention columns yet."""
        return GovernanceProject(
            database = make_database(),
            schemas  = [SchemaConfig(name="public", tables=[
                TableConfig(
                    name    = "events",
                    columns = [ColumnConfig(name="id", type="bigint")],
                    indexes = [make_index()],
                )
            ])],
            roles = [make_role()],
        )

    def test_no_retention_returns_comment(self) -> None:
        proj    = _empty_project()
        current = _empty_project()
        sql     = _generate_retention_columns(proj, current)
        assert "No tables configured for retention" in sql
        assert "ALTER TABLE" not in sql

    def test_expires_at_column_added(self) -> None:
        proj    = _project()
        current = self._make_current()
        sql     = _generate_retention_columns(proj, current)
        assert "__expires_at__" in sql
        assert "interval '90 days'" in sql

    def test_erase_on_expiry_column_added(self) -> None:
        proj    = _project()
        current = self._make_current()
        sql     = _generate_retention_columns(proj, current)
        assert "__erase_on_expiry__" in sql
        assert "DEFAULT true" in sql

    def test_columns_added_to_shadow_table(self) -> None:
        proj    = _project()
        current = self._make_current()
        sql     = _generate_retention_columns(proj, current)
        assert '"tk_public"."events"' in sql

    def test_index_created_on_expires_at(self) -> None:
        proj    = _project()
        current = self._make_current()
        sql     = _generate_retention_columns(proj, current)
        assert "idx_events_expires_at" in sql
        assert "__erase_on_expiry__ = true" in sql

    def test_custom_retention_days_in_default(self) -> None:
        table   = _retained_table(retention_days=365)
        proj    = _project(tables=[table])
        current = self._make_current()
        sql     = _generate_retention_columns(proj, current)
        assert "interval '365 days'" in sql

    def test_existing_expires_at_not_readded(self) -> None:
        """If the column already exists in current, don't ADD it again."""
        proj = _project()
        current = GovernanceProject(
            database = make_database(),
            schemas  = [SchemaConfig(name="public", tables=[
                TableConfig(
                    name    = "events",
                    columns = [
                        ColumnConfig(name="id",            type="bigint"),
                        ColumnConfig(name="__expires_at__", type="timestamptz"),
                    ],
                    indexes = [make_index()],
                )
            ])],
            roles = [make_role()],
        )
        sql = _generate_retention_columns(proj, current)
        # Should not add __expires_at__ since it already exists
        assert "ADD COLUMN __expires_at__" not in sql


class TestGenerateRetention:

    def test_no_retention_returns_comment(self) -> None:
        assert "No retention configured" in _generate_retention(_empty_project())

    def test_sweep_function_created(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "__META__.tarkin_erase_expired_records" in sql

    def test_sweep_function_filters_expired_rows(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "__expires_at__ <= now()" in sql
        assert "__erase_on_expiry__ = true" in sql

    def test_sweep_function_logs_to_tarkin_erasures(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "tarkin_erasures" in sql

    def test_sweep_function_sets_was_scheduled_true(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "was_scheduled" in sql
        assert "true" in sql

    def test_delete_strategy_in_sweep(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "DELETE FROM" in sql

    def test_nullify_strategy_in_sweep(self) -> None:
        table = _retained_table(strategy=ErasureStrategy.NULLIFY)
        proj  = _project(tables=[table], retention_schedule="0 2 * * *")
        sql   = _generate_retention(proj)
        assert "UPDATE" in sql
        assert "nullify" in sql

    def test_obfuscate_strategy_in_sweep(self) -> None:
        table = _retained_table(strategy=ErasureStrategy.OBFUSCATE)
        proj  = _project(tables=[table], retention_schedule="0 2 * * *")
        sql   = _generate_retention(proj)
        assert "sha256" in sql

    def test_cron_job_scheduled_when_schedule_set(self) -> None:
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "cron.schedule" in sql
        assert "tarkin_retention_" in sql
        assert "0 2 * * *" in sql

    def test_cron_job_unscheduled_before_scheduling(self) -> None:
        """Ensures idempotency — we unschedule before re-scheduling."""
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "cron.unschedule" in sql

    def test_no_cron_when_no_schedule(self) -> None:
        proj = _project(retention_schedule=None)
        with warnings.catch_warnings(record=False):
            warnings.simplefilter("ignore", UserWarning)
            sql = _generate_retention(proj)
        assert "cron.schedule" not in sql
        assert "No retention_schedule" in sql

    def test_shadow_schema_derived_correctly(self) -> None:
        """The sweep uses 'tk_' || schema_name — not a stored shadow name."""
        proj = _project(retention_schedule="0 2 * * *")
        sql  = _generate_retention(proj)
        assert "'tk_' || rec.schema_name" in sql or "tk_public" in sql or "shadow_schema" in sql


class TestRetentionRoundtrip:

    def test_retention_days_roundtrips(self) -> None:
        proj     = _project(retention_schedule="0 2 * * *")
        restored = YamlLoader.loads(Serializer.to_yaml_string(proj))
        assert restored is not None
        assert restored.schemas[0].tables[0].retention_days == 90

    def test_retention_schedule_roundtrips(self) -> None:
        proj     = _project(retention_schedule="0 2 * * *")
        restored = YamlLoader.loads(Serializer.to_yaml_string(proj))
        assert restored is not None
        assert restored.database.retention_schedule == "0 2 * * *"

    def test_no_retention_omitted_from_yaml(self) -> None:
        proj     = _empty_project()
        yaml_str = Serializer.to_yaml_string(proj)
        assert "retention_days"     not in yaml_str
        assert "retention_schedule" not in yaml_str

    def test_all_strategies_roundtrip(self) -> None:
        for strategy in ErasureStrategy:
            table    = _retained_table(strategy=strategy)
            proj     = _project(tables=[table], retention_schedule="0 2 * * *")
            restored = YamlLoader.loads(Serializer.to_yaml_string(proj))
            assert restored is not None
            rt = restored.schemas[0].tables[0]
            assert rt.retention_days  == 90
            assert rt.erase_strategy  == strategy


class TestRetentionDiff:

    def test_retention_days_change_detected(self) -> None:
        before = _project(retention_schedule="0 2 * * *")
        after  = before.model_copy(deep=True)
        after.schemas[0].tables[0].retention_days = 30
        changes = diff_projects(before, after)
        table_changes = [c for c in changes if c.object_type == ObjectType.TABLE]
        modified = [c for c in table_changes if c.field == "retention_days"]
        assert len(modified) == 1
        assert modified[0].before == 90
        assert modified[0].after  == 30

    def test_retention_days_added_detected(self) -> None:
        before = _empty_project()
        after  = before.model_copy(deep=True)
        after.schemas[0].tables[0].retention_days = 60
        changes = diff_projects(before, after)
        table_changes = [c for c in changes if c.object_type == ObjectType.TABLE]
        modified = [c for c in table_changes if c.field == "retention_days"]
        assert len(modified) == 1
        assert modified[0].before is None
        assert modified[0].after  == 60

    def test_retention_schedule_change_detected(self) -> None:
        before = _project(retention_schedule="0 2 * * *")
        after  = before.model_copy(deep=True)
        after.database.retention_schedule = "0 4 * * 0"
        changes = diff_projects(before, after)
        db_changes = [c for c in changes if c.object_type == ObjectType.DATABASE]
        sched_changes = [c for c in db_changes if c.field == "retention_schedule"]
        assert len(sched_changes) == 1
        assert sched_changes[0].before == "0 2 * * *"
        assert sched_changes[0].after  == "0 4 * * 0"

    def test_retention_schedule_added_detected(self) -> None:
        before = _project(retention_schedule=None)
        after  = before.model_copy(deep=True)
        after.database.retention_schedule = "0 2 * * *"
        with warnings.catch_warnings(record=False):
            warnings.simplefilter("ignore", UserWarning)
            changes = diff_projects(before, after)
        db_changes = [c for c in changes if c.object_type == ObjectType.DATABASE]
        sched_changes = [c for c in db_changes if c.field == "retention_schedule"]
        assert len(sched_changes) == 1
