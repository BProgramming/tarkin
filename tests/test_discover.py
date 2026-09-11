"""Tests for tarkin.discover — object mapping, function calls, and output.

The generated DDL is covered in test_codegen.py; the query schema context and
system prompt are covered in test_query.py.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from tarkin.codegen import _generate_discovery_functions
from tarkin.credentials import ConnectionProfile
from tarkin.discover import (
    OBJECTS,
    DiscoverError,
    _call,
    discover,
)


ALL_FUNCTIONS = (
    "get_schemas", "get_tables", "get_columns", "get_roles",
    "get_build", "get_retention", "get_erasures",
    "get_erasure_counts", "get_rls_policies",
)


def _make_profile() -> ConnectionProfile:
    return ConnectionProfile(
        profile  = "test",
        host     = "localhost",
        port     = 5432,
        database = "testdb",
        username = "testuser",
        password = SecretStr("testpass"),
    )


def _mock_engine(fetch_value=None):
    """Return (engine, conn) where every fetchone() yields (fetch_value,)."""
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = (fetch_value,)

    engine = MagicMock()
    engine.connect.return_value.__enter__ = MagicMock(return_value=conn)
    engine.connect.return_value.__exit__  = MagicMock(return_value=False)
    return engine, conn


# ---------------------------------------------------------------------------
# discover()
# ---------------------------------------------------------------------------

class TestObjectMap:

    def test_every_object_maps_to_a_generated_function(self) -> None:
        sql = _generate_discovery_functions()
        for _, (fn, _params) in OBJECTS.items():
            assert f"CREATE OR REPLACE FUNCTION __META__.{fn}(" in sql

    def test_object_map_covers_all_functions(self) -> None:
        mapped = {fn for fn, _ in OBJECTS.values()}
        assert mapped == set(ALL_FUNCTIONS)


class TestCall:

    def test_no_arg_function_is_called_with_empty_parens(self) -> None:
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = ({"name": "public"},)

        _call(conn, "get_schemas", (), {})

        sql = str(conn.execute.call_args.args[0])
        assert "SELECT __META__.get_schemas()" in sql

    def test_parameters_are_bound_and_cast(self) -> None:
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = ([],)

        _call(conn, "get_columns", ("schema", "table"), {"schema": "analytics", "table": "events"})

        sql   = str(conn.execute.call_args.args[0])
        bound = conn.execute.call_args.args[1]
        assert "CAST(:schema AS text)" in sql
        assert "CAST(:table AS text)"  in sql
        assert bound == {"schema": "analytics", "table": "events"}

    def test_since_is_cast_to_timestamptz(self) -> None:
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = ([],)

        _call(conn, "get_erasures", ("since",), {"since": "2026-01-01"})

        sql = str(conn.execute.call_args.args[0])
        assert "CAST(:since AS timestamptz)" in sql

    def test_missing_parameter_binds_none(self) -> None:
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = ([],)

        _call(conn, "get_tables", ("schema",), {})

        assert conn.execute.call_args.args[1] == {"schema": None}

    def test_null_row_returns_none(self) -> None:
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = (None,)

        assert _call(conn, "get_schemas", (), {}) is None


class TestDiscover:

    def test_unknown_object_raises(self) -> None:
        with pytest.raises(DiscoverError, match="Unknown object"):
            discover(profile=_make_profile(), objects=["nonsense"])

    def test_unknown_object_lists_valid_names(self) -> None:
        with pytest.raises(DiscoverError) as exc:
            discover(profile=_make_profile(), objects=["nonsense"])
        for name in OBJECTS:
            assert name in str(exc.value)

    def test_all_objects_are_queried(self) -> None:
        engine, conn = _mock_engine([])

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            result, written = discover(profile=_make_profile(), objects=list(OBJECTS))

        assert set(result) == set(OBJECTS)
        assert written is None
        executed = [str(c.args[0]) for c in conn.execute.call_args_list]
        for fn, _ in OBJECTS.values():
            assert any(f"__META__.{fn}(" in sql for sql in executed)

    def test_subset_queries_only_requested_objects(self) -> None:
        engine, conn = _mock_engine([])

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            result, _ = discover(profile=_make_profile(), objects=["retention", "rls"])

        assert set(result) == {"retention", "rls"}
        executed = [str(c.args[0]) for c in conn.execute.call_args_list]
        assert not any("get_schemas" in sql for sql in executed)

    def test_transaction_is_read_only_and_rolled_back(self) -> None:
        engine, conn = _mock_engine([])

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            discover(profile=_make_profile(), objects=["schemas"])

        executed = [str(c.args[0]) for c in conn.execute.call_args_list]
        assert "SET TRANSACTION READ ONLY" in executed[0]
        assert "ROLLBACK" in executed[-1]

    def test_rollback_happens_even_on_failure(self) -> None:
        conn = MagicMock()
        conn.execute.side_effect = [MagicMock(), RuntimeError("boom"), MagicMock()]

        engine = MagicMock()
        engine.connect.return_value.__enter__ = MagicMock(return_value=conn)
        engine.connect.return_value.__exit__  = MagicMock(return_value=False)

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            with pytest.raises(DiscoverError, match="Discovery failed"):
                discover(profile=_make_profile(), objects=["schemas"])

        assert "ROLLBACK" in str(conn.execute.call_args_list[-1].args[0])

    def test_output_directory_writes_a_timestamped_json(self, tmp_path) -> None:
        engine, _ = _mock_engine([{"name": "public"}])

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            result, written = discover(
                profile          = _make_profile(),
                objects          = ["schemas"],
                output_directory = tmp_path,
            )

        assert written is not None
        assert written.parent == tmp_path
        assert written.name.startswith("tarkin_discover_")
        assert written.name.endswith(".json")
        assert json.loads(written.read_text()) == result

    def test_no_file_is_written_without_output_directory(self, tmp_path) -> None:
        engine, _ = _mock_engine([])

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            _, written = discover(profile=_make_profile(), objects=["schemas"])

        assert written is None
        assert not list(tmp_path.iterdir())

    def test_engine_is_disposed(self) -> None:
        engine, _ = _mock_engine([])

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            discover(profile=_make_profile(), objects=["schemas"])

        engine.dispose.assert_called_once()

    def test_filters_reach_the_function_call(self) -> None:
        engine, conn = _mock_engine([])

        with patch("tarkin.credentials.ConnectionProfile.engine", return_value=engine):
            discover(
                profile = _make_profile(),
                objects = ["columns"],
                schema  = "analytics",
                table   = "events",
            )

        bound = [c.args[1] for c in conn.execute.call_args_list if len(c.args) > 1]
        assert {"schema": "analytics", "table": "events"} in bound
