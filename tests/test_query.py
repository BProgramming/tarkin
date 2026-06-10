"""Tests for tarkin.query — AI payload construction and read-only execution."""
from __future__ import annotations

import json
from typing import Literal
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from tarkin.credentials import AIProfile, ConnectionProfile
from tarkin.query import (
    _extract_sql,
    _fetch_schema_context,
    _execute_read_only,
    query,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_ai(provider: Literal["anthropic", "openai"] = "anthropic", model: str = "claude-test") -> AIProfile:
    return AIProfile(
        provider = provider,
        api_key  = SecretStr("test-key"),
        model    = model,
    )


def _make_db_profile() -> ConnectionProfile:
    return ConnectionProfile(
        profile  = "test",
        host     = "localhost",
        port     = 5432,
        database = "testdb",
        username = "testuser",
        password = SecretStr("testpass"),
    )


_FAKE_CONTEXT = {
    "schemas": [{"name": "analytics", "clearance": 0, "description": "Analytics schema"}],
    "tables":  [{"schema": "analytics", "name": "events", "description": "Raw event log"}],
    "columns": [
        {"schema": "analytics", "table": "events", "name": "event_id",   "type": "bigint",      "description": "Primary key"},
        {"schema": "analytics", "table": "events", "name": "event_name", "type": "text",        "description": "Event type"},
        {"schema": "analytics", "table": "events", "name": "created_at", "type": "timestamptz", "description": "When it happened"},
    ],
    "roles": [{"name": "analyst", "clearance": 0, "can_admin": False}],
}


# ---------------------------------------------------------------------------
# _extract_sql
# ---------------------------------------------------------------------------

class TestExtractSql:

    def test_strips_sql_fence(self) -> None:
        raw = "```sql\nSELECT 1;\n```"
        assert _extract_sql(raw) == "SELECT 1;"

    def test_strips_plain_fence(self) -> None:
        raw = "```\nSELECT 1;\n```"
        assert _extract_sql(raw) == "SELECT 1;"

    def test_passthrough_clean_sql(self) -> None:
        raw = "SELECT id FROM users WHERE active = true;"
        assert _extract_sql(raw) == raw

    def test_strips_surrounding_whitespace(self) -> None:
        raw = "  \n  SELECT 1  \n  "
        assert _extract_sql(raw) == "SELECT 1"


# ---------------------------------------------------------------------------
# _fetch_schema_context
# ---------------------------------------------------------------------------

class TestFetchSchemaContext:

    def test_calls_all_four_functions(self) -> None:
        """_fetch_schema_context calls get_schemas, get_tables, get_columns, get_roles."""
        mock_conn = MagicMock()

        # Each call to conn.execute().fetchone() returns a row with the context value
        mock_conn.execute.return_value.fetchone.side_effect = [
            (_FAKE_CONTEXT["schemas"],),
            (_FAKE_CONTEXT["tables"],),
            (_FAKE_CONTEXT["columns"],),
            (_FAKE_CONTEXT["roles"],),
        ]

        result = _fetch_schema_context(mock_conn)

        assert result["schemas"] == _FAKE_CONTEXT["schemas"]
        assert result["tables"]  == _FAKE_CONTEXT["tables"]
        assert result["columns"] == _FAKE_CONTEXT["columns"]
        assert result["roles"]   == _FAKE_CONTEXT["roles"]

        # Verify all four function names were called
        executed_sql = [str(c.args[0]) for c in mock_conn.execute.call_args_list]
        assert any("get_schemas" in s for s in executed_sql)
        assert any("get_tables"  in s for s in executed_sql)
        assert any("get_columns" in s for s in executed_sql)
        assert any("get_roles"   in s for s in executed_sql)


# ---------------------------------------------------------------------------
# AI payload test — what gets sent to the model on the first call
# ---------------------------------------------------------------------------

class TestAiPayload:

    def test_anthropic_payload_contains_schema_context_and_prompt(self) -> None:
        """The first AI call includes the full schema context JSON and user prompt."""
        ai      = _make_ai(provider="anthropic")
        prompt  = "How many events happened yesterday?"
        context = _FAKE_CONTEXT
        context_json = json.dumps(context, indent=2, default=str)

        captured_messages = []

        def fake_call(ai_profile, messages):
            captured_messages.extend(messages)
            return "SELECT COUNT(*) FROM analytics.events WHERE created_at >= NOW() - INTERVAL '1 day';"

        mock_conn   = MagicMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__  = MagicMock(return_value=False)

        with patch("tarkin.query._call_ai",           side_effect=fake_call):
            with patch("tarkin.query._fetch_schema_context", return_value=context):
                with patch("tarkin.credentials.ConnectionProfile.engine", return_value=mock_engine):
                    query(
                        db_profile = _make_db_profile(),
                        ai_profile = ai,
                        prompt     = prompt,
                        do_execute = False,
                    )

        assert len(captured_messages) == 1
        msg = captured_messages[0]
        assert msg["role"] == "user"
        assert context_json in msg["content"]
        assert prompt in msg["content"]
        assert "Schema context:" in msg["content"]
        assert "User request:" in msg["content"]

    def test_openai_payload_contains_schema_context_and_prompt(self) -> None:
        """OpenAI path sends the same user message content."""
        ai      = _make_ai(provider="openai", model="gpt-4o")
        prompt  = "Show me the top 5 events by count."
        context = _FAKE_CONTEXT
        context_json = json.dumps(context, indent=2, default=str)

        captured_messages = []

        def fake_call(ai_profile, messages):
            captured_messages.extend(messages)
            return "SELECT event_name, COUNT(*) FROM analytics.events GROUP BY 1 ORDER BY 2 DESC LIMIT 5;"

        mock_conn   = MagicMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__  = MagicMock(return_value=False)

        with patch("tarkin.query._call_ai",           side_effect=fake_call):
            with patch("tarkin.query._fetch_schema_context", return_value=context):
                with patch("tarkin.credentials.ConnectionProfile.engine", return_value=mock_engine):
                    query(
                        db_profile = _make_db_profile(),
                        ai_profile = ai,
                        prompt     = prompt,
                        do_execute = False,
                    )

        assert len(captured_messages) == 1
        msg = captured_messages[0]
        assert context_json in msg["content"]
        assert prompt in msg["content"]


# ---------------------------------------------------------------------------
# Execute + interpret flow
# ---------------------------------------------------------------------------

class TestExecuteAndInterpret:

    def test_execute_sends_result_to_ai_with_correct_format(self) -> None:
        """When do_execute=True, DB results are sent to the AI in the expected format."""
        ai     = _make_ai(provider="anthropic")
        prompt = "How many events happened yesterday?"

        fake_rows   = [{"count": 42}]
        fake_sql    = "SELECT COUNT(*) AS count FROM analytics.events;"
        result_json = json.dumps(fake_rows, indent=2, default=str)

        interpret_messages_captured = []

        def fake_call_ai(ai_profile, messages):
            return fake_sql

        def fake_interpret(ai_profile, messages):
            interpret_messages_captured.extend(messages)
            return "There were 42 events yesterday."

        result_mock = MagicMock()
        result_mock.keys.return_value     = ["count"]
        result_mock.fetchall.return_value = [(42,)]

        mock_conn = MagicMock()
        mock_conn.execute.return_value = result_mock

        mock_engine = MagicMock()
        mock_engine.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_engine.connect.return_value.__exit__  = MagicMock(return_value=False)

        with patch("tarkin.query._call_ai",               side_effect=fake_call_ai):
            with patch("tarkin.query._call_ai_interpret", side_effect=fake_interpret):
                with patch("tarkin.query._fetch_schema_context", return_value=_FAKE_CONTEXT):
                    with patch("tarkin.credentials.ConnectionProfile.engine", return_value=mock_engine):
                        query(
                            db_profile = _make_db_profile(),
                            ai_profile = ai,
                            prompt     = prompt,
                            do_execute = True,
                        )

        assert len(interpret_messages_captured) == 1
        content = interpret_messages_captured[0]["content"]
        assert f"The user asked:\n{prompt}" in content
        assert "The database returned:" in content
        assert result_json in content
        assert "Please provide an accurate and concise response" in content

    def test_read_only_transaction_is_set(self) -> None:
        """SET TRANSACTION READ ONLY is always issued before executing the query."""
        mock_conn = MagicMock()

        result_mock = MagicMock()
        result_mock.keys.return_value     = ["id"]
        result_mock.fetchall.return_value = [(1,)]

        mock_conn.execute.return_value = result_mock

        _execute_read_only(mock_conn, "SELECT id FROM users;")

        executed = [str(c.args[0]) for c in mock_conn.execute.call_args_list]
        assert any("READ ONLY" in s for s in executed)

    def test_rollback_always_called(self) -> None:
        """ROLLBACK is always called after execution, even on success."""
        mock_conn = MagicMock()

        result_mock = MagicMock()
        result_mock.keys.return_value     = ["id"]
        result_mock.fetchall.return_value = [(1,)]

        mock_conn.execute.return_value = result_mock

        _execute_read_only(mock_conn, "SELECT id FROM users;")

        executed = [str(c.args[0]) for c in mock_conn.execute.call_args_list]
        assert any("ROLLBACK" in s for s in executed)

    def test_rollback_called_on_execution_error(self) -> None:
        """ROLLBACK is still issued even when the query raises."""
        mock_conn = MagicMock()

        def raise_on_query(stmt):
            if "SELECT" in str(stmt):
                raise Exception("relation does not exist")
            return MagicMock()

        mock_conn.execute.side_effect = raise_on_query

        with pytest.raises(Exception, match="relation does not exist"):
            _execute_read_only(mock_conn, "SELECT * FROM nonexistent;")

        executed = [str(c.args[0]) for c in mock_conn.execute.call_args_list]
        assert any("ROLLBACK" in s for s in executed)
