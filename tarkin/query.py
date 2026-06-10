"""Natural language query interface for Tarkin-governed databases."""
from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy import text

from .credentials import (
    AIProfile,
    ConnectionProfile,
)


class QueryError(Exception):
    """Raised when a query operation fails."""


_SYSTEM_PROMPT = """\
You are a PostgreSQL query generator. You will be given a JSON document
describing the database schema that the calling role can access, including
table and column descriptions, data types, clearance levels, and masking
strategies. Using only that schema context, generate a single valid
PostgreSQL SELECT query that answers the user's request.

Rules:
- Return ONLY the raw SQL query. No explanation, no markdown, no code fences.
- The query must be a SELECT statement.
- Do not reference tables, columns, or schemas not present in the schema context.
- Respect masking strategies: if a column has a masking strategy other than
  'none', note that the value returned may be masked.
"""


def _fetch_schema_context(conn) -> dict[str, Any]:
    """Call all four discovery functions and return a combined dict."""
    def call(fn: str) -> Any:
        row = conn.execute(text(f"SELECT __META__.{fn}()")).fetchone()
        if row and row[0]:
            return row[0]  # psycopg returns json as a Python object already
        return []

    return {
        "schemas": call("get_schemas"),
        "tables":  call("get_tables"),
        "columns": call("get_columns"),
        "roles":   call("get_roles"),
    }


def _extract_sql(raw: str) -> str:
    """Strip markdown fences and whitespace from a model response."""
    raw = re.sub(r"```(?:sql)?", "", raw, flags=re.IGNORECASE).strip()
    raw = raw.strip("`").strip()
    return raw


def _call_anthropic(ai: AIProfile, messages: list[dict]) -> str:
    """Call the Anthropic Messages API and return the text response."""
    try:
        import anthropic  # type: ignore
    except ImportError:
        raise QueryError(
            "The 'anthropic' package is required for tarkin query. "
            "Install it with: pip install tarkin[query]"
        )
    client = anthropic.Anthropic(api_key=ai.api_key.get_secret_value())
    response = client.messages.create(
        model      = ai.model,
        max_tokens = 1024,
        system     = _SYSTEM_PROMPT,
        messages   = messages,
    )
    return response.content[0].text


def _call_openai(ai: AIProfile, messages: list[dict]) -> str:
    """Call the OpenAI Chat Completions API (or compatible endpoint) and return the text response."""
    try:
        import openai  # type: ignore
    except ImportError:
        raise QueryError(
            "The 'openai' package is required for tarkin query. "
            "Install it with: pip install tarkin[query]"
        )
    kwargs: dict[str, Any] = {"api_key": ai.api_key.get_secret_value()}
    if ai.base_url:
        kwargs["base_url"] = ai.base_url
    client = openai.OpenAI(**kwargs)
    full_messages = [{"role": "system", "content": _SYSTEM_PROMPT}] + messages
    response = client.chat.completions.create(
        model      = ai.model,
        max_tokens = 1024,
        messages   = full_messages,
    )
    return response.choices[0].message.content or ""


def _call_ai(ai: AIProfile, messages: list[dict]) -> str:
    """Dispatch to the correct provider adapter."""
    if ai.provider == "anthropic":
        return _call_anthropic(ai, messages)
    elif ai.provider == "openai":
        return _call_openai(ai, messages)
    else:
        raise QueryError(f"Unsupported AI provider: {ai.provider!r}")


def _execute_read_only(conn, sql: str) -> list[dict]:
    """Execute sql in a read-only transaction and return rows as a list of dicts."""
    conn.execute(text("SET TRANSACTION READ ONLY"))
    try:
        result = conn.execute(text(sql))
        columns = list(result.keys())
        rows = [dict(zip(columns, row)) for row in result.fetchall()]
        return rows
    finally:
        # Always rollback, because SELECTs never need committing and this enforces
        # that nothing is persisted even if the model returned a mutating statement
        # that somehow slipped past Postgres's read-only guard.
        conn.execute(text("ROLLBACK"))


def query(
    db_profile: ConnectionProfile,
    ai_profile: AIProfile,
    prompt:     str,
    do_execute: bool,
) -> None:
    """Full query flow: fetch context → generate SQL → optionally execute → print."""
    engine = db_profile.engine()

    try:
        with engine.connect() as conn:
            print("Fetching schema context...", end="\r")
            context = _fetch_schema_context(conn)
            print("Fetching schema context... Done.")

            context_json = json.dumps(context, indent=2, default=str)
            messages: list[dict] = [
                {
                    "role":    "user",
                    "content": (
                        f"Schema context:\n{context_json}\n\n"
                        f"User request: {prompt}"
                    ),
                }
            ]

            print("Generating SQL...", end="\r")
            raw_sql = _call_ai(ai_profile, messages)
            sql     = _extract_sql(raw_sql)
            print("Generating SQL... Done.")

            print(f"SQL generated as:\n{sql}\n")
            if not do_execute:
                return

            print("Executing query...", end="\r")
            try:
                rows = _execute_read_only(conn, sql)
            except Exception as exc:
                raise QueryError(f"Query execution failed: {exc}") from exc
            print("Executing query... Done.")

            result_str = json.dumps(rows, indent=2, default=str)

            interpret_messages: list[dict] = [
                {
                    "role":    "user",
                    "content": (
                        f"The user asked:\n{prompt}\n\n"
                        f"The database returned:\n{result_str}\n\n"
                        "Please provide an accurate and concise response to the "
                        "user explaining the prompt's result."
                    ),
                }
            ]

            print("Interpreting results...", end="\r")
            # For the interpret call we don't want the SQL-only system prompt,
            # so we call the provider directly with a plain conversational message.
            interpretation = _call_ai_interpret(ai_profile, interpret_messages)
            print("Interpreting results... Done.\n")
            print(interpretation)

    except QueryError:
        raise
    except Exception as exc:
        raise QueryError(f"Unexpected error during query: {exc}") from exc
    finally:
        engine.dispose()


def _call_ai_interpret(ai: AIProfile, messages: list[dict]) -> str:
    """Call AI for result interpretation — no SQL system prompt, plain conversation."""
    if ai.provider == "anthropic":
        try:
            import anthropic  # type: ignore
        except ImportError:
            raise QueryError(
                "The 'anthropic' package is required for tarkin query. "
                "Install it with: pip install tarkin[query]"
            )
        client = anthropic.Anthropic(api_key=ai.api_key.get_secret_value())
        response = client.messages.create(
            model      = ai.model,
            max_tokens = 1024,
            messages   = messages,
        )
        return response.content[0].text
    elif ai.provider == "openai":
        try:
            import openai  # type: ignore
        except ImportError:
            raise QueryError(
                "The 'openai' package is required for tarkin query. "
                "Install it with: pip install tarkin[query]"
            )
        kwargs: dict[str, Any] = {"api_key": ai.api_key.get_secret_value()}
        if ai.base_url:
            kwargs["base_url"] = ai.base_url
        client = openai.OpenAI(**kwargs)
        response = client.chat.completions.create(
            model      = ai.model,
            max_tokens = 1024,
            messages   = messages,
        )
        return response.choices[0].message.content or ""
    else:
        raise QueryError(f"Unsupported AI provider: {ai.provider!r}")
