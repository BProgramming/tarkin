"""Tests for tarkin.update — patch contract enforcement."""
from __future__ import annotations

import re

from tarkin.update import PATCHES


# (label, pattern matching a non-idempotent construct)
FORBIDDEN = [
    ("CREATE SCHEMA without IF NOT EXISTS",
     r"\bCREATE\s+SCHEMA\s+(?!IF\s+NOT\s+EXISTS)"),
    ("CREATE TABLE without IF NOT EXISTS",
     r"\bCREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS)"),
    ("ADD COLUMN without IF NOT EXISTS",
     r"\bADD\s+COLUMN\s+(?!IF\s+NOT\s+EXISTS)"),
    ("CREATE INDEX without IF NOT EXISTS",
     r"\bCREATE\s+(UNIQUE\s+)?INDEX\s+(?!IF\s+NOT\s+EXISTS|CONCURRENTLY\s+IF\s+NOT\s+EXISTS)"),
    ("CREATE FUNCTION without OR REPLACE",
     r"\bCREATE\s+FUNCTION\b"),
    ("CREATE VIEW without OR REPLACE",
     r"\bCREATE\s+(MATERIALIZED\s+)?VIEW\b"),
    ("CREATE TRIGGER without OR REPLACE",
     r"\bCREATE\s+TRIGGER\b"),
    ("DROP without IF EXISTS",
     r"\bDROP\s+(TABLE|COLUMN|INDEX|FUNCTION|VIEW|SCHEMA|TRIGGER|CONSTRAINT)\s+(?!IF\s+EXISTS)"),
    ("ALTER TABLE ... RENAME",
     r"\bALTER\s+TABLE\b[^;]*\bRENAME\b"),
]


def _strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", "", sql)
    return re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)


class TestPatchContract:

    def test_patches_are_well_formed(self) -> None:
        for patch in PATCHES:
            assert len(patch) == 2
            description, sql = patch
            assert description.strip()
            assert sql.strip()

    def test_descriptions_are_unique(self) -> None:
        descriptions = [d for d, _ in PATCHES]
        assert len(descriptions) == len(set(descriptions))

    def test_no_patch_uses_a_non_idempotent_construct(self) -> None:
        failures: list[str] = []
        for description, sql in PATCHES:
            body = _strip_sql_comments(sql)
            for label, pattern in FORBIDDEN:
                if re.search(pattern, body, flags=re.IGNORECASE):
                    failures.append(f"{description!r}: {label}")
        assert not failures, "Non-idempotent patch(es): " + "; ".join(failures)


class TestPatchOrdering:

    def test_meta_tables_precede_discovery_functions(self) -> None:
        """LANGUAGE sql function bodies are validated at CREATE time."""
        descriptions = [d for d, _ in PATCHES]
        assert descriptions.index("Ensure __META__ tables exist") < \
               descriptions.index("Refresh __META__ discovery functions")


class TestPatchContent:

    def test_meta_patch_creates_the_tables_the_functions_read(self) -> None:
        sql = next(s for d, s in PATCHES if d == "Ensure __META__ tables exist")
        for table in ("tarkin_builds", "tarkin_schemas", "tarkin_tables",
                      "tarkin_columns", "tarkin_roles", "tarkin_role_schemas",
                      "tarkin_role_tables", "tarkin_retention", "tarkin_erasures"):
            assert f"CREATE TABLE IF NOT EXISTS __META__.{table}" in sql

    def test_discovery_patch_carries_the_governance_view(self) -> None:
        sql = next(s for d, s in PATCHES if d == "Refresh __META__ discovery functions")
        assert "CREATE OR REPLACE VIEW __META__.tarkin_governance" in sql
        assert "GRANT SELECT ON __META__.tarkin_governance TO PUBLIC;" in sql

    def test_governance_view_is_created_after_the_meta_tables(self) -> None:
        """The view reads the discovery functions, which read the __META__ tables."""
        descriptions = [d for d, _ in PATCHES]
        assert descriptions.index("Ensure __META__ tables exist") < \
               descriptions.index("Refresh __META__ discovery functions")

    def test_discovery_patch_carries_all_functions(self) -> None:
        sql = next(s for d, s in PATCHES if d == "Refresh __META__ discovery functions")
        for fn in ("get_schemas", "get_tables", "get_columns", "get_roles",
                   "get_build", "get_retention", "get_erasures", "get_rls_policies"):
            assert f"CREATE OR REPLACE FUNCTION __META__.{fn}(" in sql
