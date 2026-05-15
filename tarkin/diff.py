"""
Tarkin diff engine.

Compares two :class:`~tarkin.model.GovernanceProject` objects and produces a
structured list of :class:`Change` objects describing every addition, removal,
and modification.  A :func:`render_diff` function writes a human-readable
Markdown report to ``out/``.

Typical usage::

    from tarkin.diff import diff_projects, render_diff
    from tarkin.yaml import YamlLoader

    before = YamlLoader.load(Path("before.yaml"))
    after  = YamlLoader.load(Path("after.yaml"))
    changes = diff_projects(before, after)
    render_diff(changes, Path("out/diff_report.md"))
"""
from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .model import (
    GovernanceProject,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    IndexConfig,
    ForeignKeyConfig,
    RoleConfig,
    SchemaPermissionConfig,
    TablePermissionConfig,
)


# =========================================================
# CHANGE MODEL
# =========================================================


class ChangeKind(str, Enum):
    """The kind of change recorded in a :class:`Change`."""

    ADDED   = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class ObjectType(str, Enum):
    """The category of governance object affected by a change."""

    DATABASE    = "database"
    SCHEMA      = "schema"
    TABLE       = "table"
    COLUMN      = "column"
    INDEX       = "index"
    FOREIGN_KEY = "foreign_key"
    ROLE        = "role"
    PERMISSION  = "permission"


@dataclass
class Change:
    """A single atomic difference between two governance specifications.

    Attributes:
        kind:        Whether the object was added, removed, or modified.
        object_type: The category of the affected object.
        path:        Human-readable dotted path to the object
                     (e.g. ``"public.users.email"``).
        field:       For MODIFIED changes, the name of the field that changed.
                     ``None`` for ADDED/REMOVED.
        before:      The previous value.  ``None`` for ADDED changes.
        after:       The new value.  ``None`` for REMOVED changes.
        note:        Optional free-text annotation (e.g. migration risk notes).
    """

    kind:        ChangeKind
    object_type: ObjectType
    path:        str
    field:       str | None      = None
    before:      Any             = None
    after:       Any             = None
    note:        str | None      = None


# =========================================================
# PUBLIC ENTRY POINT
# =========================================================


def diff_projects(
    before: GovernanceProject,
    after:  GovernanceProject,
) -> list[Change]:
    """Compare two governance projects and return all detected changes.

    Both projects should be fully validated before diffing.  The comparison
    is purely structural — it does not connect to a live database.

    Args:
        before: The current (or baseline) governance specification.
        after:  The target governance specification.

    Returns:
        A list of :class:`Change` objects in breadth-first order:
        database → schemas → tables → columns → indexes → foreign keys →
        roles → permissions.
    """
    changes: list[Change] = []
    _diff_database(before, after, changes)
    _diff_schemas(before, after, changes)
    _diff_roles(before, after, changes)
    return changes


# =========================================================
# RENDERER
# =========================================================


def render_diff(changes: list[Change], output_path: Path) -> None:
    """Write a human-readable Markdown diff report to *output_path*.

    Creates parent directories as needed.  If there are no changes, a brief
    "no changes detected" report is written rather than an empty file.

    Args:
        changes:     The list of changes produced by :func:`diff_projects`.
        output_path: Destination path for the Markdown report.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = ["# Tarkin Diff Report\n"]

    if not changes:
        lines.append("No changes detected between the two governance specifications.\n")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    # Group by object type for readable sections
    by_type: dict[ObjectType, list[Change]] = {}
    for c in changes:
        by_type.setdefault(c.object_type, []).append(c)

    section_order = [
        ObjectType.DATABASE,
        ObjectType.SCHEMA,
        ObjectType.TABLE,
        ObjectType.COLUMN,
        ObjectType.INDEX,
        ObjectType.FOREIGN_KEY,
        ObjectType.ROLE,
        ObjectType.PERMISSION,
    ]

    summary_added   = sum(1 for c in changes if c.kind == ChangeKind.ADDED)
    summary_removed = sum(1 for c in changes if c.kind == ChangeKind.REMOVED)
    summary_modified = sum(1 for c in changes if c.kind == ChangeKind.MODIFIED)

    lines.append(
        f"**Summary**: {len(changes)} change(s) — "
        f"{summary_added} added, {summary_removed} removed, "
        f"{summary_modified} modified.\n"
    )

    for ot in section_order:
        section_changes = by_type.get(ot)
        if not section_changes:
            continue

        lines.append(f"\n## {ot.value.replace('_', ' ').title()}\n")
        lines.append("| Kind | Path | Field | Before | After | Note |")
        lines.append("|------|------|-------|--------|-------|------|")

        for c in section_changes:
            kind_icon = {"added": "✅", "removed": "❌", "modified": "✏️"}.get(c.kind, c.kind)
            before_str = _fmt(c.before)
            after_str  = _fmt(c.after)
            field_str  = c.field or "—"
            note_str   = c.note or "—"
            lines.append(
                f"| {kind_icon} {c.kind} | `{c.path}` | {field_str} "
                f"| {before_str} | {after_str} | {note_str} |"
            )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fmt(value: Any) -> str:
    """Format a diff value for Markdown table display."""
    if value is None:
        return "—"
    s = str(value)
    if len(s) > 60:
        s = s[:57] + "..."
    return f"`{s}`"


# =========================================================
# DATABASE-LEVEL DIFF
# =========================================================


def _diff_database(
    before: GovernanceProject,
    after:  GovernanceProject,
    out:    list[Change],
) -> None:
    """Diff top-level database configuration fields."""
    db_fields = [
        "name", "audit_enabled", "audit_logged", "engine",
        "host", "port", "database", "owner",
    ]
    for f in db_fields:
        b_val = getattr(before.database, f)
        a_val = getattr(after.database, f)
        if b_val != a_val:
            out.append(Change(
                kind=ChangeKind.MODIFIED,
                object_type=ObjectType.DATABASE,
                path="database",
                field=f,
                before=b_val,
                after=a_val,
            ))


# =========================================================
# SCHEMA DIFF
# =========================================================


def _diff_schemas(
    before: GovernanceProject,
    after:  GovernanceProject,
    out:    list[Change],
) -> None:
    """Diff schemas, tables, columns, indexes, and foreign keys."""
    before_map = {s.name: s for s in before.schemas}
    after_map  = {s.name: s for s in after.schemas}

    for name in sorted(set(before_map) - set(after_map)):
        out.append(Change(
            kind=ChangeKind.REMOVED,
            object_type=ObjectType.SCHEMA,
            path=name,
            note="All tables and views in this schema will need to be rebuilt.",
        ))

    for name in sorted(set(after_map) - set(before_map)):
        out.append(Change(
            kind=ChangeKind.ADDED,
            object_type=ObjectType.SCHEMA,
            path=name,
        ))

    for name in sorted(set(before_map) & set(after_map)):
        _diff_schema(before_map[name], after_map[name], out)


def _diff_schema(
    before: SchemaConfig,
    after:  SchemaConfig,
    out:    list[Change],
) -> None:
    """Diff a single schema's fields and its tables."""
    path = before.name
    for f in ("clearance", "audit_enabled"):
        b_val = getattr(before, f)
        a_val = getattr(after, f)
        if b_val != a_val:
            out.append(Change(
                kind=ChangeKind.MODIFIED,
                object_type=ObjectType.SCHEMA,
                path=path,
                field=f,
                before=b_val,
                after=a_val,
            ))

    _diff_tables(before, after, out)


def _diff_tables(
    before_schema: SchemaConfig,
    after_schema:  SchemaConfig,
    out:           list[Change],
) -> None:
    """Diff tables within a schema."""
    before_map = {t.name: t for t in before_schema.tables}
    after_map  = {t.name: t for t in after_schema.tables}
    schema     = before_schema.name

    for name in sorted(set(before_map) - set(after_map)):
        out.append(Change(
            kind=ChangeKind.REMOVED,
            object_type=ObjectType.TABLE,
            path=f"{schema}.{name}",
            note="DROP TABLE in shadow schema required.",
        ))

    for name in sorted(set(after_map) - set(before_map)):
        out.append(Change(
            kind=ChangeKind.ADDED,
            object_type=ObjectType.TABLE,
            path=f"{schema}.{name}",
        ))

    for name in sorted(set(before_map) & set(after_map)):
        _diff_table(schema, before_map[name], after_map[name], out)


def _diff_table(
    schema: str,
    before: TableConfig,
    after:  TableConfig,
    out:    list[Change],
) -> None:
    """Diff a single table's fields, columns, indexes, and foreign keys."""
    path = f"{schema}.{before.name}"

    for f in ("clearance", "audit_enabled"):
        b_val = getattr(before, f)
        a_val = getattr(after, f)
        if b_val != a_val:
            out.append(Change(
                kind=ChangeKind.MODIFIED,
                object_type=ObjectType.TABLE,
                path=path,
                field=f,
                before=b_val,
                after=a_val,
            ))

    _diff_columns(schema, before, after, out)
    _diff_indexes(schema, before, after, out)
    _diff_foreign_keys(schema, before, after, out)


def _diff_columns(
    schema:       str,
    before_table: TableConfig,
    after_table:  TableConfig,
    out:          list[Change],
) -> None:
    """Diff columns within a table."""
    before_map = {c.name: c for c in before_table.columns}
    after_map  = {c.name: c for c in after_table.columns}
    table      = before_table.name

    for name in sorted(set(before_map) - set(after_map)):
        out.append(Change(
            kind=ChangeKind.REMOVED,
            object_type=ObjectType.COLUMN,
            path=f"{schema}.{table}.{name}",
            note="ALTER TABLE DROP COLUMN required in shadow schema.",
        ))

    for name in sorted(set(after_map) - set(before_map)):
        out.append(Change(
            kind=ChangeKind.ADDED,
            object_type=ObjectType.COLUMN,
            path=f"{schema}.{table}.{name}",
        ))

    col_fields = [
        "type", "clearance", "nullable", "unique", "immutable",
        "versioned", "sensitive", "masking_strategy", "default",
        "generated_expression", "generated_storage",
    ]
    for name in sorted(set(before_map) & set(after_map)):
        bc = before_map[name]
        ac = after_map[name]
        path = f"{schema}.{table}.{name}"
        for f in col_fields:
            b_val = getattr(bc, f)
            a_val = getattr(ac, f)
            if b_val != a_val:
                note = None
                if f == "type":
                    note = "Type changes require ALTER COLUMN TYPE — verify cast compatibility."
                elif f == "nullable" and not a_val:
                    note = "Adding NOT NULL requires a backfill or DEFAULT."
                elif f in ("masking_strategy", "sensitive", "clearance"):
                    note = "View regeneration required."
                out.append(Change(
                    kind=ChangeKind.MODIFIED,
                    object_type=ObjectType.COLUMN,
                    path=path,
                    field=f,
                    before=b_val,
                    after=a_val,
                    note=note,
                ))

        # Diff mask_config as a blob — detailed field diffing would add noise
        b_mc = str(bc.mask_config) if bc.mask_config else None
        a_mc = str(ac.mask_config) if ac.mask_config else None
        if b_mc != a_mc:
            out.append(Change(
                kind=ChangeKind.MODIFIED,
                object_type=ObjectType.COLUMN,
                path=path,
                field="mask_config",
                before=b_mc,
                after=a_mc,
                note="View regeneration required.",
            ))


def _diff_indexes(
    schema:       str,
    before_table: TableConfig,
    after_table:  TableConfig,
    out:          list[Change],
) -> None:
    """Diff indexes within a table."""
    before_map = {i.name: i for i in before_table.indexes}
    after_map  = {i.name: i for i in after_table.indexes}
    table      = before_table.name

    for name in sorted(set(before_map) - set(after_map)):
        out.append(Change(
            kind=ChangeKind.REMOVED,
            object_type=ObjectType.INDEX,
            path=f"{schema}.{table}.{name}",
            note="DROP INDEX required.",
        ))

    for name in sorted(set(after_map) - set(before_map)):
        out.append(Change(
            kind=ChangeKind.ADDED,
            object_type=ObjectType.INDEX,
            path=f"{schema}.{table}.{name}",
        ))

    idx_fields = ["columns", "index_type", "unique", "primary_key", "partial_filter"]
    for name in sorted(set(before_map) & set(after_map)):
        bi = before_map[name]
        ai = after_map[name]
        path = f"{schema}.{table}.{name}"
        for f in idx_fields:
            b_val = getattr(bi, f)
            a_val = getattr(ai, f)
            if b_val != a_val:
                out.append(Change(
                    kind=ChangeKind.MODIFIED,
                    object_type=ObjectType.INDEX,
                    path=path,
                    field=f,
                    before=b_val,
                    after=a_val,
                    note="DROP and recreate index required.",
                ))


def _diff_foreign_keys(
    schema:       str,
    before_table: TableConfig,
    after_table:  TableConfig,
    out:          list[Change],
) -> None:
    """Diff foreign key constraints within a table."""
    before_map = {fk.name: fk for fk in before_table.foreign_keys}
    after_map  = {fk.name: fk for fk in after_table.foreign_keys}
    table      = before_table.name

    for name in sorted(set(before_map) - set(after_map)):
        out.append(Change(
            kind=ChangeKind.REMOVED,
            object_type=ObjectType.FOREIGN_KEY,
            path=f"{schema}.{table}.{name}",
        ))

    for name in sorted(set(after_map) - set(before_map)):
        out.append(Change(
            kind=ChangeKind.ADDED,
            object_type=ObjectType.FOREIGN_KEY,
            path=f"{schema}.{table}.{name}",
        ))

    fk_fields = ["column", "referenced_schema", "referenced_table", "referenced_column"]
    for name in sorted(set(before_map) & set(after_map)):
        bf = before_map[name]
        af = after_map[name]
        path = f"{schema}.{table}.{name}"
        for f in fk_fields:
            b_val = getattr(bf, f)
            a_val = getattr(af, f)
            if b_val != a_val:
                out.append(Change(
                    kind=ChangeKind.MODIFIED,
                    object_type=ObjectType.FOREIGN_KEY,
                    path=path,
                    field=f,
                    before=b_val,
                    after=a_val,
                    note="DROP CONSTRAINT and recreate required.",
                ))


# =========================================================
# ROLE DIFF
# =========================================================


def _diff_roles(
    before: GovernanceProject,
    after:  GovernanceProject,
    out:    list[Change],
) -> None:
    """Diff roles and their schema/table permissions."""
    before_map = {r.name: r for r in before.roles}
    after_map  = {r.name: r for r in after.roles}

    for name in sorted(set(before_map) - set(after_map)):
        out.append(Change(
            kind=ChangeKind.REMOVED,
            object_type=ObjectType.ROLE,
            path=name,
            note="Role will be dropped if it was created by Tarkin.",
        ))

    for name in sorted(set(after_map) - set(before_map)):
        out.append(Change(
            kind=ChangeKind.ADDED,
            object_type=ObjectType.ROLE,
            path=name,
        ))

    role_fields = [
        "clearance", "can_login", "can_admin", "can_write",
        "can_maintain", "can_access_sensitive", "member_of",
    ]
    for name in sorted(set(before_map) & set(after_map)):
        br = before_map[name]
        ar = after_map[name]
        for f in role_fields:
            b_val = getattr(br, f)
            a_val = getattr(ar, f)
            if b_val != a_val:
                out.append(Change(
                    kind=ChangeKind.MODIFIED,
                    object_type=ObjectType.ROLE,
                    path=name,
                    field=f,
                    before=b_val,
                    after=a_val,
                ))

        _diff_permissions(br, ar, out)


def _diff_permissions(
    before_role: RoleConfig,
    after_role:  RoleConfig,
    out:         list[Change],
) -> None:
    """Diff schema and table permissions for a role."""
    before_map = {sp.name: sp for sp in before_role.on}
    after_map  = {sp.name: sp for sp in after_role.on}
    role       = before_role.name

    for schema in sorted(set(before_map) - set(after_map)):
        out.append(Change(
            kind=ChangeKind.REMOVED,
            object_type=ObjectType.PERMISSION,
            path=f"{role}.{schema}",
            note="REVOKE USAGE ON SCHEMA required.",
        ))

    for schema in sorted(set(after_map) - set(before_map)):
        out.append(Change(
            kind=ChangeKind.ADDED,
            object_type=ObjectType.PERMISSION,
            path=f"{role}.{schema}",
        ))

    for schema in sorted(set(before_map) & set(after_map)):
        bsp = before_map[schema]
        asp = after_map[schema]
        path = f"{role}.{schema}"

        for f in ("usage", "create"):
            b_val = getattr(bsp, f)
            a_val = getattr(asp, f)
            if b_val != a_val:
                out.append(Change(
                    kind=ChangeKind.MODIFIED,
                    object_type=ObjectType.PERMISSION,
                    path=path,
                    field=f,
                    before=b_val,
                    after=a_val,
                ))

        # Table permissions
        bt_map = {tp.name: tp for tp in bsp.tables}
        at_map = {tp.name: tp for tp in asp.tables}

        for tname in sorted(set(bt_map) - set(at_map)):
            out.append(Change(
                kind=ChangeKind.REMOVED,
                object_type=ObjectType.PERMISSION,
                path=f"{role}.{schema}.{tname}",
                note="REVOKE on table required.",
            ))

        for tname in sorted(set(at_map) - set(bt_map)):
            out.append(Change(
                kind=ChangeKind.ADDED,
                object_type=ObjectType.PERMISSION,
                path=f"{role}.{schema}.{tname}",
            ))

        tp_fields = ["select", "insert", "update", "delete",
                     "truncate", "references", "trigger", "maintain"]
        for tname in sorted(set(bt_map) & set(at_map)):
            btp = bt_map[tname]
            atp = at_map[tname]
            tp_path = f"{role}.{schema}.{tname}"
            for f in tp_fields:
                b_val = getattr(btp, f)
                a_val = getattr(atp, f)
                if b_val != a_val:
                    out.append(Change(
                        kind=ChangeKind.MODIFIED,
                        object_type=ObjectType.PERMISSION,
                        path=tp_path,
                        field=f,
                        before=b_val,
                        after=a_val,
                    ))
