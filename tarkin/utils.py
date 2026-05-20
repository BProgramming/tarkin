from __future__ import annotations
import json
import re
import zipfile
from pathlib import Path
from sqlalchemy import Connection, text

from tarkin.model import GovernanceProject

OUT_DIR = Path("out")
DEFAULT_CREDENTIALS_PATH = Path.home() / ".tarkin" / "credentials.toml"


def build_output_directory(out_dir: Path) -> Path:
    """Create *out_dir* (and parents) if it does not exist and return it.

    Note: this always treats its argument as a *directory*. Callers that hold a
    file path must pass ``path.parent`` — see the `output_file` / `output_directory`
    parameter naming used throughout the codebase.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def find_latest_artifact(out_dir: Path = OUT_DIR) -> Path | None:
    """Return the most recently created build/migrate artifact in *out_dir*, or None."""
    if not out_dir.exists():
        return None
    artifacts = sorted(
        list(out_dir.glob("tarkin_build_*.zip")) + list(out_dir.glob("tarkin_migrate_*.zip")),
        key=lambda p: p.name,
    )
    return artifacts[-1] if artifacts else None


def pg_version(version: str) -> str:
    """Extract a short numeric version (e.g. "16.2") from PostgreSQL's version() string."""
    # version() returns e.g. "PostgreSQL 16.2 on x86_64-pc-linux-gnu, ..."
    m = re.search(r'PostgreSQL\s+(\d+\.\d+)', version)
    if m:
        return m.group(1)
    else:
        parts = version.split()
        if len(parts) >= 2:
            return parts[1]
        else:
            return version


def sql_comment_block_section(title: str, subtitle: str = "") -> str:
    """Return a SQL comment block marking a named section."""
    line  = "-" * 60
    parts = [f"-- {line}", f"-- {title}"]
    if subtitle:
        parts.append(f"-- {subtitle}")
    parts.append(f"-- {line}")
    return "\n".join(parts)


def sql_safe_dollar_quote(yaml_str: str) -> tuple[str, str]:
    """Return a dollar-quote tag that does not appear anywhere in yaml_str."""
    base = "tarkin_yaml"
    tag  = base
    n    = 0
    while f"${tag}$" in yaml_str:
        n  += 1
        tag = f"{base}_{n}"
    return f"${tag}$", f"${tag}$"


def sql_safe_double_quote(name: str) -> str:
    """Double-quote a PostgreSQL identifier."""
    return f'"{name}"'


def sql_safe_escape_string(s: str) -> str:
    """Escape a string value for safe inclusion in a SQL single-quoted literal."""
    if not s:
        return ""
    return s.replace("'", "''")


def sql_select_single_scalar(conn: Connection, query: str) -> str:
    row = conn.execute(text(query)).fetchone()
    return row[0] if row else ""


def write_artifact(zip_path: Path, sql: str, metadata: dict) -> None:
    """Write an artifact to a zip file."""
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("tarkin_build.json", json.dumps(metadata, indent=2))
        zf.writestr("tarkin_build.sql",  sql)


def emit_per_build_inserts(project: GovernanceProject, build_id_expr: str) -> str:
    """Emit per-row INSERTs for all declarative META tables.

    Covers: tarkin_schemas, tarkin_tables, tarkin_columns, tarkin_indexes,
    tarkin_foreign_keys, tarkin_role_schemas, tarkin_role_tables,
    tarkin_subject_identifiers, tarkin_retention.

    Does NOT emit tarkin_migrations rows (build path writes those separately;
    migrate path writes them from the Change list in _emit_migrate_meta_update).
    Does NOT emit tarkin_added_fks / tarkin_added_generated_cols / tarkin_moved_objects /
    tarkin_revoked_grants / tarkin_roles — those are handled by their respective
    callers because the values differ between build and migrate paths.
    """
    b = build_id_expr
    lines: list[str] = []

    for schema in project.schemas:
        sn = sql_safe_escape_string(schema.name)
        lines.append(
            f"    INSERT INTO __META__.tarkin_schemas "
            f"(build_id, name, shadow_name, clearance, audit_enabled) "
            f"VALUES ({b}, '{sn}', 'tk_{sn}', {schema.clearance}, "
            f"{str(schema.audit_enabled).lower()});"
        )
    if project.schemas:
        lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            sn = sql_safe_escape_string(schema.name)
            tn = sql_safe_escape_string(table.name)
            lines.append(
                f"    INSERT INTO __META__.tarkin_tables "
                f"(build_id, schema_name, name, clearance, audit_enabled) "
                f"VALUES ({b}, '{sn}', '{tn}', {table.clearance}, "
                f"{str(table.audit_enabled).lower()});"
            )
    if any(s.tables for s in project.schemas):
        lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            for col in table.columns:
                sn  = sql_safe_escape_string(schema.name)
                tn  = sql_safe_escape_string(table.name)
                cn  = sql_safe_escape_string(col.name)
                ct  = sql_safe_escape_string(col.type)
                dv  = f"'{sql_safe_escape_string(col.default)}'" if col.default else "NULL"
                ge  = f"'{sql_safe_escape_string(col.generated_expression)}'" if col.generated_expression else "NULL"
                ms  = sql_safe_escape_string(col.masking_strategy)
                gs  = sql_safe_escape_string(col.generated_storage)
                lines.append(
                    f"    INSERT INTO __META__.tarkin_columns "
                    f"(build_id, schema_name, table_name, name, type, clearance, nullable, \"unique\", "
                    f"immutable, versioned, sensitive, masking_strategy, "
                    f"default_value, generated_expression, generated_storage) "
                    f"VALUES ({b}, '{sn}', '{tn}', '{cn}', '{ct}', {col.clearance}, "
                    f"{str(col.nullable).lower()}, {str(col.unique).lower()}, "
                    f"{str(col.immutable).lower()}, {str(col.versioned).lower()}, "
                    f"{str(col.sensitive).lower()}, '{ms}', {dv}, {ge}, '{gs}');"
                )
    if any(t.columns for s in project.schemas for t in s.tables):
        lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            for idx in table.indexes:
                sn  = sql_safe_escape_string(schema.name)
                tn  = sql_safe_escape_string(table.name)
                idn = sql_safe_escape_string(idx.name)
                ca  = "ARRAY[" + ", ".join(f"'{c}'" for c in idx.columns) + "]"
                pf  = f"'{sql_safe_escape_string(idx.partial_filter)}'" if idx.partial_filter else "NULL"
                lines.append(
                    f"    INSERT INTO __META__.tarkin_indexes "
                    f"(build_id, schema_name, table_name, name, columns, index_type, \"unique\", primary_key, partial_filter) "
                    f"VALUES ({b}, '{sn}', '{tn}', '{idn}', {ca}, '{idx.index_type}', "
                    f"{str(idx.unique).lower()}, {str(idx.primary_key).lower()}, {pf});"
                )
    if any(t.indexes for s in project.schemas for t in s.tables):
        lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            for fk in table.foreign_keys:
                sn  = sql_safe_escape_string(schema.name)
                tn  = sql_safe_escape_string(table.name)
                fn_ = sql_safe_escape_string(fk.name)
                lines.append(
                    f"    INSERT INTO __META__.tarkin_foreign_keys "
                    f"(build_id, schema_name, table_name, name, column_name, "
                    f"referenced_schema, referenced_table, referenced_column) "
                    f"VALUES ({b}, '{sn}', '{tn}', '{fn_}', "
                    f"'{sql_safe_escape_string(fk.column)}', "
                    f"'{sql_safe_escape_string(fk.referenced_schema)}', "
                    f"'{sql_safe_escape_string(fk.referenced_table)}', "
                    f"'{sql_safe_escape_string(fk.referenced_column)}');"
                )
    if any(t.foreign_keys for s in project.schemas for t in s.tables):
        lines.append("")

    for role in project.roles:
        for sp in role.on:
            rn = sql_safe_escape_string(role.name)
            sn = sql_safe_escape_string(sp.name)
            lines.append(
                f"    INSERT INTO __META__.tarkin_role_schemas "
                f"(build_id, role_name, schema_name, \"usage\", \"create\") "
                f"VALUES ({b}, '{rn}', '{sn}', "
                f"{str(sp.usage).lower()}, {str(sp.create).lower()});"
            )
    if any(r.on for r in project.roles):
        lines.append("")

    for role in project.roles:
        for sp in role.on:
            for tp in sp.tables:
                rn = sql_safe_escape_string(role.name)
                sn = sql_safe_escape_string(sp.name)
                tn = sql_safe_escape_string(tp.name)
                lines.append(
                    f"    INSERT INTO __META__.tarkin_role_tables "
                    f"(build_id, role_name, schema_name, table_name, \"select\", "
                    f"\"insert\", \"update\", \"delete\", \"truncate\", \"references\", \"trigger\", \"maintain\") "
                    f"VALUES ({b}, '{rn}', '{sn}', '{tn}', "
                    f"{str(tp.select).lower()}, {str(tp.insert).lower()}, "
                    f"{str(tp.update).lower()}, {str(tp.delete).lower()}, "
                    f"{str(tp.truncate).lower()}, {str(tp.references).lower()}, "
                    f"{str(tp.trigger).lower()}, {str(tp.maintain).lower()});"
                )
    if any(sp.tables for r in project.roles for sp in r.on):
        lines.append("")

    for schema in project.schemas:
        shadow = f"tk_{schema.name}"
        for table in schema.tables:
            id_cols = [c for c in table.columns if c.is_subject_identifier]
            if not id_cols or table.erase_strategy is None:
                continue
            sn        = sql_safe_escape_string(schema.name)
            tn        = sql_safe_escape_string(table.name)
            sh        = sql_safe_escape_string(shadow)
            es        = sql_safe_escape_string(str(table.erase_strategy))
            col_names = "ARRAY[" + ", ".join(f"'{sql_safe_escape_string(c.name)}'" for c in id_cols) + "]"
            col_types = "ARRAY[" + ", ".join(f"'{sql_safe_escape_string(c.type)}'" for c in id_cols) + "]"
            lines.append(
                f"    INSERT INTO __META__.tarkin_subject_identifiers "
                f"(build_id, schema_name, table_name, shadow_schema, shadow_table, "
                f"identifier_cols, identifier_types, erase_strategy) "
                f"VALUES ({b}, '{sn}', '{tn}', '{sh}', '{tn}', "
                f"{col_names}, {col_types}, '{es}');"
            )
    lines.append("")

    for schema in project.schemas:
        for table in schema.tables:
            if table.retention_days is None or table.erase_strategy is None:
                continue
            sn = sql_safe_escape_string(schema.name)
            tn = sql_safe_escape_string(table.name)
            es = sql_safe_escape_string(str(table.erase_strategy))
            lines.append(
                f"    INSERT INTO __META__.tarkin_retention "
                f"(build_id, schema_name, table_name, erase_strategy, retention_days) "
                f"VALUES ({b}, '{sn}', '{tn}', '{es}', {table.retention_days});"
            )
    lines.append("")

    return "\n".join(lines)
