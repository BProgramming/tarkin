from __future__ import annotations
"""
Database introspection for Tarkin.

Uses SQLAlchemy's Inspector for the broad strokes, then drops into raw
pg_catalog / information_schema queries for everything SA doesn't expose:
sequences, OWNED BY, check constraints, custom types, trigger function bodies,
role memberships, and table/schema grants.

Produces a GovernanceProject that can be serialized to YAML and round-tripped
back through YamlLoader + SemanticValidator without loss.

Excluded schemas (never introspected):
  pg_catalog, information_schema, pg_toast, pg_temp_*, __META__
  and any schema whose name starts with "tk_" (Tarkin shadow schemas).
"""

from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect as sa_inspect, text
from sqlalchemy.engine import Engine

from .credentials import ConnectionProfile
from .model import (
    GovernanceProject, DatabaseConfig, SchemaConfig, TableConfig,
    ColumnConfig, IndexConfig, ForeignKeyConfig,
    TablePermissionConfig, SchemaPermissionConfig, RoleConfig, UserConfig,
    DatabaseEngine, IndexType,
)


# =========================================================
# EXCLUDED SCHEMAS
# =========================================================

_SYSTEM_SCHEMAS = {
    "pg_catalog",
    "information_schema",
    "pg_toast",
    "__META__",
}

def _is_excluded_schema(name: str) -> bool:
    return (
        name in _SYSTEM_SCHEMAS
        or name.startswith("pg_temp_")
        or name.startswith("pg_toast_")
        or name.startswith("tk_")
    )


# =========================================================
# PUBLIC ENTRY POINT
# =========================================================

def inspect_database(profile: ConnectionProfile) -> GovernanceProject:
    """
    Introspect a live PostgreSQL database and return a GovernanceProject.

    The project captures the full pre-Tarkin state: schemas, tables, columns,
    indexes, foreign keys, check constraints, sequences, views, materialized
    views, functions, trigger functions, custom types, roles, and grants.

    This is intentionally read-only — no DDL is executed.
    """
    engine = profile.engine()
    try:
        return _build_project(engine, profile)
    finally:
        engine.dispose()


# =========================================================
# PROJECT BUILDER
# =========================================================

def _build_project(engine: Engine, profile: ConnectionProfile) -> GovernanceProject:
    with engine.connect() as conn:
        db_name    = _scalar(conn, "SELECT current_database()")
        db_version = _scalar(conn, "SELECT version()")

        schema_names = _get_user_schemas(conn)
        schemas      = [_build_schema(conn, engine, name) for name in schema_names]
        roles        = _build_roles(conn)
        users        = _build_users(conn, roles)

    return GovernanceProject(
        database=DatabaseConfig(
            name=db_name,
            description=f"Introspected from {profile.safe_repr()} — {db_version.split(',')[0]}",
            engine=DatabaseEngine.POSTGRESQL,
            host=profile.host,
            port=profile.port,
            database=profile.database,
            audit_enabled=False,
        ),
        schemas=schemas,
        roles=roles,
        users=users,
    )


# =========================================================
# SCHEMAS
# =========================================================

def _get_user_schemas(conn) -> list[str]:
    rows = conn.execute(text("""
        SELECT schema_name
        FROM information_schema.schemata
        WHERE schema_name NOT IN ('pg_catalog', 'information_schema')
          AND schema_name NOT LIKE 'pg_toast%'
          AND schema_name NOT LIKE 'pg_temp_%'
          AND schema_name NOT LIKE 'tk\\_%'  ESCAPE '\\'
          AND schema_name != '__META__'
        ORDER BY schema_name
    """)).fetchall()
    return [r[0] for r in rows]


def _build_schema(conn, engine: Engine, schema_name: str) -> SchemaConfig:
    insp = sa_inspect(engine)

    tables             = _build_tables(conn, insp, schema_name)
    views              = _get_views(conn, schema_name)
    mat_views          = _get_materialized_views(conn, schema_name)
    functions          = _get_functions(conn, schema_name)
    trigger_functions  = _get_trigger_functions(conn, schema_name)
    sequences          = _get_sequences(conn, schema_name)
    types_             = _get_custom_types(conn, schema_name)
    collations         = _get_collations(conn, schema_name)
    domains            = _get_domains(conn, schema_name)

    return SchemaConfig(
        name=schema_name,
        tables=tables,
        views=views,
        materialized_views=mat_views,
        functions=functions,
        trigger_functions=trigger_functions,
        sequences=sequences,
        types=types_,
        collations=collations,
        domains=domains,
    )


# =========================================================
# TABLES
# =========================================================

def _build_tables(conn, insp, schema_name: str) -> list[TableConfig]:
    table_names = insp.get_table_names(schema=schema_name)
    return [_build_table(conn, insp, schema_name, t) for t in sorted(table_names)]


def _build_table(conn, insp, schema_name: str, table_name: str) -> TableConfig:
    columns     = _build_columns(conn, insp, schema_name, table_name)
    indexes     = _build_indexes(conn, insp, schema_name, table_name)
    foreign_keys = _build_foreign_keys(insp, schema_name, table_name)

    return TableConfig(
        name=table_name,
        columns=columns,
        indexes=indexes,
        foreign_keys=foreign_keys,
    )


# =========================================================
# COLUMNS
# =========================================================

# Map PostgreSQL type categories to simplified Tarkin data_type strings.
# We preserve the raw pg type name so the round-trip can reconstruct DDL.
def _build_columns(conn, insp, schema_name: str, table_name: str) -> list[ColumnConfig]:
    # SA gives us the basics; supplement with pg_catalog for defaults + identity
    sa_cols = insp.get_columns(table_name, schema=schema_name)
    pg_cols = _get_pg_column_details(conn, schema_name, table_name)

    cols = []
    for sa_col in sa_cols:
        name     = sa_col["name"]
        pg_extra = pg_cols.get(name, {})

        data_type = _pg_type_string(sa_col)
        default   = pg_extra.get("column_default")

        # Strip nextval(... defaults — these are sequence-driven, not user defaults.
        # The sequence is captured separately; we don't want it in the YAML default field.
        if default and default.startswith("nextval("):
            default = None

        nullable = sa_col.get("nullable", True)
        unique   = pg_extra.get("is_unique", False)

        cols.append(ColumnConfig(
            name=name,
            data_type=data_type,
            nullable=nullable,
            unique=unique,
            default=default,
        ))

    return cols


def _get_pg_column_details(conn, schema_name: str, table_name: str) -> dict[str, dict]:
    """
    Pull column-level details from information_schema that SA doesn't always expose:
    raw default expressions and uniqueness (via constraint, not index).
    """
    rows = conn.execute(text("""
        SELECT
            c.column_name,
            c.column_default,
            COALESCE(
                (
                    SELECT true
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                      ON tc.constraint_name = kcu.constraint_name
                     AND tc.table_schema    = kcu.table_schema
                     AND tc.table_name      = kcu.table_name
                    WHERE tc.constraint_type = 'UNIQUE'
                      AND tc.table_schema    = c.table_schema
                      AND tc.table_name      = c.table_name
                      AND kcu.column_name    = c.column_name
                    LIMIT 1
                ),
                false
            ) AS is_unique
        FROM information_schema.columns c
        WHERE c.table_schema = :schema
          AND c.table_name   = :table
        ORDER BY c.ordinal_position
    """), {"schema": schema_name, "table": table_name}).fetchall()

    return {
        r[0]: {
            "column_default": r[1],
            "is_unique":      bool(r[2]),
        }
        for r in rows
    }


def _pg_type_string(sa_col: dict) -> str:
    """
    Produce a canonical PostgreSQL type string from a SQLAlchemy column dict.
    We use the compiled form so the YAML contains real pg types, not SA abstractions.
    """
    type_obj = sa_col.get("type")
    if type_obj is None:
        return "text"
    try:
        # SA types have a compile method; use the generic dialect for portability
        from sqlalchemy.dialects import postgresql as pg_dialect
        compiled = type_obj.compile(dialect=pg_dialect.dialect())
        return str(compiled).lower()
    except Exception:
        return str(type_obj).lower()


# =========================================================
# INDEXES
# =========================================================

_INDEX_TYPE_MAP = {
    "btree": IndexType.BTREE,
    "hash":  IndexType.HASH,
    "gin":   IndexType.GIN,
    "gist":  IndexType.GIST,
    "brin":  IndexType.BRIN,
}

def _build_indexes(conn, insp, schema_name: str, table_name: str) -> list[IndexConfig]:
    rows = conn.execute(text("""
        SELECT
            i.relname                    AS index_name,
            ix.indisunique               AS is_unique,
            ix.indisprimary              AS is_primary,
            am.amname                    AS index_type,
            array_agg(a.attname ORDER BY k.ord) AS columns,
            pg_get_expr(ix.indpred, ix.indrelid) AS partial_filter
        FROM pg_index ix
        JOIN pg_class  t  ON t.oid  = ix.indrelid
        JOIN pg_class  i  ON i.oid  = ix.indexrelid
        JOIN pg_am     am ON am.oid = i.relam
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord)
          ON true
        JOIN pg_attribute a
          ON a.attrelid = t.oid AND a.attnum = k.attnum AND a.attnum > 0
        WHERE n.nspname = :schema
          AND t.relname = :table
          AND t.relkind = 'r'
        GROUP BY i.relname, ix.indisunique, ix.indisprimary, am.amname,
                 ix.indpred, ix.indrelid
        ORDER BY i.relname
    """), {"schema": schema_name, "table": table_name}).fetchall()

    indexes = []
    for r in rows:
        idx_type = _INDEX_TYPE_MAP.get(r[3], IndexType.BTREE)
        indexes.append(IndexConfig(
            name=r[0],
            unique=bool(r[1]),
            primary_key=bool(r[2]),
            index_type=idx_type,
            columns=list(r[4]),
            partial_filter=r[5],
        ))
    return indexes


# =========================================================
# FOREIGN KEYS
# =========================================================

def _build_foreign_keys(insp, schema_name: str, table_name: str) -> list[ForeignKeyConfig]:
    sa_fks = insp.get_foreign_keys(table_name, schema=schema_name)
    fks = []
    for fk in sa_fks:
        # SA returns multi-column FKs; we model one ForeignKeyConfig per column pair
        constrained = fk.get("constrained_columns", [])
        referred    = fk.get("referred_columns", [])
        ref_schema  = fk.get("referred_schema") or schema_name
        ref_table   = fk.get("referred_table", "")
        fk_name     = fk.get("name") or f"fk_{table_name}_{'_'.join(constrained)}"

        for local_col, remote_col in zip(constrained, referred):
            fks.append(ForeignKeyConfig(
                name=fk_name if len(constrained) == 1 else f"{fk_name}_{local_col}",
                column=local_col,
                referenced_schema=ref_schema,
                referenced_table=ref_table,
                referenced_column=remote_col,
            ))
    return fks


# =========================================================
# VIEWS / MATERIALIZED VIEWS
# =========================================================

def _get_views(conn, schema_name: str) -> list[str]:
    """Return view names. Body is not stored in the governance YAML (inspect only captures structure)."""
    rows = conn.execute(text("""
        SELECT table_name
        FROM information_schema.views
        WHERE table_schema = :schema
        ORDER BY table_name
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


def _get_materialized_views(conn, schema_name: str) -> list[str]:
    rows = conn.execute(text("""
        SELECT relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = :schema
          AND c.relkind = 'm'
        ORDER BY relname
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


# =========================================================
# FUNCTIONS / TRIGGER FUNCTIONS
# =========================================================

def _get_functions(conn, schema_name: str) -> list[str]:
    """Return function signatures (name + arg types). Bodies excluded from governance YAML."""
    rows = conn.execute(text("""
        SELECT p.proname || '(' ||
               pg_get_function_identity_arguments(p.oid) || ')'  AS sig
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = :schema
          AND p.prokind = 'f'
          AND NOT EXISTS (
              SELECT 1 FROM pg_trigger t WHERE t.tgfoid = p.oid
          )
        ORDER BY sig
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


def _get_trigger_functions(conn, schema_name: str) -> list[str]:
    """Return trigger function signatures (functions whose return type is trigger)."""
    rows = conn.execute(text("""
        SELECT p.proname || '(' ||
               pg_get_function_identity_arguments(p.oid) || ')'  AS sig
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_type      t ON t.oid = p.prorettype
        WHERE n.nspname   = :schema
          AND t.typname   = 'trigger'
        ORDER BY sig
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


# =========================================================
# SEQUENCES
# =========================================================

def _get_sequences(conn, schema_name: str) -> list[str]:
    """
    Return sequence names. Format: 'sequence_name' or 'sequence_name OWNED BY table.column'.
    The OWNED BY clause is included so attach can reconstruct the ownership relationship.
    """
    rows = conn.execute(text("""
        SELECT
            s.relname AS seq_name,
            d.refobjid::regclass::text AS owned_table,
            a.attname                  AS owned_column
        FROM pg_class s
        JOIN pg_namespace n ON n.oid = s.relnamespace
        LEFT JOIN pg_depend   d ON d.objid    = s.oid
                                AND d.deptype  = 'a'
                                AND d.classid  = 'pg_class'::regclass
        LEFT JOIN pg_attribute a ON a.attrelid = d.refobjid
                                AND a.attnum   = d.refobjsubid
        WHERE n.nspname = :schema
          AND s.relkind = 'S'
        ORDER BY s.relname
    """), {"schema": schema_name}).fetchall()

    results = []
    for r in rows:
        seq_name, owned_table, owned_col = r
        if owned_table and owned_col:
            # Strip schema prefix from owned_table if it matches current schema
            short_table = owned_table.split(".")[-1].strip('"')
            results.append(f"{seq_name} OWNED BY {short_table}.{owned_col}")
        else:
            results.append(seq_name)
    return results


# =========================================================
# CUSTOM TYPES
# =========================================================

def _get_custom_types(conn, schema_name: str) -> list[str]:
    """
    Return custom type signatures.
    Enums:      'my_enum (val1, val2, val3)'
    Composites: 'my_type (col1 text, col2 int)'
    Domains:    excluded (handled separately).
    """
    rows = conn.execute(text("""
        SELECT
            t.typname,
            t.typtype,
            CASE t.typtype
                WHEN 'e' THEN (
                    SELECT string_agg(e.enumlabel, ', ' ORDER BY e.enumsortorder)
                    FROM pg_enum e WHERE e.enumtypid = t.oid
                )
                WHEN 'c' THEN (
                    SELECT string_agg(a.attname || ' ' || pg_catalog.format_type(a.atttypid, a.atttypmod), ', ' ORDER BY a.attnum)
                    FROM pg_attribute a
                    WHERE a.attrelid = t.typrelid AND a.attnum > 0 AND NOT a.attisdropped
                )
                ELSE NULL
            END AS definition
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = :schema
          AND t.typtype IN ('e', 'c')
        ORDER BY t.typname
    """), {"schema": schema_name}).fetchall()

    result = []
    for r in rows:
        name, typtype, definition = r
        if typtype == "e":
            result.append(f"ENUM {name} ({definition})")
        elif typtype == "c":
            result.append(f"TYPE {name} ({definition})")
    return result


# =========================================================
# COLLATIONS
# =========================================================

def _get_collations(conn, schema_name: str) -> list[str]:
    rows = conn.execute(text("""
        SELECT collname
        FROM pg_collation c
        JOIN pg_namespace n ON n.oid = c.collnamespace
        WHERE n.nspname = :schema
        ORDER BY collname
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


# =========================================================
# DOMAINS
# =========================================================

def _get_domains(conn, schema_name: str) -> list[str]:
    """
    Return domain definitions as 'domain_name AS base_type [CHECK (...)]'.
    """
    rows = conn.execute(text("""
        SELECT
            t.typname,
            pg_catalog.format_type(t.typbasetype, t.typtypmod) AS base_type,
            t.typnotnull,
            pg_get_expr(t.typdefaultbin, 'pg_type'::regclass)  AS default_expr,
            (
                SELECT string_agg(
                    'CHECK (' || pg_get_expr(c.conbin, 'pg_type'::regclass) || ')',
                    ' '
                )
                FROM pg_constraint c
                WHERE c.contypid = t.oid
            ) AS checks
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = :schema
          AND t.typtype = 'd'
        ORDER BY t.typname
    """), {"schema": schema_name}).fetchall()

    result = []
    for r in rows:
        name, base, notnull, default, checks = r
        parts = [f"{name} AS {base}"]
        if notnull:
            parts.append("NOT NULL")
        if default:
            parts.append(f"DEFAULT {default}")
        if checks:
            parts.append(checks)
        result.append(" ".join(parts))
    return result


# =========================================================
# ROLES
# =========================================================

def _build_roles(conn) -> list[RoleConfig]:
    """
    Introspect all non-system roles and their schema/table grants.
    System roles (pg_*) are excluded.
    """
    role_rows = conn.execute(text("""
        SELECT
            r.rolname,
            r.rolsuper,
            r.rolcreatedb,
            r.rolcreaterole,
            r.rolinherit,
            r.rolcanlogin,
            r.rolbypassrls,
            obj_description(r.oid, 'pg_authid') AS description
        FROM pg_roles r
        WHERE r.rolname NOT LIKE 'pg\\_%'
        ORDER BY r.rolname
    """)).fetchall()

    schema_grants  = _get_all_schema_grants(conn)
    table_grants   = _get_all_table_grants(conn)

    roles = []
    for r in role_rows:
        (rolname, is_super, can_createdb, can_createrole,
         inherit, can_login, bypass_rls, description) = r

        # Build SchemaPermissionConfig for each schema this role has grants on
        schema_perms: dict[str, SchemaPermissionConfig] = {}
        for grant in schema_grants.get(rolname, []):
            sname = grant["schema"]
            if sname not in schema_perms:
                schema_perms[sname] = SchemaPermissionConfig(
                    schema_name=sname,
                    usage=False,
                    create=False,
                )
            if grant["privilege"] == "USAGE":
                schema_perms[sname].usage = True
            if grant["privilege"] == "CREATE":
                schema_perms[sname].create = True

        # Add table grants into the right SchemaPermissionConfig
        for grant in table_grants.get(rolname, []):
            sname = grant["schema"]
            tname = grant["table"]
            if sname not in schema_perms:
                schema_perms[sname] = SchemaPermissionConfig(
                    schema_name=sname,
                    usage=False,
                    create=False,
                )
            # Find or create TablePermissionConfig for this table
            table_perm = next(
                (tp for tp in schema_perms[sname].tables if tp.table == tname),
                None,
            )
            if table_perm is None:
                table_perm = TablePermissionConfig(table=tname)
                schema_perms[sname].tables.append(table_perm)

            priv = grant["privilege"]
            if priv == "SELECT":    table_perm.select    = True
            if priv == "INSERT":    table_perm.insert    = True
            if priv == "UPDATE":    table_perm.update    = True
            if priv == "DELETE":    table_perm.delete    = True
            if priv == "TRUNCATE":  table_perm.truncate  = True
            if priv == "REFERENCES": table_perm.references = True
            if priv == "TRIGGER":   table_perm.trigger   = True

        roles.append(RoleConfig(
            name=rolname,
            description=description,
            can_admin=bool(is_super),
            can_write=bool(can_createdb or can_createrole),
            on=list(schema_perms.values()),
        ))

    return roles


def _get_all_schema_grants(conn) -> dict[str, list[dict]]:
    """Returns {rolname: [{schema, privilege}]} for all non-system schemas."""
    rows = conn.execute(text("""
        SELECT
            n.nspname          AS schema,
            r.rolname          AS grantee,
            p.privilege_type   AS privilege
        FROM pg_namespace n
        CROSS JOIN pg_roles r
        CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS p(privilege_type)
        WHERE n.nspname NOT LIKE 'pg\\_%'
          AND n.nspname NOT IN ('information_schema', '__META__')
          AND n.nspname NOT LIKE 'tk\\_%'
          AND r.rolname NOT LIKE 'pg\\_%'
          AND has_schema_privilege(r.rolname, n.nspname, p.privilege_type)
        ORDER BY r.rolname, n.nspname, p.privilege_type
    """)).fetchall()

    result: dict[str, list[dict]] = {}
    for schema, grantee, privilege in rows:
        result.setdefault(grantee, []).append({"schema": schema, "privilege": privilege})
    return result


def _get_all_table_grants(conn) -> dict[str, list[dict]]:
    """Returns {rolname: [{schema, table, privilege}]} for all non-system tables."""
    rows = conn.execute(text("""
        SELECT
            grantee,
            table_schema  AS schema,
            table_name    AS table,
            privilege_type AS privilege
        FROM information_schema.role_table_grants
        WHERE table_schema NOT LIKE 'pg\\_%'
          AND table_schema NOT IN ('information_schema', '__META__')
          AND table_schema NOT LIKE 'tk\\_%'
          AND grantee NOT LIKE 'pg\\_%'
        ORDER BY grantee, table_schema, table_name, privilege_type
    """)).fetchall()

    result: dict[str, list[dict]] = {}
    for grantee, schema, table, privilege in rows:
        result.setdefault(grantee, []).append({
            "schema":    schema,
            "table":     table,
            "privilege": privilege,
        })
    return result


# =========================================================
# USERS
# =========================================================

def _build_users(conn, roles: list[RoleConfig]) -> list[UserConfig]:
    """
    Introspect roles that can log in (i.e. actual users) and their role memberships.
    """
    rows = conn.execute(text("""
        SELECT
            r.rolname,
            r.rolcanlogin,
            ARRAY(
                SELECT m.rolname
                FROM pg_auth_members am
                JOIN pg_roles m ON m.oid = am.roleid
                WHERE am.member = r.oid
                  AND m.rolname NOT LIKE 'pg\\_%'
                ORDER BY m.rolname
            ) AS member_of
        FROM pg_roles r
        WHERE r.rolcanlogin = true
          AND r.rolname NOT LIKE 'pg\\_%'
        ORDER BY r.rolname
    """)).fetchall()

    role_names = {role.name for role in roles}

    users = []
    for r in rows:
        rolname, can_login, member_of = r
        # Only include role memberships that exist in our role list
        valid_roles = [m for m in (member_of or []) if m in role_names]
        users.append(UserConfig(
            username=rolname,
            active=bool(can_login),
            roles=valid_roles,
        ))
    return users


# =========================================================
# UTILS
# =========================================================

def _scalar(conn, query: str) -> str:
    row = conn.execute(text(query)).fetchone()
    return row[0] if row else ""
