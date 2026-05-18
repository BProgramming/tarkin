"""Inspects a database to produce a GovernanceProject."""
from __future__ import annotations
import re
from sqlalchemy import inspect as sa_inspect, text, Inspector, Connection
from sqlalchemy.engine import Engine
from sqlalchemy.engine.interfaces import ReflectedColumn
from sqlalchemy.dialects import postgresql as pg_dialect

from .credentials import ConnectionProfile
from .model import (
    GovernanceProject,
    DatabaseConfig,
    SchemaConfig,
    TableConfig,
    ColumnConfig,
    IndexConfig,
    ForeignKeyConfig,
    TablePermissionConfig,
    SchemaPermissionConfig,
    RoleConfig,
    DatabaseEngine,
    IndexType,
    RLSPolicyConfig,
)


_SYSTEM_SCHEMAS = {
    "information_schema",
    "__META__",
}

def _is_excluded_schema(name: str) -> bool:
    return name.startswith("pg_") or name in _SYSTEM_SCHEMAS


def _parse_pg_version_number(version_str: str) -> str:
    """Extract a short numeric version (e.g. "16.2") from PostgreSQL's version() string."""
    # version() returns e.g. "PostgreSQL 16.2 on x86_64-pc-linux-gnu, ..."
    m = re.search(r'PostgreSQL\s+(\d+\.\d+)', version_str)
    if m:
        return m.group(1)
    # Fall back to first whitespace-delimited token after "PostgreSQL"
    parts = version_str.split()
    if len(parts) >= 2:
        return parts[1]
    return version_str


def inspect_database(profile: ConnectionProfile, include_tk: bool = False) -> GovernanceProject:
    """Inspect a live PostgreSQL database and return a GovernanceProject."""
    engine = profile.engine()
    try:
        return _build_project(engine, profile, include_tk=include_tk)
    finally:
        engine.dispose()


def _build_project(engine: Engine, profile: ConnectionProfile, include_tk: bool = False) -> GovernanceProject:
    """Build a GovernanceProject from a live PostgreSQL database."""
    with engine.connect() as conn:
        db_name    = _scalar(conn, "SELECT current_database()")
        db_version = _scalar(conn, "SELECT version()")

        schema_names = _get_user_schemas(conn, include_tk=include_tk)
        schemas      = [_build_schema(conn, engine, name) for name in schema_names]
        roles        = _build_roles(conn, include_tk=include_tk)

        audit_enabled = _scalar(conn, """
            SELECT COUNT(*) > 0
            FROM pg_extension e, pg_settings s
            WHERE e.extname = 'pgaudit'
              AND s.name = 'shared_preload_libraries'
              AND s.setting LIKE '%pgaudit%'
        """)

    return GovernanceProject(
        database = DatabaseConfig(
            name          = db_name,
            description   = f"Inspected from {profile.safe_repr()} on {db_version.split(',')[0]}.",
            engine        = DatabaseEngine(DatabaseEngine.POSTGRES),
            host          = profile.host,
            port          = profile.port,
            database      = profile.database,
            version       = _parse_pg_version_number(db_version),
            audit_enabled = bool(audit_enabled),
            profile       = profile.profile,
            owner         = profile.username,
        ),
        schemas  = schemas,
        roles    = roles,
    )


def check_pgcron_available(profile: ConnectionProfile) -> bool:
    """Return True if pg_cron is installed and preloaded on the live database."""
    engine = profile.engine()
    try:
        with engine.connect() as conn:
            result = _scalar(conn, """
                SELECT COUNT(*) > 0
                FROM pg_extension e, pg_settings s
                WHERE e.extname = 'pg_cron'
                  AND s.name = 'shared_preload_libraries'
                  AND s.setting LIKE '%pg_cron%'
            """)
            return bool(result)
    finally:
        engine.dispose()


def _get_user_schemas(conn: Connection, include_tk: bool = False) -> list[str]:
    """Get all database schemas."""
    rows = conn.execute(text("""
        SELECT schema_name
        FROM information_schema.schemata
        WHERE schema_name NOT IN ('information_schema', '__META__')
          AND schema_name NOT LIKE 'pg\\_%'  ESCAPE '\\'
          AND (:include_tk OR schema_name NOT LIKE 'tk\\_%'  ESCAPE '\\')
        ORDER BY schema_name
    """), {"include_tk": include_tk}).fetchall()
    return [r[0] for r in rows]


def _build_schema(conn: Connection, engine: Engine, schema_name: str) -> SchemaConfig:
    """Build a SchemaConfig from a live PostgreSQL database."""
    inspector = sa_inspect(engine)

    tables             = _build_tables(conn, inspector, schema_name)
    views              = _get_views(conn, schema_name)
    mat_views          = _get_materialized_views(conn, schema_name)
    functions          = _get_functions(conn, schema_name)
    trigger_functions  = _get_trigger_functions(conn, schema_name)
    sequences          = _get_sequences(conn, schema_name)
    types_             = _get_custom_types(conn, schema_name)
    collations         = _get_collations(conn, schema_name)
    domains            = _get_domains(conn, schema_name)
    operators          = _get_operators(conn, schema_name)
    foreign_tables     = _get_foreign_tables(conn, schema_name)

    return SchemaConfig(
        name               = schema_name,
        tables             = tables,
        views              = views,
        materialized_views = mat_views,
        functions          = functions,
        trigger_functions  = trigger_functions,
        sequences          = sequences,
        types              = types_,
        collations         = collations,
        domains            = domains,
        operators          = operators,
        foreign_tables     = foreign_tables,
    )


# =========================================================
# TABLES
# =========================================================

def _build_tables(conn: Connection, inspector: Inspector, schema_name: str) -> list[TableConfig]:
    """Build tables from a live PostgreSQL database."""
    table_names = inspector.get_table_names(schema=schema_name)
    return [_build_table(conn, inspector, schema_name, str(t)) for t in sorted(table_names)]


def _build_table(conn: Connection, inspector: Inspector, schema_name: str, table_name: str) -> TableConfig:
    """Build a TableConfig from a live PostgreSQL database."""
    columns      = _build_columns(conn, inspector, schema_name, table_name)
    indexes      = _build_indexes(conn, schema_name, table_name)
    foreign_keys = _build_foreign_keys(inspector, schema_name, table_name)
    rls_enabled, rls_force, rls_policies = _build_rls(conn, schema_name, table_name)

    return TableConfig(
        name         = table_name,
        columns      = columns,
        indexes      = indexes,
        foreign_keys = foreign_keys,
        rls_enabled  = rls_enabled,
        rls_force    = rls_force,
        rls_policies = rls_policies,
    )


def _build_columns(conn: Connection, inspector: Inspector, schema_name: str, table_name: str) -> list[ColumnConfig]:
    """Build ColumnConfigs from a live PostgreSQL database."""
    sa_cols = inspector.get_columns(table_name, schema=schema_name)
    pg_cols = _get_pg_column_details(conn, schema_name, table_name)

    cols = []
    for sa_col in sa_cols:
        name     = sa_col["name"]
        pg_extra = pg_cols.get(name, {})

        col_type    = _pg_type_string(sa_col) # noqa
        default = pg_extra.get("column_default")
        default = str(default) if default is not None else None

        if default and default.startswith("nextval("):
            default = None

        nullable = sa_col.get("nullable", True)
        unique   = bool(pg_extra.get("is_unique", False))

        cols.append(ColumnConfig(
            name     = name,
            type     = col_type,
            nullable = nullable,
            unique   = unique,
            default  = default,
        ))

    return cols


def _get_pg_column_details(conn: Connection, schema_name: str, table_name: str) -> dict[str, dict[str, str | bool | None]]:
    """Pull column-level details from information_schema."""
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
            "column_default": str(r[1]) if r[1] is not None else None,
            "is_unique":      bool(r[2]),
        }
        for r in rows
    }


def _pg_type_string(sa_col: dict | ReflectedColumn) -> str:
    """Produce a canonical PostgreSQL type string from a SQLAlchemy column dict."""
    type_obj = sa_col.get("type")
    if not type_obj:
        return "text"
    elif hasattr(type_obj, 'compile'):
        compiled = type_obj.compile(dialect=pg_dialect.dialect())
        return str(compiled).lower()
    else:
        return str(type_obj).lower()


_INDEX_TYPE_MAP = {
    "btree": IndexType.BTREE,
    "hash":  IndexType.HASH,
    "gin":   IndexType.GIN,
    "gist":  IndexType.GIST,
    "brin":  IndexType.BRIN,
}


def _build_indexes(conn: Connection, schema_name: str, table_name: str) -> list[IndexConfig]:
    """Build IndexConfigs from a live PostgreSQL database."""
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
            name           = r[0],
            unique         = bool(r[1]),
            primary_key    = bool(r[2]),
            index_type     = IndexType(idx_type),
            columns        = list(r[4]),
            partial_filter = r[5],
        ))
    return indexes


def _build_foreign_keys(inspector: Inspector, schema_name: str, table_name: str) -> list[ForeignKeyConfig]:
    """Build ForeignKeyConfigs from a live PostgreSQL database."""
    sa_fks = inspector.get_foreign_keys(table_name, schema=schema_name)
    fks = []
    for fk in sa_fks:
        constrained = fk.get("constrained_columns", [])
        referred    = fk.get("referred_columns", [])
        ref_schema  = fk.get("referred_schema") or schema_name
        ref_table   = fk.get("referred_table", "")
        fk_name     = fk.get("name") or f"fk_{table_name}_{'_'.join(constrained)}"

        for local_col, remote_col in zip(constrained, referred):
            fks.append(ForeignKeyConfig(
                name              = fk_name if len(constrained) == 1 else f"{fk_name}_{local_col}",
                column            = local_col,
                referenced_schema = ref_schema,
                referenced_table  = ref_table,
                referenced_column = remote_col,
            ))
    return fks


def _get_views(conn: Connection, schema_name: str) -> list[str]:
    """Return view names. Body is not stored in the governance YAML."""
    rows = conn.execute(text("""
        SELECT table_name
        FROM information_schema.views
        WHERE table_schema = :schema
        ORDER BY table_name
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


def _get_materialized_views(conn: Connection, schema_name: str) -> list[str]:
    """Return materialized view names. Body is not stored in the governance YAML."""
    rows = conn.execute(text("""
        SELECT relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = :schema
          AND c.relkind = 'm'
        ORDER BY relname
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


def _get_functions(conn: Connection, schema_name: str) -> list[str]:
    """Return function signatures (name + arg types). Body is not stored in the governance YAML."""
    rows = conn.execute(text("""
        SELECT p.proname || '(' ||
               pg_get_function_identity_arguments(p.oid) || ')'  AS sig
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = :schema
          AND p.prokind = 'f'
          AND p.prorettype != 'trigger'::regtype
          AND NOT EXISTS (
                SELECT 1 FROM pg_depend d
                WHERE d.objid = p.oid
                  AND d.deptype IN ('e', 'x')
            )
        ORDER BY sig
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


def _get_trigger_functions(conn: Connection, schema_name: str) -> list[str]:
    """Return trigger function signatures (functions whose return type is trigger). Body is not stored in the governance YAML."""
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


def _get_sequences(conn: Connection, schema_name: str) -> list[str]:
    """Return sequence names. Format: 'sequence_name' or 'sequence_name OWNED BY table.column'."""
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
            short_table = owned_table.split(".")[-1].strip('"')
            results.append(f"{seq_name} OWNED BY {short_table}.{owned_col}")
        else:
            results.append(seq_name)
    return results


def _get_custom_types(conn: Connection, schema_name: str) -> list[str]:
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
          AND NOT EXISTS (
              SELECT 1 FROM pg_class c
              WHERE c.relnamespace = t.typnamespace
                AND c.relname = t.typname
                AND c.relkind = 'r'
          )
        ORDER BY t.typname
    """), {"schema": schema_name}).fetchall()

    result = []
    for r in rows:
        name, type_type, definition = r
        if type_type == "e":
            result.append(f"ENUM {name} ({definition})")
        elif type_type == "c":
            result.append(f"TYPE {name} ({definition})")
    return result


def _get_collations(conn: Connection, schema_name: str) -> list[str]:
    """Return collations."""
    rows = conn.execute(text("""
        SELECT collname
        FROM pg_collation c
        JOIN pg_namespace n ON n.oid = c.collnamespace
        WHERE n.nspname = :schema
        ORDER BY collname
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


def _get_domains(conn: Connection, schema_name: str) -> list[str]:
    """Return domain definitions as 'domain_name AS base_type [CHECK (...)]'."""
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


def _get_operators(conn: Connection, schema_name: str) -> list[str]:
    """Return operator signatures as 'oprname(left_type,right_type)'."""
    rows = conn.execute(text("""
        SELECT
            o.oprname,
            CASE WHEN o.oprleft  = 0 THEN 'NONE'
                 ELSE o.oprleft::regtype::text END AS left_type,
            CASE WHEN o.oprright = 0 THEN 'NONE'
                 ELSE o.oprright::regtype::text END AS right_type
        FROM pg_operator o
        JOIN pg_namespace n ON n.oid = o.oprnamespace
        WHERE n.nspname = :schema
          AND NOT EXISTS (
              SELECT 1 FROM pg_depend d
              WHERE d.objid   = o.oid
                AND d.deptype IN ('e', 'x')
          )
        ORDER BY o.oprname, left_type, right_type
    """), {"schema": schema_name}).fetchall()
    return [f"{r[0]}({r[1]},{r[2]})" for r in rows]


def _get_foreign_tables(conn: Connection, schema_name: str) -> list[str]:
    """Return foreign table names."""
    rows = conn.execute(text("""
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = :schema
          AND c.relkind = 'f'
        ORDER BY c.relname
    """), {"schema": schema_name}).fetchall()
    return [r[0] for r in rows]


def _build_rls(
    conn:        Connection,
    schema_name: str,
    table_name:  str,
) -> tuple[bool, bool, list[RLSPolicyConfig]]:
    """
    Return (rls_enabled, rls_force, policies) for a table from pg_class and pg_policies.

    Only non-Tarkin policies are returned.
    """
    rls_row = conn.execute(text("""
        SELECT c.relrowsecurity, c.relforcerowsecurity
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = :schema AND c.relname = :table AND c.relkind = 'r'
    """), {"schema": schema_name, "table": table_name}).fetchone()

    if not rls_row:
        return False, False, []

    rls_enabled = bool(rls_row[0])
    rls_force   = bool(rls_row[1])

    if not rls_enabled:
        return False, False, []

    policy_rows = conn.execute(text("""
        SELECT
            policyname,
            roles,
            qual,         -- USING expression
            with_check    -- WITH CHECK expression
        FROM pg_policies
        WHERE schemaname = :schema
          AND tablename  = :table
          AND policyname NOT LIKE 'tarkin_rls_%'
        ORDER BY policyname
    """), {"schema": schema_name, "table": table_name}).fetchall()

    policies: list[RLSPolicyConfig] = []
    for row in policy_rows:
        _, roles_arr, using_expr, check_expr = row
        roles = ["PUBLIC" if r2.lower() == "public" else r2 for r2 in [r.strip('"') for r in (roles_arr or [])]]
        if using_expr:
            policies.append(RLSPolicyConfig(
                roles      = roles,
                using_expr = using_expr,
                check_expr = check_expr if check_expr else None,
            ))

    return rls_enabled, rls_force, policies


def _build_roles(conn: Connection, include_tk: bool = False) -> list[RoleConfig]:
    """Build RoleConfigs from a live PostgreSQL database"""
    role_rows = conn.execute(text("""
        SELECT
            r.rolname,
            r.rolsuper,
            r.rolcreatedb,
            r.rolcreaterole,
            r.rolinherit,
            r.rolcanlogin,
            r.rolbypassrls,
            obj_description(r.oid, 'pg_authid') AS description,
            ARRAY(
                SELECT m.rolname
                FROM pg_auth_members am
                JOIN pg_roles m ON m.oid = am.roleid
                WHERE am.member = r.oid
                  AND m.rolname NOT LIKE 'pg\\_%'
                ORDER BY m.rolname
            ) AS member_of
        FROM pg_roles r
        WHERE r.rolname NOT LIKE 'pg\\_%'
        ORDER BY r.rolname
    """)).fetchall()

    schema_grants = _get_all_schema_grants(conn, include_tk=include_tk)
    table_grants  = _get_all_table_grants(conn, include_tk=include_tk)

    roles = []
    for r in role_rows:
        (role_name, is_super, can_create_db, can_create_role,
         inherit, can_login, bypass_rls, description, member_of) = r

        schema_perms: dict[str, SchemaPermissionConfig] = {}
        for grant in schema_grants.get(role_name, []):
            schema = str(grant["schema"])
            if schema not in schema_perms:
                schema_perms[schema] = SchemaPermissionConfig(
                    name   = schema,
                    usage  = False,
                    create = False,
                )
            if grant["privilege"] == "USAGE":
                schema_perms[schema].usage = True
            if grant["privilege"] == "CREATE":
                schema_perms[schema].create = True

        for grant in table_grants.get(role_name, []):
            schema = str(grant["schema"])
            table  = str(grant["table"])
            if schema not in schema_perms:
                schema_perms[schema] = SchemaPermissionConfig(
                    name   = schema,
                    usage  = False,
                    create = False,
                )
            table_perm = next(
                (tp for tp in schema_perms[schema].tables if tp.name == table),
                None,
            )
            if table_perm is None:
                table_perm = TablePermissionConfig(name=table)
                schema_perms[schema].tables.append(table_perm)

            privilege = grant["privilege"]
            if privilege == "SELECT":     table_perm.select     = True
            if privilege == "INSERT":     table_perm.insert     = True
            if privilege == "UPDATE":     table_perm.update     = True
            if privilege == "DELETE":     table_perm.delete     = True
            if privilege == "TRUNCATE":   table_perm.truncate   = True
            if privilege == "REFERENCES": table_perm.references = True
            if privilege == "TRIGGER":    table_perm.trigger    = True
            if privilege == "MAINTAIN":   table_perm.maintain   = True

        roles.append(RoleConfig(
            name         = role_name,
            description  = description,
            can_login    = bool(can_login),
            can_admin    = bool(is_super),
            can_write    = bool(can_create_db or can_create_role),
            can_maintain = bool(is_super) or any(tp.maintain for sp in schema_perms.values() for tp in sp.tables),
            member_of    = [m for m in (member_of or [])],
            on           = list(schema_perms.values()),
        ))

    return roles


def _get_all_schema_grants(conn: Connection, include_tk: bool = False) -> dict[str, list[dict]]:
    """Returns {role_name: [{schema, privilege}]} for all non-system schemas."""
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
          AND (:include_tk OR n.nspname NOT LIKE 'tk\\_%')
          AND r.rolname NOT LIKE 'pg\\_%'
          AND has_schema_privilege(r.rolname, n.nspname, p.privilege_type)
        ORDER BY r.rolname, n.nspname, p.privilege_type
    """), {"include_tk": include_tk}).fetchall()

    result: dict[str, list[dict]] = {}
    for schema, grantee, privilege in rows:
        result.setdefault(grantee, []).append({"schema": schema, "privilege": privilege})
    return result


def _get_all_table_grants(conn: Connection, include_tk: bool = False) -> dict[str, list[dict]]:
    """Returns {role_name: [{schema, table, privilege}]} for all non-system tables."""
    rows = conn.execute(text("""
        SELECT
            grantee,
            table_schema  AS schema,
            table_name    AS table,
            privilege_type AS privilege
        FROM information_schema.role_table_grants
        WHERE table_schema NOT LIKE 'pg\\_%'
          AND table_schema NOT IN ('information_schema', '__META__')
          AND (:include_tk OR table_schema NOT LIKE 'tk\\_%')
          AND grantee NOT LIKE 'pg\\_%'
        ORDER BY grantee, table_schema, table_name, privilege_type
    """), {"include_tk": include_tk}).fetchall()

    result: dict[str, list[dict]] = {}
    for grantee, schema, table, privilege in rows:
        result.setdefault(grantee, []).append({
            "schema":    schema,
            "table":     table,
            "privilege": privilege,
        })
    return result


def _scalar(conn: Connection, query: str) -> str:
    row = conn.execute(text(query)).fetchone()
    return row[0] if row else ""
