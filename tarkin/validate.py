from __future__ import annotations
from .model import (
    GovernanceProject, SchemaConfig, TableConfig, ColumnConfig,
    IndexConfig, ForeignKeyConfig, RoleConfig, UserConfig,
)


# =========================================================
# ERRORS
# =========================================================

class ValidationError(Exception):
    pass


# =========================================================
# SEMANTIC VALIDATOR
# =========================================================

class SemanticValidator:

    @classmethod
    def validate(cls, project: GovernanceProject) -> bool:
        errors = []
        errors.append(cls._validate_project_structure(project))
        errors.append(cls._validate_schemas(project))
        errors.append(cls._validate_tables(project))
        errors.append(cls._validate_columns(project))
        errors.append(cls._validate_cross_references(project))
        errors.append(cls._validate_clearance_rules(project))
        errors.append(cls._validate_roles(project))
        errors.append(cls._validate_users(project))

        errors = [e for e in errors if e]

        if errors:
            raise ValidationError("\n".join(errors))

        return True

    # =====================================================
    # PROJECT LEVEL
    # =====================================================

    @classmethod
    def _validate_project_structure(cls, project: GovernanceProject) -> str | None:
        if not project.schemas:
            return "Database must have at least one schema."

    # =====================================================
    # SCHEMA RULES
    # =====================================================

    @classmethod
    def _validate_schemas(cls, project: GovernanceProject) -> str | None:
        errors = []

        names = [s.name for s in project.schemas]
        unq = cls._check_unique(names, "schema")
        if unq:
            errors.append(unq)

        for schema in project.schemas:
            if not schema.tables:
                errors.append(f"Schema '{schema.name}' must have at least one table.")

        if errors:
            return "\n".join(errors)

    # =====================================================
    # TABLE RULES
    # =====================================================

    @classmethod
    def _validate_tables(cls, project: GovernanceProject) -> str | None:
        errors = []

        for schema in project.schemas:
            for table in schema.tables:

                if not table.columns:
                    errors.append(f"Table '{schema.name}.{table.name}' must have at least one column.")

                col_names = [c.name for c in table.columns]
                unq = cls._check_unique(col_names, f"column in {schema.name}.{table.name}")
                if unq:
                    errors.append(unq)

                idx_names = [i.name for i in table.indexes]
                unq = cls._check_unique(idx_names, f"index in {schema.name}.{table.name}")
                if unq:
                    errors.append(unq)

        if errors:
            return "\n".join(errors)

    # =====================================================
    # COLUMN RULES
    # =====================================================

    @classmethod
    def _validate_columns(cls, project: GovernanceProject) -> str | None:
        errors = []
        for schema in project.schemas:
            for table in schema.tables:
                for col in table.columns:
                    vld = cls._validate_column_constraints(schema.name, table.name, col)
                    if vld:
                        errors.append(vld)
        if errors:
            return "\n".join(errors)

    @classmethod
    def _validate_column_constraints(
        cls, schema_name: str, table_name: str, col: ColumnConfig
    ) -> str | None:
        errors = []
        path = f"{schema_name}.{table_name}.{col.name}"

        if col.generated_expression and col.default:
            errors.append(f"Column '{path}' cannot have both default and generated expression.")

        if col.versioned and col.generated_expression:
            errors.append(f"Column '{path}' cannot be versioned and generated.")

        if col.versioned and col.immutable:
            errors.append(f"Column '{path}' cannot be both versioned and immutable.")

        if col.encrypted and not (col.sensitive or col.clearance > 0):
            errors.append(
                f"Column '{path}' is encrypted but not marked sensitive or assigned clearance above 0."
            )

        if errors:
            return "\n".join(errors)

    # =====================================================
    # CROSS REFERENCES
    # =====================================================

    @classmethod
    def _validate_cross_references(cls, project: GovernanceProject) -> str | None:
        errors = []

        # Build global schema map and per-schema table maps
        schema_map: dict[str, SchemaConfig] = {s.name: s for s in project.schemas}
        table_map: dict[str, dict[str, TableConfig]] = {
            s.name: {t.name: t for t in s.tables}
            for s in project.schemas
        }

        for schema in project.schemas:
            for table in schema.tables:
                col_names = {c.name for c in table.columns}

                # Validate index columns exist on this table
                for idx in table.indexes:
                    for idx_col in idx.columns:
                        if idx_col not in col_names:
                            errors.append(
                                f"Index '{idx.name}' in {schema.name}.{table.name} "
                                f"references missing column '{idx_col}'."
                            )

                # Validate foreign keys — look up the *referenced* schema's table map
                for fk in table.foreign_keys:
                    if fk.referenced_schema not in schema_map:
                        errors.append(
                            f"Foreign key '{fk.name}' in {schema.name}.{table.name} "
                            f"references missing schema '{fk.referenced_schema}'."
                        )
                        continue

                    ref_tables = table_map[fk.referenced_schema]

                    if fk.referenced_table not in ref_tables:
                        errors.append(
                            f"Foreign key '{fk.name}' in {schema.name}.{table.name} "
                            f"references missing table "
                            f"'{fk.referenced_schema}.{fk.referenced_table}'."
                        )
                        continue

                    ref_col_names = {c.name for c in ref_tables[fk.referenced_table].columns}
                    if fk.referenced_column not in ref_col_names:
                        errors.append(
                            f"Foreign key '{fk.name}' in {schema.name}.{table.name} "
                            f"references missing column "
                            f"'{fk.referenced_schema}.{fk.referenced_table}.{fk.referenced_column}'."
                        )

                    if fk.column not in col_names:
                        errors.append(
                            f"Foreign key '{fk.name}' in {schema.name}.{table.name} "
                            f"references local column '{fk.column}' which does not exist."
                        )

        if errors:
            return "\n".join(errors)

    # =====================================================
    # CLEARANCE RULES
    # =====================================================

    @classmethod
    def _validate_clearance_rules(cls, project: GovernanceProject) -> str | None:
        errors = []
        for schema in project.schemas:
            for table in schema.tables:
                req_min = min(table.clearance, schema.clearance)
                for col in table.columns:
                    if col.clearance < req_min:
                        errors.append(
                            f"Column '{schema.name}.{table.name}.{col.name}' "
                            f"has clearance below required minimum clearance {req_min}."
                        )

        req_max = project.clearance_max
        req_min = project.clearance_min
        role_max = max([role.clearance for role in project.roles], default=0)
        role_min = min([role.clearance for role in project.roles], default=0)
        if role_max < req_max:
            errors.append(
                f"The database has a maximum clearance of {req_max}, "
                f"but highest role clearance is {role_max}."
            )
        if role_min > req_min:
            errors.append(
                f"The database has a minimum clearance of {req_min}, "
                f"but lowest role clearance is {role_min}."
            )

        if errors:
            return "\n".join(errors)

    # =====================================================
    # ROLE RULES
    # =====================================================

    @classmethod
    def _validate_roles(cls, project: GovernanceProject) -> str | None:
        errors = []

        role_names = [r.name for r in project.roles]
        unq = cls._check_unique(role_names, "role")
        if unq:
            errors.append(unq)

        schema_names = {s.name for s in project.schemas}
        for role in project.roles:
            if not role.on:
                errors.append(f"Role '{role.name}' has no assigned schemas or tables.")
            for sp in role.on:
                if sp.schema_name not in schema_names:
                    errors.append(
                        f"Role '{role.name}' references schema '{sp.schema_name}' which does not exist."
                    )

        if errors:
            return "\n".join(errors)

    # =====================================================
    # USER RULES
    # =====================================================

    @classmethod
    def _validate_users(cls, project: GovernanceProject) -> str | None:
        errors = []

        role_names = {r.name for r in project.roles}
        active = False
        for user in project.users:
            if not active and user.active:
                active = True
            if not user.roles:
                errors.append(f"User '{user.username}' has no assigned roles.")
            for role_name in user.roles:
                if role_name not in role_names:
                    errors.append(
                        f"User '{user.username}' references role '{role_name}' which does not exist."
                    )

        if not active:
            errors.append("Database has no active users.")

        if errors:
            return "\n".join(errors)

    # =====================================================
    # UTILS
    # =====================================================

    @classmethod
    def _check_unique(
        cls,
        values: list[str],
        label: str,
        trim_prefix: str | None = None,
        trim_suffix: str | None = None,
    ) -> str | None:
        if trim_prefix:
            values = [v.removeprefix(trim_prefix) for v in values]
        if trim_suffix:
            values = [v.removesuffix(trim_suffix) for v in values]

        if len(values) != len(set(values)):
            seen: set[str] = set()
            duplicates: set[str] = set()
            for value in values:
                if value in seen:
                    duplicates.add(value)
                else:
                    seen.add(value)

            msg = f"Duplicate {label} names detected: {sorted(duplicates)}."
            if trim_prefix:
                msg += f" (Prefix '{trim_prefix}' is ignored)."
            if trim_suffix:
                msg += f" (Suffix '{trim_suffix}' is ignored)."
            return msg
