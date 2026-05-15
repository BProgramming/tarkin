"""Validates a GovernanceProjects."""
from __future__ import annotations

from .model import (
    GovernanceProject, SchemaConfig, TableConfig, ColumnConfig,
    MaskingStrategy,
    FullMaskConfig, PartialMaskConfig, HashMaskConfig,
    EmailMaskConfig, PhoneMaskConfig, CreditCardMaskConfig,
    IpAddressMaskConfig, NameMaskConfig,
)

_STRATEGY_CONFIG_MAP = {
    MaskingStrategy.NONE:        type(None),
    MaskingStrategy.FULL:        FullMaskConfig,
    MaskingStrategy.PARTIAL:     PartialMaskConfig,
    MaskingStrategy.HASH:        HashMaskConfig,
    MaskingStrategy.EMAIL:       EmailMaskConfig,
    MaskingStrategy.PHONE:       PhoneMaskConfig,
    MaskingStrategy.CREDIT_CARD: CreditCardMaskConfig,
    MaskingStrategy.IP_ADDRESS:  IpAddressMaskConfig,
    MaskingStrategy.NAME:        NameMaskConfig,
}


class ValidationError(Exception):
    """Raised when semantic validation of a governance project fails."""
    pass


class SemanticValidator:
    """Validates a GovernanceProject for logical consistency."""

    @classmethod
    def validate(cls, project: GovernanceProject) -> bool:
        """
        Validate a GovernanceProject and raise on any errors.

        All validation rules are checked and errors are collected before
        raising, so the caller sees the full list of issues at once.

        Args:
            project: The project to validate.

        Returns:
            True if validation passes.

        Raises:
            ValidationError: If any semantic rule is violated.
        """
        errors = [
            cls._validate_project_structure(project),
            cls._validate_audit_config(project),
            cls._validate_schemas(project),
            cls._validate_tables(project),
            cls._validate_columns(project),
            cls._validate_cross_references(project),
            cls._validate_clearance_rules(project),
            cls._validate_roles(project),
        ]
        errors = [str(e) for e in errors if e]
        if errors:
            raise ValidationError("\n".join(errors))
        return True

    # =====================================================
    # PROJECT LEVEL
    # =====================================================

    @classmethod
    def _validate_project_structure(cls, project: GovernanceProject) -> str | None:
        """Validate that the project has at least one schema and one role."""
        errors = []
        if not project.schemas:
            errors.append("Database must have at least one schema.")
        if not project.roles:
            errors.append("Database must have at least one role.")
        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_audit_config(cls, project: GovernanceProject) -> str | None:
        """Validate audit configuration is consistent."""
        errors = []
        if project.database.audit_enabled and not project.database.audit_logged:
            errors.append("Database has audit_enabled=true but audit_logged is empty. Specify at least one audit log level (e.g. 'ddl', 'write').")
        if not project.database.audit_enabled:
            orphaned = [
                f"{s.name}.{t.name}"
                for s in project.schemas
                for t in s.tables
                if t.audit_enabled
            ]
            if orphaned:
                errors.append(
                    f"Tables have audit_enabled=true but database.audit_enabled=false. "
                    f"Per-table audit has no effect without database-level auditing: "
                    f"{', '.join(orphaned)}."
                )
        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_schemas(cls, project: GovernanceProject) -> str | None:
        """Validate schema-level rules."""
        errors = []
        names  = [s.name for s in project.schemas]
        unq    = cls._check_unique(names, "schema")
        if unq:
            errors.append(unq)
        for schema in project.schemas:
            if not schema.tables:
                errors.append(f"Schema '{schema.name}' must have at least one table.")
        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_tables(cls, project: GovernanceProject) -> str | None:
        """Validate table-level rules."""
        errors = []
        for schema in project.schemas:
            for table in schema.tables:
                if not table.columns:
                    errors.append(f"Table '{schema.name}.{table.name}' must have at least one column.")
                unq = cls._check_unique([c.name for c in table.columns], f"column in {schema.name}.{table.name}")
                if unq:
                    errors.append(unq)
                unq = cls._check_unique([i.name for i in table.indexes], f"index in {schema.name}.{table.name}")
                if unq:
                    errors.append(unq)
                pk_indexes = [i for i in table.indexes if i.primary_key]
                if len(pk_indexes) > 1:
                    errors.append(f"Table '{schema.name}.{table.name}' has more than one primary key index.")
                if not pk_indexes:
                    errors.append(
                        f"Table '{schema.name}.{table.name}' has no primary key defined. "
                        f"Tarkin requires a primary key on all tables to generate safe trigger functions."
                    )
        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_columns(cls, project: GovernanceProject) -> str | None:
        """Validate column-level rules."""
        errors = []
        for schema in project.schemas:
            for table in schema.tables:
                for col in table.columns:
                    vld = cls._validate_column_constraints(schema.name, table.name, col)
                    if vld:
                        errors.append(vld)
        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_column_constraints(
        cls,
        schema_name: str,
        table_name:  str,
        col:         ColumnConfig,
    ) -> str | None:
        """Validate constraints for a single column."""
        errors = []
        path   = f"{schema_name}.{table_name}.{col.name}"

        if col.generated_expression and col.default:
            errors.append(f"Column '{path}' cannot have both a default value and a generated expression.")
        if col.versioned and col.generated_expression:
            errors.append(f"Column '{path}' cannot be versioned and have a generated expression.")
        if col.versioned and col.immutable:
            errors.append(f"Column '{path}' cannot be both versioned and immutable.")

        strategy      = MaskingStrategy(col.masking_strategy)
        expected_type = _STRATEGY_CONFIG_MAP.get(strategy)

        if strategy == MaskingStrategy.NONE:
            if col.mask_config is not None:
                errors.append(
                    f"Column '{path}' has masking_strategy='none' but a mask_config is present. "
                    f"Remove mask_config or set a masking strategy."
                )
        else:
            if expected_type:
                if col.mask_config is None:
                    errors.append(
                        f"Column '{path}' has masking_strategy='{strategy}' but no mask_config. "
                        f"Expected {expected_type.__name__}."
                    )
                elif col.mask_config is not None and not isinstance(col.mask_config, expected_type):
                    errors.append(
                        f"Column '{path}' has masking_strategy='{strategy}' but mask_config is "
                        f"{type(col.mask_config).__name__}. Expected {expected_type.__name__}."
                    )
            elif col.mask_config is not None:
                errors.append(f"Column '{path}' has masking_strategy='{strategy}' but no mask_config.")

        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_cross_references(cls, project: GovernanceProject) -> str | None:
        """Validate that indexes and foreign keys reference columns that exist."""
        errors    = []
        schema_map: dict[str, SchemaConfig] = {s.name: s for s in project.schemas}
        table_map:  dict[str, dict[str, TableConfig]] = {
            s.name: {t.name: t for t in s.tables} for s in project.schemas
        }

        for schema in project.schemas:
            for table in schema.tables:
                col_names = {c.name for c in table.columns}
                for idx in table.indexes:
                    for idx_col in idx.columns:
                        if idx_col not in col_names:
                            errors.append(
                                f"Index '{idx.name}' in {schema.name}.{table.name} "
                                f"references missing column '{idx_col}'."
                            )
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
                            f"references missing table '{fk.referenced_schema}.{fk.referenced_table}'."
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
        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_clearance_rules(cls, project: GovernanceProject) -> str | None:
        """Validate that clearance levels are consistent across the project."""
        errors = []
        for schema in project.schemas:
            for table in schema.tables:
                req_min = max(table.clearance, schema.clearance)
                for col in table.columns:
                    if col.clearance < req_min:
                        errors.append(
                            f"Column '{schema.name}.{table.name}.{col.name}' "
                            f"has clearance below required minimum clearance {req_min}."
                        )
        req_max  = project.clearance_max
        req_min  = project.clearance_min
        role_max = max([r.clearance for r in project.roles], default=0)
        role_min = min([r.clearance for r in project.roles], default=0)
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
        return "\n".join(errors) if errors else None

    @classmethod
    def _validate_roles(cls, project: GovernanceProject) -> str | None:
        """Validate role definitions and references."""
        errors = []

        unq = cls._check_unique([r.name for r in project.roles], "role")
        if unq:
            errors.append(unq)

        role_names   = {r.name for r in project.roles}
        schema_names = {s.name for s in project.schemas}
        has_login    = False

        for role in project.roles:
            if role.can_login:
                has_login = True
            if not role.on and not role.member_of:
                errors.append(f"Role '{role.name}' has no assigned schemas or inherited roles.")
            for sp in role.on:
                if sp.name not in schema_names:
                    errors.append(f"Role '{role.name}' references schema '{sp.name}' which does not exist.")
            for parent in role.member_of:
                if parent not in role_names:
                    errors.append(f"Role '{role.name}' inherits from '{parent}' which does not exist.")

        if not has_login:
            errors.append("Database has no active login roles.")

        return "\n".join(errors) if errors else None

    @classmethod
    def _check_unique(
        cls,
        values:      list[str],
        label:       str,
        trim_prefix: str | None = None,
        trim_suffix: str | None = None,
    ) -> str | None:
        """Check that a list of names contains no duplicates."""
        if trim_prefix:
            values = [v.removeprefix(trim_prefix) for v in values]
        if trim_suffix:
            values = [v.removesuffix(trim_suffix) for v in values]
        if len(values) != len(set(values)):
            seen:       set[str] = set()
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
        return None
