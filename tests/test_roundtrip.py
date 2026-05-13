"""
Serialize → YAML string → YamlLoader round-trip tests.
"""
from __future__ import annotations

from tarkin.model import (
    DatabaseConfig, AuditLogLevel, GovernanceProject,
    MaskingStrategy, PartialMaskConfig, PartialMaskVisibleSide,
)
from tarkin.serialize import Serializer
from tarkin.yaml import YamlLoader
from tarkin.validate import SemanticValidator
from tests.fixtures import (
    build_minimal_project, build_cross_schema_project,
    build_clearance_project, build_masking_project,
)


def _roundtrip(project: GovernanceProject) -> GovernanceProject | None:
    yaml_str = Serializer.to_yaml_string(project)
    return YamlLoader.loads(yaml_str)


def test_minimal_project_roundtrips() -> None:
    proj = build_minimal_project()
    rt   = _roundtrip(proj)
    assert rt is not None
    if rt:
        assert rt.database.name == proj.database.name
        assert len(rt.schemas)  == len(proj.schemas)
        assert rt.schemas[0].name           == proj.schemas[0].name
        assert rt.schemas[0].tables[0].name == proj.schemas[0].tables[0].name
        assert rt.roles[0].name             == proj.roles[0].name


def test_cross_schema_project_roundtrips() -> None:
    proj = build_cross_schema_project()
    rt   = _roundtrip(proj)
    assert rt is not None
    if rt:
        assert len(rt.schemas) == len(proj.schemas)
        sales = next(s for s in rt.schemas if s.name == "sales")
        fk    = sales.tables[0].foreign_keys[0]
        assert fk.referenced_schema == "public"
        assert fk.referenced_table  == "users"


def test_clearance_project_roundtrips() -> None:
    proj = build_clearance_project()
    rt   = _roundtrip(proj)
    assert rt is not None
    if rt:
        clinical = rt.schemas[0]
        ssn_col  = next(c for c in clinical.tables[0].columns if c.name == "ssn")
        assert ssn_col.clearance  == 2
        assert ssn_col.sensitive  is True
        assert ssn_col.encrypted  is True


def test_masking_project_roundtrips() -> None:
    proj = build_masking_project()
    rt   = _roundtrip(proj)
    assert rt is not None
    if rt:
        table = rt.schemas[0].tables[0]
        col_map = {c.name: c for c in table.columns}

        # Full mask
        full_col = col_map["full_name"]
        assert full_col.masking_strategy == MaskingStrategy.FULL
        assert full_col.mask_config is not None

        # Partial mask
        partial_col = col_map["partial_code"]
        assert partial_col.masking_strategy == MaskingStrategy.PARTIAL
        assert isinstance(partial_col.mask_config, PartialMaskConfig)
        assert partial_col.mask_config.visible_length == 4
        assert partial_col.mask_config.visible_side   == PartialMaskVisibleSide.RIGHT

        # Hash mask
        hash_col = col_map["hashed_value"]
        assert hash_col.masking_strategy == MaskingStrategy.HASH

        # Email mask
        email_col = col_map["email"]
        assert email_col.masking_strategy == MaskingStrategy.EMAIL

        # Phone mask
        phone_col = col_map["phone"]
        assert phone_col.masking_strategy == MaskingStrategy.PHONE

        # Credit card mask
        cc_col = col_map["credit_card"]
        assert cc_col.masking_strategy == MaskingStrategy.CREDIT_CARD

        # IP address mask
        ip_col = col_map["ip_address"]
        assert ip_col.masking_strategy == MaskingStrategy.IP_ADDRESS

        # Name mask
        name_col = col_map["display_name"]
        assert name_col.masking_strategy == MaskingStrategy.NAME


def test_audit_config_roundtrips() -> None:
    proj = build_minimal_project()
    proj.database = DatabaseConfig(
        name="testdb",
        audit_enabled=True,
        audit_logged=[AuditLogLevel.DDL, AuditLogLevel.WRITE, AuditLogLevel.ROLE],
    )
    rt = _roundtrip(proj)
    assert rt is not None
    if rt:
        assert rt.database.audit_enabled is True
        assert set(rt.database.audit_logged) == {
            AuditLogLevel.DDL, AuditLogLevel.WRITE, AuditLogLevel.ROLE
        }


def test_roundtripped_project_passes_validation() -> None:
    for builder in [
        build_minimal_project,
        build_cross_schema_project,
        build_clearance_project,
        build_masking_project,
    ]:
        proj = builder()
        rt   = _roundtrip(proj)
        assert rt is not None
        if rt:
            assert SemanticValidator.validate(rt) is True
