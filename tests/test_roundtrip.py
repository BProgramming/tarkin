"""
Round-trip serialization tests.

These tests verify that serialize(deserialize(serialize(project))) == project
for all fixture projects, covering the full YAML → model → YAML → model cycle.

No database connection required.
"""
from __future__ import annotations

import pytest
from io import StringIO

from tarkin.model import (
    GovernanceProject, MaskingStrategy,
    FullMaskConfig, PartialMaskConfig, HashMaskConfig,
    EmailMaskConfig, PhoneMaskConfig, CreditCardMaskConfig,
    IpAddressMaskConfig, NameMaskConfig, PartialMaskVisibleSide,
    HashAlgorithm,
)
from tarkin.serialize import Serializer
from tarkin.yaml import YamlLoader

from .fixtures import (
    build_minimal_project,
    build_cross_schema_project,
    build_clearance_project,
    build_masking_project,
)


# =====================================================
# HELPERS
# =====================================================

def _roundtrip(project: GovernanceProject) -> GovernanceProject:
    """Serialize then deserialize a project."""
    yaml_str = Serializer.to_yaml_string(project)
    result   = YamlLoader.loads(yaml_str)
    assert result is not None
    return result


def _roundtrip_stable(project: GovernanceProject) -> None:
    """Assert that two serialize cycles produce identical YAML."""
    first  = Serializer.to_yaml_string(project)
    second = Serializer.to_yaml_string(_roundtrip(project))
    assert first == second, (
        "YAML output changed after roundtrip. "
        "This indicates non-determinism in serialization."
    )


# =====================================================
# BASIC ROUNDTRIP
# =====================================================

class TestRoundtrip:

    def test_minimal_project_roundtrips(self) -> None:
        proj     = build_minimal_project()
        restored = _roundtrip(proj)
        assert restored.database.name == proj.database.name
        assert len(restored.schemas)  == len(proj.schemas)
        assert len(restored.roles)    == len(proj.roles)

    def test_cross_schema_project_roundtrips(self) -> None:
        proj     = build_cross_schema_project()
        restored = _roundtrip(proj)
        assert len(restored.schemas) == 2
        sales_schema = next(s for s in restored.schemas if s.name == "sales")
        orders_table = next(t for t in sales_schema.tables if t.name == "orders")
        assert len(orders_table.foreign_keys) == 1
        fk = orders_table.foreign_keys[0]
        assert fk.referenced_schema == "public"
        assert fk.referenced_table  == "users"
        assert fk.referenced_column == "id"

    def test_clearance_project_roundtrips(self) -> None:
        proj     = build_clearance_project()
        restored = _roundtrip(proj)
        clinical = next(s for s in restored.schemas if s.name == "clinical")
        patients = next(t for t in clinical.tables if t.name == "patients")
        ssn_col  = next(c for c in patients.columns if c.name == "ssn")
        assert ssn_col.clearance  == 2
        assert ssn_col.sensitive  is True
        phi_role = next(r for r in restored.roles if r.name == "phi_reader")
        assert phi_role.clearance             == 2
        assert phi_role.can_access_sensitive  is True

    def test_masking_project_roundtrips(self) -> None:
        proj     = build_masking_project()
        restored = _roundtrip(proj)
        schema   = restored.schemas[0]
        table    = next(t for t in schema.tables if t.name == "contacts")
        col_map  = {c.name: c for c in table.columns}

        # Full mask
        full_col = col_map["full_name"]
        assert full_col.masking_strategy == MaskingStrategy.FULL
        assert isinstance(full_col.mask_config, FullMaskConfig)
        assert full_col.mask_config.mask_char == "*"

        # Partial mask
        partial_col = col_map["partial_code"]
        assert partial_col.masking_strategy == MaskingStrategy.PARTIAL
        assert isinstance(partial_col.mask_config, PartialMaskConfig)
        assert partial_col.mask_config.visible_length == 4
        assert partial_col.mask_config.visible_side   == PartialMaskVisibleSide.RIGHT

        # Email
        email_col = col_map["email"]
        assert email_col.masking_strategy == MaskingStrategy.EMAIL
        assert isinstance(email_col.mask_config, EmailMaskConfig)

        # Phone
        phone_col = col_map["phone"]
        assert phone_col.masking_strategy == MaskingStrategy.PHONE
        assert isinstance(phone_col.mask_config, PhoneMaskConfig)
        assert phone_col.mask_config.visible_digits == 4

        # Credit card
        cc_col = col_map["credit_card"]
        assert cc_col.masking_strategy == MaskingStrategy.CREDIT_CARD
        assert isinstance(cc_col.mask_config, CreditCardMaskConfig)

        # IP address
        ip_col = col_map["ip_address"]
        assert ip_col.masking_strategy == MaskingStrategy.IP_ADDRESS
        assert isinstance(ip_col.mask_config, IpAddressMaskConfig)
        assert ip_col.mask_config.visible_octets == 2

        # Name
        name_col = col_map["display_name"]
        assert name_col.masking_strategy == MaskingStrategy.NAME
        assert isinstance(name_col.mask_config, NameMaskConfig)

        # Hash algorithm roundtrips
        xxhash_col = col_map["xxhash_value"]
        assert xxhash_col.masking_strategy == MaskingStrategy.HASH
        assert isinstance(xxhash_col.mask_config, HashMaskConfig)
        assert xxhash_col.mask_config.algorithm == HashAlgorithm.XXHASH

        sha256_col = col_map["sha256_value"]
        assert sha256_col.masking_strategy == MaskingStrategy.HASH
        assert isinstance(sha256_col.mask_config, HashMaskConfig)
        assert sha256_col.mask_config.algorithm == HashAlgorithm.SHA256

        sha512_col = col_map["sha512_value"]
        assert sha512_col.masking_strategy == MaskingStrategy.HASH
        assert isinstance(sha512_col.mask_config, HashMaskConfig)
        assert sha512_col.mask_config.algorithm == HashAlgorithm.SHA512

        hmac256_col = col_map["hmac256_value"]
        assert hmac256_col.masking_strategy == MaskingStrategy.HASH
        assert isinstance(hmac256_col.mask_config, HashMaskConfig)
        assert hmac256_col.mask_config.algorithm == HashAlgorithm.HMAC256


# =====================================================
# SERIALIZATION STABILITY
# =====================================================

class TestSerializationStability:

    def test_minimal_project_yaml_stable(self) -> None:
        _roundtrip_stable(build_minimal_project())

    def test_cross_schema_project_yaml_stable(self) -> None:
        _roundtrip_stable(build_cross_schema_project())

    def test_clearance_project_yaml_stable(self) -> None:
        _roundtrip_stable(build_clearance_project())

    def test_masking_project_yaml_stable(self) -> None:
        _roundtrip_stable(build_masking_project())


# =====================================================
# FIELD PRESERVATION
# =====================================================

class TestFieldPreservation:

    def test_database_config_preserved(self) -> None:
        proj = build_minimal_project()
        proj.database.name           = "mydb"
        proj.database.host           = "db.example.com"
        proj.database.port           = 5433
        proj.database.audit_enabled  = True
        proj.database.owner          = "dbowner"
        restored = _roundtrip(proj)
        assert restored.database.name          == "mydb"
        assert restored.database.host          == "db.example.com"
        assert restored.database.port          == 5433
        assert restored.database.audit_enabled is True
        assert restored.database.owner         == "dbowner"

    def test_column_flags_preserved(self) -> None:
        from tarkin.model import ColumnConfig, TableConfig, SchemaConfig, IndexConfig
        from .fixtures import make_database, make_role

        col = ColumnConfig(
            name="value", type="text",
            nullable=False, unique=True, immutable=True,
            versioned=True, sensitive=True, clearance=1,
        )
        id_col = ColumnConfig(name="id", type="bigint", nullable=False)
        idx    = IndexConfig(name="pk_id", columns=["id"], primary_key=True, unique=True)
        table  = TableConfig(name="items", columns=[id_col, col], indexes=[idx])
        schema = SchemaConfig(name="public", tables=[table])
        role   = make_role(clearance=1, can_access_sensitive=True)

        proj     = GovernanceProject(database=make_database(), schemas=[schema], roles=[role])
        restored = _roundtrip(proj)
        items    = restored.schemas[0].tables[0]
        v_col    = next(c for c in items.columns if c.name == "value")
        assert v_col.nullable   is False
        assert v_col.unique     is True
        assert v_col.immutable  is True
        assert v_col.versioned  is True
        assert v_col.sensitive  is True
        assert v_col.clearance  == 1

    def test_role_permissions_preserved(self) -> None:
        proj = build_minimal_project()
        proj.roles[0].can_login            = True
        proj.roles[0].can_write            = True
        proj.roles[0].can_access_sensitive = True
        proj.roles[0].on[0].usage          = True
        proj.roles[0].on[0].create         = True
        restored = _roundtrip(proj)
        r = restored.roles[0]
        assert r.can_login            is True
        assert r.can_write            is True
        assert r.can_access_sensitive is True
        assert r.on[0].usage          is True
        assert r.on[0].create         is True

    def test_index_fields_preserved(self) -> None:
        from tarkin.model import IndexConfig, TableConfig, SchemaConfig, ColumnConfig
        from .fixtures import make_database, make_role

        col = ColumnConfig(name="id", type="bigint")
        idx = IndexConfig(
            name="my_idx",
            columns=["id"],
            index_type="gin",
            unique=True,
            primary_key=True,
            partial_filter="id > 0",
        )
        table  = TableConfig(name="items", columns=[col], indexes=[idx])
        schema = SchemaConfig(name="public", tables=[table])
        proj   = GovernanceProject(database=make_database(), schemas=[schema], roles=[make_role()])
        restored = _roundtrip(proj)
        r_idx = restored.schemas[0].tables[0].indexes[0]
        assert r_idx.name           == "my_idx"
        assert r_idx.index_type     == "gin"
        assert r_idx.unique         is True
        assert r_idx.primary_key    is True
        assert r_idx.partial_filter == "id > 0"

    def test_schema_list_fields_preserved(self) -> None:
        from tarkin.model import SchemaConfig, TableConfig, ColumnConfig, IndexConfig
        from .fixtures import make_database, make_role, make_column, make_index

        schema = SchemaConfig(
            name="public",
            tables=[make_table()],
            views=["v_users"],
            sequences=["user_id_seq"],
            functions=["fn_get_user"],
            types=["user_status"],
        )
        proj     = GovernanceProject(database=make_database(), schemas=[schema], roles=[make_role()])
        restored = _roundtrip(proj)
        rs = restored.schemas[0]
        assert "v_users"     in rs.views
        assert "user_id_seq" in rs.sequences
        assert "fn_get_user" in rs.functions
        assert "user_status" in rs.types


def make_table():  # type: ignore[return]
    from .fixtures import make_table as _make_table
    return _make_table()
