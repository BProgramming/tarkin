"""
Serialize → YAML string → YamlLoader round-trip tests.
"""
from __future__ import annotations

from tarkin.model import GovernanceProject
from tarkin.serialize import Serializer
from tarkin.yaml import YamlLoader
from tarkin.validate import SemanticValidator
from tests.fixtures import (
    build_minimal_project, build_cross_schema_project, build_clearance_project,
)


def _roundtrip(project: GovernanceProject) -> GovernanceProject | None:
    yaml_str = Serializer.to_yaml_string(project)
    reloaded = YamlLoader.loads(yaml_str)
    return reloaded


def test_minimal_project_roundtrips() -> None:
    proj = build_minimal_project()
    rt = _roundtrip(proj)
    assert rt is not None

    if rt:
        assert rt.database.name == proj.database.name
        assert len(rt.schemas) == len(proj.schemas)
        assert rt.schemas[0].name == proj.schemas[0].name
        assert rt.schemas[0].tables[0].name == proj.schemas[0].tables[0].name
        assert rt.roles[0].name == proj.roles[0].name
        assert rt.users[0].username == proj.users[0].username


def test_cross_schema_project_roundtrips() -> None:
    proj = build_cross_schema_project()
    rt = _roundtrip(proj)
    assert rt is not None

    if rt:
        assert len(rt.schemas) == len(proj.schemas)
        sales = next(s for s in rt.schemas if s.name == "sales")
        fk = sales.tables[0].foreign_keys[0]
        assert fk.referenced_schema == "public"
        assert fk.referenced_table == "users"


def test_clearance_project_roundtrips() -> None:
    proj = build_clearance_project()
    rt = _roundtrip(proj)
    assert rt is not None

    if rt:
        clinical = rt.schemas[0]
        ssn_col = next(c for c in clinical.tables[0].columns if c.name == "ssn")
        assert ssn_col.clearance == 2
        assert ssn_col.sensitive is True
        assert ssn_col.encrypted is True


def test_roundtripped_project_passes_validation() -> None:
    for builder in [build_minimal_project, build_cross_schema_project, build_clearance_project]:
        proj = builder()
        rt = _roundtrip(proj)
        assert rt is not None
        if rt:
            assert SemanticValidator.validate(rt) is True
