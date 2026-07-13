from types import SimpleNamespace

import pytest

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _StaticCollection:
    def list(self, **kwargs):
        return []


def _helper():
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = SimpleNamespace(stix_nested_ref_relationship=_StaticCollection())
    return helper


def _entity(root_type):
    return {
        "id": f"{root_type}--root",
        "type": root_type,
        "x_opencti_id": "root",
        "objects": [
            {
                "id": "malware",
                "standard_id": "malware--1",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            },
            {
                "id": "note",
                "standard_id": "note--1",
                "entity_type": "Note",
                "parent_types": ["Stix-Domain-Object"],
            },
            {
                "id": "opinion",
                "standard_id": "opinion--1",
                "entity_type": "Opinion",
                "parent_types": ["Stix-Domain-Object"],
            },
            {
                "id": "relationship",
                "standard_id": "relationship--1",
                "entity_type": "Relationship",
                "parent_types": ["Stix-Core-Relationship", "stix-ref-relationship"],
            },
        ],
        "objectsIds": ["malware", "note", "opinion", "relationship"],
    }


@pytest.mark.parametrize(
    ("root_type", "expected_refs"),
    [
        ("report", ["malware--1"]),
        ("note", ["malware--1"]),
        ("opinion", ["malware--1", "note--1"]),
        ("observed-data", ["malware--1", "note--1", "opinion--1"]),
        ("x-opencti-task", ["malware--1", "note--1", "opinion--1"]),
        ("indicator", []),
    ],
)
def test_prepare_export_preserves_container_object_ref_policy(root_type, expected_refs):
    result = _helper().prepare_export(_entity(root_type), mode="simple")

    assert result[0]["object_refs"] == expected_refs
