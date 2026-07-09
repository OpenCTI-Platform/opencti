from types import SimpleNamespace

from pycti.utils.opencti_stix2 import OpenCTIStix2


class _StaticCollection:
    def __init__(self, items):
        self.items = items

    def list(self, **kwargs):
        return self.items


class _CountingCollection(_StaticCollection):
    def __init__(self, items):
        super().__init__(items)
        self.list_calls = 0

    def list(self, **kwargs):
        self.list_calls += 1
        return super().list(**kwargs)


def _relationship(identifier, target_identifier=None):
    target_identifier = target_identifier or identifier
    return {
        "id": identifier,
        "type": "uses",
        "x_opencti_id": f"internal-{identifier}",
        "from": {
            "id": "root",
            "standard_id": "indicator--root",
            "entity_type": "Indicator",
            "parent_types": ["Stix-Domain-Object"],
        },
        "to": {
            "id": f"target-{target_identifier}",
            "standard_id": f"malware--{target_identifier}",
            "entity_type": "Malware",
            "parent_types": ["Stix-Domain-Object"],
        },
    }


def _helper(relationships):
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.opencti = SimpleNamespace(
        stix_nested_ref_relationship=_StaticCollection([]),
        stix_core_relationship=_StaticCollection(relationships),
        stix_sighting_relationship=_StaticCollection([]),
        opencti_stix_object_or_stix_relationship=_StaticCollection([{}]),
    )
    helper.generate_export = lambda entity: entity
    helper.prepare_id_filters_export = lambda entity_id, access_filter: None
    helper.get_reader = lambda resolve_type: lambda filters: None
    return helper


def test_prepare_export_full_deduplicates_relationship_bundles():
    helper = _helper(
        [
            _relationship("relationship--1"),
            _relationship("relationship--2"),
            _relationship("relationship--1"),
        ]
    )
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }

    result = helper.prepare_export(entity=entity, mode="full")

    assert [item["id"] for item in result] == [
        "indicator--root",
        "relationship--1",
        "relationship--2",
    ]


def test_prepare_export_full_reads_repeated_related_object_once():
    helper = _helper(
        [
            _relationship("relationship--1", "shared"),
            _relationship("relationship--2", "shared"),
            _relationship("relationship--3", "shared"),
        ]
    )
    read_calls = []

    def read(filters):
        read_calls.append(filters)
        return {
            "id": "malware--shared",
            "type": "malware",
            "x_opencti_id": "target-shared",
        }

    helper.get_reader = lambda resolve_type: read
    helper.generate_export = lambda entity: entity.copy()
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }

    result = helper.prepare_export(entity=entity, mode="full")

    assert len(read_calls) == 1
    assert [item["id"] for item in result] == [
        "indicator--root",
        "relationship--1",
        "relationship--2",
        "relationship--3",
        "malware--shared",
    ]


def test_prepare_export_full_checks_repeated_relation_endpoints_once():
    helper = _helper(
        [
            _relationship("relationship--1", "shared"),
            _relationship("relationship--2", "shared"),
            _relationship("relationship--3", "shared"),
        ]
    )
    access_collection = _CountingCollection([{}])
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }

    helper.prepare_export(entity=entity, mode="full")

    assert access_collection.list_calls == 2
