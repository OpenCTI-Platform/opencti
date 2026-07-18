from pycti.utils.opencti_stix2_update import OpenCTIStix2Update


class _RelationAdder:
    def __init__(self):
        self.calls = []

    def add_stix_object_or_stix_relationship(self, id, stixObjectOrStixRelationshipId):
        self.calls.append((id, stixObjectOrStixRelationshipId))
        return True


class _NestedRefRelationship:
    def __init__(self):
        self.calls = []

    def add_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.calls.append((from_id, list(to_ids), relationship_type))
        return True


class _OpenCTI:
    def __init__(self, with_bulk=True):
        self.report = _RelationAdder()
        if with_bulk:
            self.stix_nested_ref_relationship = _NestedRefRelationship()


def test_add_object_refs_batches_multiple_refs_in_bounded_chunks():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)
    object_refs = [{"value": f"indicator--{index}"} for index in range(201)]

    updater.add_object_refs("report", "report--1", object_refs)

    assert opencti.stix_nested_ref_relationship.calls == [
        ("report--1", [f"indicator--{index}" for index in range(100)], "object"),
        ("report--1", [f"indicator--{index}" for index in range(100, 200)], "object"),
    ]
    assert opencti.report.calls == [("report--1", "indicator--200")]


def test_add_object_refs_keeps_single_ref_on_entity_specific_path():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_refs("report", "report--1", ["indicator--1"], version=1)

    assert opencti.report.calls == [("report--1", "indicator--1")]
    assert opencti.stix_nested_ref_relationship.calls == []


def test_add_object_refs_falls_back_to_single_mutations_without_bulk_helper():
    opencti = _OpenCTI(with_bulk=False)
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_refs(
        "report",
        "report--1",
        [{"value": "indicator--1"}, {"value": "indicator--2"}],
    )

    assert opencti.report.calls == [
        ("report--1", "indicator--1"),
        ("report--1", "indicator--2"),
    ]


def test_add_object_refs_ignores_unsupported_entity_types():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_refs(
        "unsupported", "unsupported--1", [{"value": "indicator--1"}]
    )

    assert opencti.report.calls == []
    assert opencti.stix_nested_ref_relationship.calls == []
