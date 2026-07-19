from pycti.utils.opencti_stix2_update import OpenCTIStix2Update


class _RelationAdder:
    def __init__(self):
        self.calls = []

    def add_marking_definition(self, id, marking_definition_id):
        self.calls.append((id, marking_definition_id))
        return True


class _NestedRefRelationship:
    def __init__(self):
        self.object_calls = []
        self.relationship_calls = []
        self.sighting_calls = []

    def add_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.object_calls.append((from_id, list(to_ids), relationship_type))
        return True

    def add_many_to_stix_core_relationship(self, from_id, to_ids, relationship_type):
        self.relationship_calls.append((from_id, list(to_ids), relationship_type))
        return True

    def add_many_to_stix_sighting_relationship(
        self, from_id, to_ids, relationship_type
    ):
        self.sighting_calls.append((from_id, list(to_ids), relationship_type))
        return True


class _OpenCTI:
    def __init__(self, with_bulk=True, supports_bulk_validation=True):
        self._supports_bulk_validation = supports_bulk_validation
        self.feature_calls = []
        self.stix_domain_object = _RelationAdder()
        self.stix_cyber_observable = _RelationAdder()
        self.stix_core_relationship = _RelationAdder()
        self.stix_sighting_relationship = _RelationAdder()
        if with_bulk:
            self.stix_nested_ref_relationship = _NestedRefRelationship()

    def supports_api_feature(self, feature):
        self.feature_calls.append(feature)
        return (
            feature == "BULK_REF_RELATION_VALIDATION" and self._supports_bulk_validation
        )


def _marking_refs(count):
    return [{"value": f"marking-definition--{index}"} for index in range(count)]


def test_add_object_marking_refs_batches_domain_object_relations_in_bounded_chunks():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_marking_refs("indicator", "indicator--1", _marking_refs(201))

    assert opencti.stix_nested_ref_relationship.object_calls == [
        (
            "indicator--1",
            [f"marking-definition--{index}" for index in range(100)],
            "object-marking",
        ),
        (
            "indicator--1",
            [f"marking-definition--{index}" for index in range(100, 200)],
            "object-marking",
        ),
    ]
    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "marking-definition--200")
    ]


def test_add_object_marking_refs_uses_relationship_bulk_edit_path():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_marking_refs("relationship", "relationship--1", _marking_refs(2))

    assert opencti.stix_nested_ref_relationship.relationship_calls == [
        (
            "relationship--1",
            ["marking-definition--0", "marking-definition--1"],
            "object-marking",
        )
    ]
    assert opencti.stix_core_relationship.calls == []


def test_add_object_marking_refs_uses_sighting_bulk_edit_path():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_marking_refs("sighting", "sighting--1", _marking_refs(2))

    assert opencti.stix_nested_ref_relationship.sighting_calls == [
        (
            "sighting--1",
            ["marking-definition--0", "marking-definition--1"],
            "object-marking",
        )
    ]
    assert opencti.stix_sighting_relationship.calls == []


def test_add_object_marking_refs_keeps_single_ref_on_entity_specific_path():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_marking_refs(
        "indicator", "indicator--1", ["marking-definition--1"], version=1
    )

    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "marking-definition--1")
    ]
    assert opencti.stix_nested_ref_relationship.object_calls == []
    assert opencti.feature_calls == []


def test_add_object_marking_refs_falls_back_to_single_mutations_without_bulk_helper():
    opencti = _OpenCTI(with_bulk=False)
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_marking_refs("indicator", "indicator--1", _marking_refs(2))

    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "marking-definition--0"),
        ("indicator--1", "marking-definition--1"),
    ]
    assert opencti.feature_calls == []


def test_add_object_marking_refs_falls_back_when_platform_does_not_advertise_validation():
    opencti = _OpenCTI(supports_bulk_validation=False)
    updater = OpenCTIStix2Update(opencti)

    updater.add_object_marking_refs("indicator", "indicator--1", _marking_refs(2))

    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "marking-definition--0"),
        ("indicator--1", "marking-definition--1"),
    ]
    assert opencti.stix_nested_ref_relationship.object_calls == []
