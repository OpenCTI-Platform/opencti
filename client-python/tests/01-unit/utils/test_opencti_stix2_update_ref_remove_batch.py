from pycti.utils.opencti_stix2_update import OpenCTIStix2Update


class _RelationEditor:
    def __init__(self):
        self.marking_calls = []
        self.external_reference_calls = []
        self.kill_chain_phase_calls = []
        self.label_calls = []

    def remove_marking_definition(self, id, marking_definition_id):
        self.marking_calls.append((id, marking_definition_id))
        return True

    def remove_external_reference(self, id, external_reference_id):
        self.external_reference_calls.append((id, external_reference_id))
        return True

    def remove_kill_chain_phase(self, id, kill_chain_phase_id):
        self.kill_chain_phase_calls.append((id, kill_chain_phase_id))
        return True

    def remove_label(self, id, label_id=None, label_name=None):
        self.label_calls.append((id, label_id, label_name))
        return True


class _ObjectRefEditor:
    def __init__(self):
        self.calls = []

    def remove_stix_object_or_stix_relationship(
        self, id, stixObjectOrStixRelationshipId
    ):
        self.calls.append((id, stixObjectOrStixRelationshipId))
        return True


class _NestedRefRelationship:
    def __init__(self):
        self.core_object_calls = []
        self.core_relationship_calls = []
        self.sighting_calls = []

    def remove_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.core_object_calls.append((from_id, list(to_ids), relationship_type))
        return True

    def remove_many_to_stix_core_relationship(self, from_id, to_ids, relationship_type):
        self.core_relationship_calls.append((from_id, list(to_ids), relationship_type))
        return True

    def remove_many_to_stix_sighting_relationship(
        self, from_id, to_ids, relationship_type
    ):
        self.sighting_calls.append((from_id, list(to_ids), relationship_type))
        return True


class _Label:
    def __init__(self):
        self.list_calls = []

    def list(self, **kwargs):
        self.list_calls.append(kwargs)
        values = kwargs["filters"]["filters"][0]["values"]
        return [
            {"id": f"label--{value.strip().lower()}", "value": value.strip().lower()}
            for value in values
            if value.strip().lower() != "missing"
        ]


class _OpenCTI:
    def __init__(self, supports_bulk=True, with_bulk=True):
        self._supports_bulk = supports_bulk
        self.stix_domain_object = _RelationEditor()
        self.stix_core_relationship = _RelationEditor()
        self.stix_sighting_relationship = _RelationEditor()
        self.report = _ObjectRefEditor()
        self.label = _Label()
        if with_bulk:
            self.stix_nested_ref_relationship = _NestedRefRelationship()

    def supports_api_feature(self, feature):
        return feature == "BULK_REF_RELATION_DELETE" and self._supports_bulk


def test_remove_object_refs_batches_multiple_refs_in_bounded_chunks():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)
    object_refs = [{"value": f"indicator--{index}"} for index in range(201)]

    updater.remove_object_refs("report", "report--1", object_refs)

    assert opencti.stix_nested_ref_relationship.core_object_calls == [
        ("report--1", [f"indicator--{index}" for index in range(100)], "object"),
        (
            "report--1",
            [f"indicator--{index}" for index in range(100, 200)],
            "object",
        ),
    ]
    assert opencti.report.calls == [("report--1", "indicator--200")]


def test_remove_object_refs_falls_back_without_advertised_bulk_delete():
    opencti = _OpenCTI(supports_bulk=False)
    updater = OpenCTIStix2Update(opencti)

    updater.remove_object_refs(
        "report",
        "report--1",
        [{"value": "indicator--1"}, {"value": "indicator--2"}],
    )

    assert opencti.report.calls == [
        ("report--1", "indicator--1"),
        ("report--1", "indicator--2"),
    ]
    assert opencti.stix_nested_ref_relationship.core_object_calls == []


def test_remove_relation_helpers_use_bulk_delete_for_known_ref_ids():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.remove_object_marking_refs(
        "relationship",
        "relationship--1",
        [{"value": "marking-definition--1"}, {"value": "marking-definition--2"}],
    )
    updater.remove_external_references(
        "relationship",
        "relationship--1",
        [{"id": "external-reference--1"}, {"id": "external-reference--2"}],
    )
    updater.remove_kill_chain_phases(
        "relationship",
        "relationship--1",
        [{"id": "kill-chain-phase--1"}, {"id": "kill-chain-phase--2"}],
    )

    assert opencti.stix_nested_ref_relationship.core_relationship_calls == [
        (
            "relationship--1",
            ["marking-definition--1", "marking-definition--2"],
            "object-marking",
        ),
        (
            "relationship--1",
            ["external-reference--1", "external-reference--2"],
            "external-reference",
        ),
        (
            "relationship--1",
            ["kill-chain-phase--1", "kill-chain-phase--2"],
            "kill-chain-phase",
        ),
    ]
    assert opencti.stix_core_relationship.marking_calls == []
    assert opencti.stix_core_relationship.external_reference_calls == []
    assert opencti.stix_core_relationship.kill_chain_phase_calls == []


def test_remove_labels_prefetches_existing_ids_before_bulk_delete():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.remove_labels(
        "intrusion-set",
        "intrusion-set--1",
        [{"value": " Existing-One "}, {"value": "existing-two"}, {"value": "missing"}],
    )

    assert len(opencti.label.list_calls) == 1
    assert opencti.stix_nested_ref_relationship.core_object_calls == [
        (
            "intrusion-set--1",
            ["label--existing-one", "label--existing-two"],
            "object-label",
        )
    ]
    assert opencti.stix_domain_object.label_calls == []


def test_remove_labels_keeps_name_lookup_fallback_without_bulk_delete():
    opencti = _OpenCTI(supports_bulk=False)
    updater = OpenCTIStix2Update(opencti)

    updater.remove_labels(
        "intrusion-set",
        "intrusion-set--1",
        [{"value": "existing-one"}, {"value": "existing-two"}],
    )

    assert opencti.label.list_calls == []
    assert opencti.stix_domain_object.label_calls == [
        ("intrusion-set--1", None, "existing-one"),
        ("intrusion-set--1", None, "existing-two"),
    ]
