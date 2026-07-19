from pycti.utils.opencti_stix2_update import OpenCTIStix2Update


class _Label:
    def __init__(self, existing=None, fail_list=False):
        self.existing = {} if existing is None else dict(existing)
        self.fail_list = fail_list
        self.list_calls = []
        self.create_calls = []

    def list(self, filters, getAll=True):
        self.list_calls.append((filters, getAll))
        if self.fail_list:
            raise RuntimeError("prefetch failed")
        values = filters["filters"][0]["values"]
        return [
            self.existing[value.lower().strip()]
            for value in values
            if value.lower().strip() in self.existing
        ]

    def create(self, value):
        self.create_calls.append(value)
        label_data = {"id": f"label--created-{len(self.create_calls)}", "value": value}
        self.existing[value.lower().strip()] = label_data
        return label_data


class _RelationAdder:
    def __init__(self):
        self.calls = []

    def add_label(self, id, label_name=None, label_id=None):
        self.calls.append((id, label_name, label_id))
        return True


class _NestedRefRelationship:
    def __init__(self):
        self.object_calls = []
        self.relationship_calls = []

    def add_many_to_stix_core_object(self, from_id, to_ids, relationship_type):
        self.object_calls.append((from_id, list(to_ids), relationship_type))
        return True

    def add_many_to_stix_core_relationship(self, from_id, to_ids, relationship_type):
        self.relationship_calls.append((from_id, list(to_ids), relationship_type))
        return True


class _OpenCTI:
    def __init__(self, existing=None, fail_list=False, with_bulk=True):
        self.label = _Label(existing=existing, fail_list=fail_list)
        self.stix_domain_object = _RelationAdder()
        self.stix_cyber_observable = _RelationAdder()
        self.stix_core_relationship = _RelationAdder()
        if with_bulk:
            self.stix_nested_ref_relationship = _NestedRefRelationship()


def _labels(count):
    return [{"value": f"label-{index}"} for index in range(count)]


def _existing_labels(count):
    return {
        f"label-{index}": {"id": f"label--{index}", "value": f"label-{index}"}
        for index in range(count)
    }


def test_add_labels_prefetches_existing_labels_and_batches_relations():
    opencti = _OpenCTI(existing=_existing_labels(201))
    updater = OpenCTIStix2Update(opencti)

    updater.add_labels("indicator", "indicator--1", _labels(201))

    assert len(opencti.label.list_calls) == 1
    assert opencti.label.create_calls == []
    assert opencti.stix_nested_ref_relationship.object_calls == [
        (
            "indicator--1",
            [f"label--{index}" for index in range(100)],
            "object-label",
        ),
        (
            "indicator--1",
            [f"label--{index}" for index in range(100, 200)],
            "object-label",
        ),
    ]
    assert opencti.stix_domain_object.calls == [("indicator--1", None, "label--200")]


def test_add_labels_reuses_normalized_prefetch_matches_and_creates_only_misses():
    opencti = _OpenCTI(existing={"known": {"id": "label--known", "value": "Known"}})
    updater = OpenCTIStix2Update(opencti)

    updater.add_labels(
        "indicator",
        "indicator--1",
        [{"value": " known "}, {"value": "missing"}, {"value": "MISSING"}],
    )

    assert opencti.label.create_calls == ["missing"]
    assert opencti.stix_nested_ref_relationship.object_calls == [
        (
            "indicator--1",
            ["label--known", "label--created-1", "label--created-1"],
            "object-label",
        )
    ]


def test_add_labels_uses_relationship_bulk_edit_path():
    opencti = _OpenCTI(existing=_existing_labels(2))
    updater = OpenCTIStix2Update(opencti)

    updater.add_labels("relationship", "relationship--1", _labels(2))

    assert opencti.stix_nested_ref_relationship.relationship_calls == [
        ("relationship--1", ["label--0", "label--1"], "object-label")
    ]
    assert opencti.stix_core_relationship.calls == []


def test_add_labels_keeps_single_label_on_existing_entity_helper_path():
    opencti = _OpenCTI(existing=_existing_labels(1))
    updater = OpenCTIStix2Update(opencti)

    updater.add_labels("indicator", "indicator--1", [{"value": "label-0"}])

    assert opencti.label.list_calls == []
    assert opencti.stix_domain_object.calls == [("indicator--1", "label-0", None)]
    assert opencti.stix_nested_ref_relationship.object_calls == []


def test_add_labels_falls_back_to_existing_entity_helper_when_prefetch_fails():
    opencti = _OpenCTI(existing=_existing_labels(2), fail_list=True)
    updater = OpenCTIStix2Update(opencti)

    updater.add_labels("indicator", "indicator--1", _labels(2))

    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "label-0", None),
        ("indicator--1", "label-1", None),
    ]
    assert opencti.stix_nested_ref_relationship.object_calls == []


def test_add_labels_uses_label_ids_when_bulk_helper_is_unavailable():
    opencti = _OpenCTI(existing=_existing_labels(2), with_bulk=False)
    updater = OpenCTIStix2Update(opencti)

    updater.add_labels("indicator", "indicator--1", _labels(2))

    assert opencti.stix_domain_object.calls == [
        ("indicator--1", None, "label--0"),
        ("indicator--1", None, "label--1"),
    ]
