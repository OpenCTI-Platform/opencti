from pycti.utils.opencti_stix2_update import (
    EXTERNAL_REFERENCE_PREFETCH_BATCH_SIZE,
    OpenCTIStix2Update,
)


class _ExternalReference:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return {"id": f"external-reference--{len(self.calls) - 1}"}


class _PrefetchingExternalReference:
    def __init__(self):
        self.list_filters = []
        self.create_calls = []

    @staticmethod
    def generate_id(url=None, source_name=None, external_id=None):
        if url is not None:
            return f"external-reference--{url}"
        return f"external-reference--{source_name}|{external_id}"

    def list(self, **kwargs):
        ids = kwargs["filters"]["filters"][0]["values"]
        self.list_filters.append(ids)
        return [
            {
                "id": f"internal--{standard_id}",
                "standard_id": standard_id,
                "source_name": (
                    "source-"
                    + standard_id.removeprefix("external-reference--").rsplit("/", 1)[1]
                ),
                "url": standard_id.removeprefix("external-reference--"),
                "external_id": None,
                "description": None,
            }
            for standard_id in ids
        ]

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        standard_id = self.generate_id(
            kwargs.get("url"), kwargs.get("source_name"), kwargs.get("external_id")
        )
        return {"id": f"internal--{standard_id}"}


class _RelationAdder:
    def __init__(self):
        self.calls = []

    def add_external_reference(self, id, external_reference_id):
        self.calls.append((id, external_reference_id))
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
    def __init__(self, with_bulk=True):
        self.external_reference = _ExternalReference()
        self.stix_domain_object = _RelationAdder()
        self.stix_cyber_observable = _RelationAdder()
        self.stix_core_relationship = _RelationAdder()
        if with_bulk:
            self.stix_nested_ref_relationship = _NestedRefRelationship()


class _PrefetchOpenCTI(_OpenCTI):
    def __init__(self):
        super().__init__()
        self.external_reference = _PrefetchingExternalReference()


def _external_references(count):
    return [
        {
            "value": {
                "source_name": f"source-{index}",
                "url": f"https://example.test/{index}",
            }
        }
        for index in range(count)
    ]


def test_add_external_references_batches_domain_object_relations_in_bounded_chunks():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_external_references(
        "indicator", "indicator--1", _external_references(201)
    )

    assert len(opencti.external_reference.calls) == 201
    assert opencti.stix_nested_ref_relationship.object_calls == [
        (
            "indicator--1",
            [f"external-reference--{index}" for index in range(100)],
            "external-reference",
        ),
        (
            "indicator--1",
            [f"external-reference--{index}" for index in range(100, 200)],
            "external-reference",
        ),
    ]
    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "external-reference--200")
    ]


def test_add_external_references_uses_relationship_bulk_edit_path():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_external_references(
        "relationship", "relationship--1", _external_references(2)
    )

    assert opencti.stix_nested_ref_relationship.relationship_calls == [
        (
            "relationship--1",
            ["external-reference--0", "external-reference--1"],
            "external-reference",
        )
    ]
    assert opencti.stix_core_relationship.calls == []


def test_add_external_references_falls_back_to_single_mutations_without_bulk_helper():
    opencti = _OpenCTI(with_bulk=False)
    updater = OpenCTIStix2Update(opencti)

    updater.add_external_references(
        "indicator", "indicator--1", _external_references(2)
    )

    assert opencti.stix_domain_object.calls == [
        ("indicator--1", "external-reference--0"),
        ("indicator--1", "external-reference--1"),
    ]


def test_add_external_references_keeps_invalid_values_skipped():
    opencti = _OpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_external_references(
        "indicator",
        "indicator--1",
        [
            {"value": {"source_name": "missing-url"}},
            {"value": {"url": "https://example.test/missing-source"}},
        ],
    )

    assert opencti.external_reference.calls == []
    assert opencti.stix_domain_object.calls == []
    assert opencti.stix_nested_ref_relationship.object_calls == []


def test_add_external_references_prefetches_existing_refs_in_bounded_chunks():
    opencti = _PrefetchOpenCTI()
    updater = OpenCTIStix2Update(opencti)

    updater.add_external_references(
        "indicator",
        "indicator--1",
        _external_references(EXTERNAL_REFERENCE_PREFETCH_BATCH_SIZE + 1),
    )

    assert opencti.external_reference.list_filters[0] == [
        f"external-reference--https://example.test/{index}"
        for index in range(EXTERNAL_REFERENCE_PREFETCH_BATCH_SIZE)
    ]
    assert opencti.external_reference.list_filters[1] == [
        f"external-reference--https://example.test/{EXTERNAL_REFERENCE_PREFETCH_BATCH_SIZE}"
    ]
    assert opencti.external_reference.create_calls == []


def test_add_external_references_keeps_changed_metadata_on_per_item_create():
    opencti = _PrefetchOpenCTI()
    updater = OpenCTIStix2Update(opencti)
    external_references = _external_references(2)
    for external_reference in external_references:
        external_reference["value"]["description"] = "changed"

    updater.add_external_references("indicator", "indicator--1", external_references)

    assert [
        call["description"] for call in opencti.external_reference.create_calls
    ] == ["changed", "changed"]


def test_add_external_references_falls_back_to_per_item_create_when_prefetch_fails():
    opencti = _PrefetchOpenCTI()
    updater = OpenCTIStix2Update(opencti)
    opencti.external_reference.list = lambda **_kwargs: (_ for _ in ()).throw(
        RuntimeError("prefetch failed")
    )

    updater.add_external_references(
        "indicator", "indicator--1", _external_references(2)
    )

    assert [call["url"] for call in opencti.external_reference.create_calls] == [
        "https://example.test/0",
        "https://example.test/1",
    ]
