from types import SimpleNamespace

from pycti.utils.opencti_stix2 import (
    EXPORT_ACCESS_LISTER_ATTRIBUTES,
    EXPORT_PREFETCH_BATCH_SIZE,
    OpenCTIStix2,
)


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


class _RelationshipCollection:
    def __init__(self, relationships_by_root):
        self.relationships_by_root = relationships_by_root
        self.list_calls = 0
        self.from_or_to_ids = []

    def list(self, **kwargs):
        self.list_calls += 1
        from_or_to_ids = kwargs["fromOrToId"]
        self.from_or_to_ids.append(from_or_to_ids)
        if isinstance(from_or_to_ids, str):
            from_or_to_ids = [from_or_to_ids]
        relationships = []
        seen_relationship_ids = set()
        for from_or_to_id in from_or_to_ids:
            for relationship in self.relationships_by_root.get(from_or_to_id, []):
                if relationship["id"] not in seen_relationship_ids:
                    seen_relationship_ids.add(relationship["id"])
                    relationships.append(relationship)
        return relationships


class _FilteredRelationshipCollection:
    def __init__(self, relationships_by_root):
        self.relationships_by_root = relationships_by_root
        self.list_calls = 0
        self.filters = []

    def list(self, **kwargs):
        self.list_calls += 1
        filters = kwargs["filters"]
        self.filters.append(filters)
        from_or_to_ids = filters["filters"][0]["values"]
        relationships = []
        seen_relationship_ids = set()
        for from_or_to_id in from_or_to_ids:
            for relationship in self.relationships_by_root.get(from_or_to_id, []):
                if relationship["id"] not in seen_relationship_ids:
                    seen_relationship_ids.add(relationship["id"])
                    relationships.append(relationship)
        return relationships


class _NestedRefRelationshipCollection:
    def __init__(self, relationships_by_root):
        self.relationships_by_root = relationships_by_root
        self.list_calls = 0
        self.from_id_queries = []

    def list(self, **kwargs):
        self.list_calls += 1
        if kwargs.get("filters") is not None:
            from_ids = kwargs["filters"]["filters"][0]["values"]
        else:
            from_ids = kwargs["fromId"]
        if isinstance(from_ids, str):
            from_ids = [from_ids]
        self.from_id_queries.append(from_ids)
        relationships = []
        seen_relationship_ids = set()
        for from_id in from_ids:
            for relationship in self.relationships_by_root.get(from_id, []):
                if relationship["id"] not in seen_relationship_ids:
                    seen_relationship_ids.add(relationship["id"])
                    relationships.append(relationship)
        return relationships


class _CountingRelatedObjectLister:
    def __init__(self, targets_by_id):
        self.targets_by_id = targets_by_id
        self.list_calls = 0
        self.filters = []

    def list(self, **kwargs):
        self.list_calls += 1
        self.filters.append(kwargs["filters"])
        return [self.targets_by_id[target_id] for target_id in kwargs["filters"]]


class _CountingAccessCollection:
    def __init__(self):
        self.list_calls = 0
        self.kwargs = []

    def list(self, **kwargs):
        self.list_calls += 1
        self.kwargs.append(kwargs)
        entity_ids = kwargs["filters"]
        if isinstance(entity_ids, str):
            entity_ids = [entity_ids]
        return [{"id": entity_id} for entity_id in entity_ids]


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


def _nested_ref_relationship(identifier, from_identifier, target_identifier):
    return {
        "id": identifier,
        "relationship_type": "sample",
        "from": {
            "id": from_identifier,
            "standard_id": f"indicator--{from_identifier}",
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
    helper.get_lister = lambda resolve_type: None
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


def test_prepare_export_full_checks_only_unseen_repeated_relation_endpoints_once():
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

    assert access_collection.list_calls == 1


def test_prepare_export_full_batches_unique_relation_endpoint_access_checks():
    helper = _helper(
        [
            _relationship("relationship--1", "target-1"),
            _relationship("relationship--2", "target-2"),
            _relationship("relationship--3", "target-3"),
        ]
    )
    access_collection = _CountingAccessCollection()
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
    helper.prepare_id_filters_export = lambda entity_id, access_filter: entity_id
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }

    helper.prepare_export(entity=entity, mode="full")

    assert access_collection.list_calls == 1
    assert access_collection.kwargs == [
        {
            "filters": ["target-target-1", "target-target-2", "target-target-3"],
            "getAll": True,
            "customAttributes": EXPORT_ACCESS_LISTER_ATTRIBUTES,
        }
    ]


def test_prepare_export_full_batches_unique_related_object_reads_by_type():
    helper = _helper(
        [
            _relationship("relationship--1", "target-1"),
            _relationship("relationship--2", "target-2"),
            _relationship("relationship--3", "target-3"),
        ]
    )
    lister = _CountingRelatedObjectLister(
        {
            f"target-target-{index}": {
                "id": f"target-target-{index}",
                "standard_id": f"malware--target-{index}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(1, 4)
        }
    )
    helper.get_lister = lambda resolve_type: lister.list
    helper.prepare_id_filters_export = lambda entity_id, access_filter: entity_id
    helper.generate_export = lambda entity: (
        {
            "id": entity["standard_id"],
            "type": entity["entity_type"].lower(),
            "x_opencti_id": entity["id"],
        }
        if "standard_id" in entity
        else entity.copy()
    )
    helper.get_reader = lambda resolve_type: lambda filters: (_ for _ in ()).throw(
        AssertionError("batchable related objects should not use the reader")
    )
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }

    result = helper.prepare_export(entity=entity, mode="full")

    assert lister.list_calls == 1
    assert lister.filters == [["target-target-1", "target-target-2", "target-target-3"]]
    assert [item["id"] for item in result] == [
        "indicator--root",
        "relationship--1",
        "relationship--2",
        "relationship--3",
        "malware--target-1",
        "malware--target-2",
        "malware--target-3",
    ]


def test_prepare_export_full_batches_nested_refs_for_relationships_and_related_objects():
    helper = _helper(
        [
            _relationship("relationship--1", "target-1"),
            _relationship("relationship--2", "target-2"),
            _relationship("relationship--3", "target-3"),
        ]
    )
    nested_ref_collection = _NestedRefRelationshipCollection(
        {
            "target-target-1": [
                _nested_ref_relationship(
                    "nested-ref--target-1", "target-target-1", "sample-1"
                )
            ]
        }
    )
    helper.opencti.stix_nested_ref_relationship = nested_ref_collection
    lister = _CountingRelatedObjectLister(
        {
            f"target-target-{index}": {
                "id": f"target-target-{index}",
                "standard_id": f"malware--target-{index}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(1, 4)
        }
    )
    helper.get_lister = lambda resolve_type: lister.list
    helper.prepare_id_filters_export = lambda entity_id, access_filter: entity_id
    helper.generate_export = lambda entity: (
        {
            "id": entity["standard_id"],
            "type": entity["entity_type"].lower(),
            "x_opencti_id": entity["id"],
        }
        if "standard_id" in entity
        else entity.copy()
    )
    helper.get_reader = lambda resolve_type: lambda filters: (_ for _ in ()).throw(
        AssertionError("batchable related objects should not use the reader")
    )
    entity = {
        "id": "indicator--root",
        "type": "indicator",
        "x_opencti_id": "root",
    }

    result = helper.prepare_export(entity=entity, mode="full")
    target_objects = {
        item["id"]: item for item in result if item["id"].startswith("malware--")
    }

    assert nested_ref_collection.list_calls == 2
    assert nested_ref_collection.from_id_queries == [
        ["root"],
        [
            "internal-relationship--1",
            "internal-relationship--2",
            "internal-relationship--3",
            "target-target-1",
            "target-target-2",
            "target-target-3",
        ],
    ]
    assert target_objects["malware--target-1"]["sample_refs"] == ["malware--sample-1"]


def test_export_selected_reuses_related_endpoint_access_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "shared")],
            "root-2": [_relationship("relationship--2", "shared")],
            "root-3": [_relationship("relationship--3", "shared")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    access_collection = _CountingCollection([{}])
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert access_collection.list_calls == 1


def test_export_list_reuses_related_endpoint_access_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "shared")],
            "root-2": [_relationship("relationship--2", "shared")],
            "root-3": [_relationship("relationship--3", "shared")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    access_collection = _CountingCollection([{}])
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
    helper.export_entities_list = lambda **kwargs: [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    helper.export_list(entity_type="Indicator", mode="full")

    assert access_collection.list_calls == 1


def test_export_selected_reuses_related_object_reads_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "shared")],
            "root-2": [_relationship("relationship--2", "shared")],
            "root-3": [_relationship("relationship--3", "shared")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
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
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert len(read_calls) == 1


def test_export_list_reuses_related_object_reads_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "shared")],
            "root-2": [_relationship("relationship--2", "shared")],
            "root-3": [_relationship("relationship--3", "shared")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
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
    helper.export_entities_list = lambda **kwargs: [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    helper.export_list(entity_type="Indicator", mode="full")

    assert len(read_calls) == 1


def test_export_selected_batches_core_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "target-1")],
            "root-2": [_relationship("relationship--2", "target-2")],
            "root-3": [_relationship("relationship--3", "target-3")],
        }
    )
    helper.opencti.stix_core_relationship = relationship_collection
    for index, relationship in enumerate(
        relationship_collection.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.from_or_to_ids == [["root-1", "root-2", "root-3"]]
    assert [
        item["id"] for item in result["objects"] if item["type"] == "relationship"
    ] == [
        "relationship--1",
        "relationship--2",
        "relationship--3",
    ]


def test_export_list_batches_core_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "target-1")],
            "root-2": [_relationship("relationship--2", "target-2")],
            "root-3": [_relationship("relationship--3", "target-3")],
        }
    )
    helper.opencti.stix_core_relationship = relationship_collection
    for index, relationship in enumerate(
        relationship_collection.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    helper.export_entities_list = lambda **kwargs: [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    result = helper.export_list(entity_type="Indicator", mode="full")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.from_or_to_ids == [["root-1", "root-2", "root-3"]]
    assert [
        item["id"] for item in result["objects"] if item["type"] == "relationship"
    ] == [
        "relationship--1",
        "relationship--2",
        "relationship--3",
    ]


def test_export_selected_batch_core_relationships_keep_shared_root_relationships_usable():
    helper = _helper([])
    relationship = _relationship("relationship--1", "root-2")
    relationship["to"]["id"] = "root-2"
    relationship["to"]["standard_id"] = "indicator--root-2"
    relationship["to"]["entity_type"] = "Indicator"
    relationship_collection = _RelationshipCollection(
        {"root-1": [relationship], "root-2": [relationship]}
    )
    helper.opencti.stix_core_relationship = relationship_collection
    relationship["from"]["id"] = "root-1"
    relationship["from"]["standard_id"] = "indicator--root-1"
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 3)
    ]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 1
    assert [item["id"] for item in result["objects"]] == [
        "indicator--root-1",
        "relationship--1",
        "indicator--root-2",
    ]


def test_export_selected_batches_core_relationship_listing_in_bounded_chunks():
    helper = _helper([])
    relationship_collection = _RelationshipCollection({})
    helper.opencti.stix_core_relationship = relationship_collection
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 2
    assert len(relationship_collection.from_or_to_ids[0]) == EXPORT_PREFETCH_BATCH_SIZE
    assert relationship_collection.from_or_to_ids[1] == [
        f"root-{EXPORT_PREFETCH_BATCH_SIZE}"
    ]


def test_export_selected_batches_sighting_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _FilteredRelationshipCollection(
        {
            "root-1": [_relationship("sighting--1", "target-1")],
            "root-2": [_relationship("sighting--2", "target-2")],
            "root-3": [_relationship("sighting--3", "target-3")],
        }
    )
    helper.opencti.stix_sighting_relationship = relationship_collection
    for index, relationship in enumerate(
        relationship_collection.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.filters == [
        {
            "mode": "and",
            "filters": [
                {"key": "fromOrToId", "values": ["root-1", "root-2", "root-3"]}
            ],
            "filterGroups": [],
        }
    ]
    assert [
        item["id"] for item in result["objects"] if item["id"].startswith("sighting--")
    ] == [
        "sighting--1",
        "sighting--2",
        "sighting--3",
    ]


def test_export_list_batches_sighting_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _FilteredRelationshipCollection(
        {
            "root-1": [_relationship("sighting--1", "target-1")],
            "root-2": [_relationship("sighting--2", "target-2")],
            "root-3": [_relationship("sighting--3", "target-3")],
        }
    )
    helper.opencti.stix_sighting_relationship = relationship_collection
    for index, relationship in enumerate(
        relationship_collection.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    helper.export_entities_list = lambda **kwargs: [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    result = helper.export_list(entity_type="Indicator", mode="full")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.filters == [
        {
            "mode": "and",
            "filters": [
                {"key": "fromOrToId", "values": ["root-1", "root-2", "root-3"]}
            ],
            "filterGroups": [],
        }
    ]
    assert [
        item["id"] for item in result["objects"] if item["id"].startswith("sighting--")
    ] == [
        "sighting--1",
        "sighting--2",
        "sighting--3",
    ]


def test_export_selected_batch_sighting_relationships_keep_shared_root_relationships_usable():
    helper = _helper([])
    relationship = _relationship("sighting--1", "root-2")
    relationship["to"]["id"] = "root-2"
    relationship["to"]["standard_id"] = "indicator--root-2"
    relationship["to"]["entity_type"] = "Indicator"
    relationship_collection = _FilteredRelationshipCollection(
        {"root-1": [relationship], "root-2": [relationship]}
    )
    helper.opencti.stix_sighting_relationship = relationship_collection
    relationship["from"]["id"] = "root-1"
    relationship["from"]["standard_id"] = "indicator--root-1"
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 3)
    ]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 1
    assert [item["id"] for item in result["objects"]] == [
        "indicator--root-1",
        "sighting--1",
        "indicator--root-2",
    ]


def test_export_selected_batches_sighting_relationship_listing_in_bounded_chunks():
    helper = _helper([])
    relationship_collection = _FilteredRelationshipCollection({})
    helper.opencti.stix_sighting_relationship = relationship_collection
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 2
    assert (
        len(relationship_collection.filters[0]["filters"][0]["values"])
        == EXPORT_PREFETCH_BATCH_SIZE
    )
    assert relationship_collection.filters[1]["filters"][0]["values"] == [
        f"root-{EXPORT_PREFETCH_BATCH_SIZE}"
    ]


def test_export_selected_batches_nested_ref_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _FilteredRelationshipCollection(
        {
            "root-1": [_nested_ref_relationship("nested-ref--1", "root-1", "target-1")],
            "root-2": [_nested_ref_relationship("nested-ref--2", "root-2", "target-2")],
            "root-3": [_nested_ref_relationship("nested-ref--3", "root-3", "target-3")],
        }
    )
    helper.opencti.stix_nested_ref_relationship = relationship_collection
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.filters == [
        {
            "mode": "and",
            "filters": [{"key": "fromId", "values": ["root-1", "root-2", "root-3"]}],
            "filterGroups": [],
        }
    ]
    assert [
        item["sample_refs"]
        for item in result["objects"]
        if item["id"].startswith("indicator--root-")
    ] == [
        ["malware--target-1"],
        ["malware--target-2"],
        ["malware--target-3"],
    ]


def test_export_list_batches_nested_ref_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _FilteredRelationshipCollection(
        {
            "root-1": [_nested_ref_relationship("nested-ref--1", "root-1", "target-1")],
            "root-2": [_nested_ref_relationship("nested-ref--2", "root-2", "target-2")],
            "root-3": [_nested_ref_relationship("nested-ref--3", "root-3", "target-3")],
        }
    )
    helper.opencti.stix_nested_ref_relationship = relationship_collection
    helper.export_entities_list = lambda **kwargs: [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    result = helper.export_list(entity_type="Indicator", mode="full")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.filters == [
        {
            "mode": "and",
            "filters": [{"key": "fromId", "values": ["root-1", "root-2", "root-3"]}],
            "filterGroups": [],
        }
    ]
    assert [
        item["sample_refs"]
        for item in result["objects"]
        if item["id"].startswith("indicator--root-")
    ] == [
        ["malware--target-1"],
        ["malware--target-2"],
        ["malware--target-3"],
    ]


def test_export_selected_batch_nested_ref_relationships_apply_only_to_source_roots():
    helper = _helper([])
    relationship = _nested_ref_relationship("nested-ref--1", "root-1", "root-2")
    relationship["to"]["id"] = "root-2"
    relationship["to"]["standard_id"] = "indicator--root-2"
    relationship["to"]["entity_type"] = "Indicator"
    relationship_collection = _FilteredRelationshipCollection(
        {"root-1": [relationship]}
    )
    helper.opencti.stix_nested_ref_relationship = relationship_collection
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 3)
    ]

    result = helper.export_selected(entities_list=entities, mode="full")
    root_objects = {
        item["id"]: item
        for item in result["objects"]
        if item["id"].startswith("indicator--root-")
    }

    assert root_objects["indicator--root-1"]["sample_refs"] == ["indicator--root-2"]
    assert "sample_refs" not in root_objects["indicator--root-2"]


def test_export_selected_batches_nested_ref_relationship_listing_in_bounded_chunks():
    helper = _helper([])
    relationship_collection = _FilteredRelationshipCollection({})
    helper.opencti.stix_nested_ref_relationship = relationship_collection
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert relationship_collection.list_calls == 2
    assert (
        len(relationship_collection.filters[0]["filters"][0]["values"])
        == EXPORT_PREFETCH_BATCH_SIZE
    )
    assert relationship_collection.filters[1]["filters"][0]["values"] == [
        f"root-{EXPORT_PREFETCH_BATCH_SIZE}"
    ]
