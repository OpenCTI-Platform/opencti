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


def _container_root(identifier):
    return {
        "id": f"report--root-{identifier}",
        "type": "report",
        "x_opencti_id": f"root-{identifier}",
        "objects": [
            {
                "id": f"target-{identifier}",
                "standard_id": f"malware--target-{identifier}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
        ],
        "objectsIds": [f"target-{identifier}"],
    }


def _nested_ref_root(identifier):
    return {
        "id": f"indicator--root-{identifier}",
        "type": "indicator",
        "x_opencti_id": f"root-{identifier}",
    }


def _relationship_root(identifier):
    return {
        "id": f"relationship--root-{identifier}",
        "type": "uses",
        "x_opencti_id": f"relationship-root-{identifier}",
        "from": {
            "id": f"source-{identifier}",
            "standard_id": f"malware--source-{identifier}",
            "entity_type": "Malware",
            "parent_types": ["Stix-Domain-Object"],
        },
        "to": {
            "id": f"target-{identifier}",
            "standard_id": f"malware--target-{identifier}",
            "entity_type": "Malware",
            "parent_types": ["Stix-Domain-Object"],
        },
    }


def _emitted_ref_root(identifier):
    return {
        "id": f"indicator--root-{identifier}",
        "type": "indicator",
        "x_opencti_id": f"root-{identifier}",
        "createdBy": {
            "id": f"creator-{identifier}",
            "standard_id": f"identity--creator-{identifier}",
            "entity_type": "Identity",
            "parent_types": ["Stix-Domain-Object"],
        },
        "createdById": f"creator-{identifier}",
        "dataSource": {
            "id": f"data-source-{identifier}",
            "standard_id": f"data-source--{identifier}",
            "entity_type": "Data-Source",
            "parent_types": ["Stix-Domain-Object"],
        },
        "dataSourceId": f"data-source-{identifier}",
        "objectMarking": [
            {
                "id": f"marking-{identifier}",
                "standard_id": f"marking-definition--{identifier}",
                "definition_type": "TLP",
                "definition": "TLP:CLEAR",
                "created": "2017-01-20T00:00:00.000Z",
            }
        ],
        "objectMarkingIds": [f"marking-{identifier}"],
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


def test_export_selected_batches_unique_related_endpoint_access_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "target-1")],
            "root-2": [_relationship("relationship--2", "target-2")],
            "root-3": [_relationship("relationship--3", "target-3")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    access_collection = _CountingAccessCollection()
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
    helper.prepare_id_filters_export = lambda entity_id, access_filter: entity_id
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
    assert access_collection.kwargs == [
        {
            "filters": ["target-target-1", "target-target-2", "target-target-3"],
            "getAll": True,
            "customAttributes": EXPORT_ACCESS_LISTER_ATTRIBUTES,
        }
    ]


def test_export_list_batches_unique_related_endpoint_access_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "target-1")],
            "root-2": [_relationship("relationship--2", "target-2")],
            "root-3": [_relationship("relationship--3", "target-3")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    access_collection = _CountingAccessCollection()
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
    helper.prepare_id_filters_export = lambda entity_id, access_filter: entity_id
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
    assert access_collection.kwargs == [
        {
            "filters": ["target-target-1", "target-target-2", "target-target-3"],
            "getAll": True,
            "customAttributes": EXPORT_ACCESS_LISTER_ATTRIBUTES,
        }
    ]


def test_export_selected_batches_unique_related_endpoint_access_in_bounded_chunks():
    helper = _helper([])
    relationship_collection = _RelationshipCollection(
        {
            f"root-{index}": [
                _relationship(f"relationship--{index}", f"target-{index}")
            ]
            for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
        }
    )
    helper.opencti.stix_core_relationship = relationship_collection
    for index, relationship in enumerate(
        relationship_collection.relationships_by_root.values()
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    access_collection = _CountingAccessCollection()
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
    helper.prepare_id_filters_export = lambda entity_id, access_filter: entity_id
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert access_collection.list_calls == 2
    assert access_collection.kwargs[0]["filters"] == [
        f"target-target-{index}" for index in range(EXPORT_PREFETCH_BATCH_SIZE)
    ]
    assert (
        access_collection.kwargs[1]["filters"]
        == f"target-target-{EXPORT_PREFETCH_BATCH_SIZE}"
    )


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


def test_export_selected_batches_unique_related_object_reads_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "target-1")],
            "root-2": [_relationship("relationship--2", "target-2")],
            "root-3": [_relationship("relationship--3", "target-3")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    helper.opencti.opencti_stix_object_or_stix_relationship = (
        _CountingAccessCollection()
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
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert lister.list_calls == 1
    assert lister.filters == [["target-target-1", "target-target-2", "target-target-3"]]


def test_export_list_batches_unique_related_object_reads_across_roots():
    helper = _helper([])
    helper.opencti.stix_core_relationship = _RelationshipCollection(
        {
            "root-1": [_relationship("relationship--1", "target-1")],
            "root-2": [_relationship("relationship--2", "target-2")],
            "root-3": [_relationship("relationship--3", "target-3")],
        }
    )
    for index, relationship in enumerate(
        helper.opencti.stix_core_relationship.relationships_by_root.values(), start=1
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    helper.opencti.opencti_stix_object_or_stix_relationship = (
        _CountingAccessCollection()
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
    helper.export_entities_list = lambda **kwargs: [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(1, 4)
    ]

    helper.export_list(entity_type="Indicator", mode="full")

    assert lister.list_calls == 1
    assert lister.filters == [["target-target-1", "target-target-2", "target-target-3"]]


def test_export_selected_batches_container_object_reads_across_roots():
    helper = _helper([])
    lister = _CountingRelatedObjectLister(
        {
            f"target-{index}": {
                "id": f"target-{index}",
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
        AssertionError("batchable container objects should not use the reader")
    )
    entities = [_container_root(index) for index in range(1, 4)]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert lister.list_calls == 1
    assert lister.filters == [["target-1", "target-2", "target-3"]]
    assert [item["id"] for item in result["objects"]] == [
        "report--root-1",
        "malware--target-1",
        "report--root-2",
        "malware--target-2",
        "report--root-3",
        "malware--target-3",
    ]


def test_prepare_export_full_does_not_reread_contained_objects_from_object_refs():
    helper = _helper([])
    read_calls = []
    targets_by_id = {
        "target-1": {
            "id": "target-1",
            "standard_id": "malware--target-1",
            "entity_type": "Malware",
            "parent_types": ["Stix-Domain-Object"],
        }
    }
    targets_by_id["malware--target-1"] = targets_by_id["target-1"]

    def read(filters):
        read_calls.append(filters)
        return targets_by_id[filters]

    helper.get_reader = lambda resolve_type: read
    helper.get_lister = lambda resolve_type: None
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

    result = helper.prepare_export(entity=_container_root(1), mode="full")

    assert read_calls == ["target-1"]
    assert [item["id"] for item in result] == ["report--root-1", "malware--target-1"]


def test_prepare_export_full_does_not_reread_already_emitted_reference_objects():
    helper = _helper([])
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
        AssertionError("already-emitted reference objects should not be reread")
    )

    result = helper.prepare_export(entity=_emitted_ref_root(1), mode="full")

    assert [item["id"] for item in result] == [
        "identity--creator-1",
        "data-source--1",
        "marking-definition--1",
        "indicator--root-1",
    ]


def test_export_list_batches_container_object_reads_across_roots():
    helper = _helper([])
    lister = _CountingRelatedObjectLister(
        {
            f"target-{index}": {
                "id": f"target-{index}",
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
        AssertionError("batchable container objects should not use the reader")
    )
    helper.export_entities_list = lambda **kwargs: [
        _container_root(index) for index in range(1, 4)
    ]

    result = helper.export_list(entity_type="Report", mode="full")

    assert lister.list_calls == 1
    assert lister.filters == [["target-1", "target-2", "target-3"]]
    assert [item["id"] for item in result["objects"]] == [
        "report--root-1",
        "malware--target-1",
        "report--root-2",
        "malware--target-2",
        "report--root-3",
        "malware--target-3",
    ]


def test_export_selected_batches_nested_ref_target_reads_across_roots():
    helper = _helper([])
    nested_ref_collection = _NestedRefRelationshipCollection(
        {
            "root-1": [_nested_ref_relationship("nested-ref--1", "root-1", "1")],
            "root-2": [_nested_ref_relationship("nested-ref--2", "root-2", "2")],
            "root-3": [_nested_ref_relationship("nested-ref--3", "root-3", "3")],
        }
    )
    lister = _CountingRelatedObjectLister(
        {
            f"target-{index}": {
                "id": f"target-{index}",
                "standard_id": f"malware--{index}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(1, 4)
        }
    )
    helper.opencti.stix_nested_ref_relationship = nested_ref_collection
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
        AssertionError("batchable nested-ref targets should not use the reader")
    )
    entities = [_nested_ref_root(index) for index in range(1, 4)]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert nested_ref_collection.list_calls == 2
    assert nested_ref_collection.from_id_queries == [
        ["root-1", "root-2", "root-3"],
        ["target-1", "target-2", "target-3"],
    ]
    assert lister.list_calls == 1
    assert lister.filters == [["target-1", "target-2", "target-3"]]
    assert [item["id"] for item in result["objects"]] == [
        "indicator--root-1",
        "malware--1",
        "indicator--root-2",
        "malware--2",
        "indicator--root-3",
        "malware--3",
    ]


def test_export_list_batches_nested_ref_target_reads_across_roots():
    helper = _helper([])
    nested_ref_collection = _NestedRefRelationshipCollection(
        {
            "root-1": [_nested_ref_relationship("nested-ref--1", "root-1", "1")],
            "root-2": [_nested_ref_relationship("nested-ref--2", "root-2", "2")],
            "root-3": [_nested_ref_relationship("nested-ref--3", "root-3", "3")],
        }
    )
    lister = _CountingRelatedObjectLister(
        {
            f"target-{index}": {
                "id": f"target-{index}",
                "standard_id": f"malware--{index}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(1, 4)
        }
    )
    helper.opencti.stix_nested_ref_relationship = nested_ref_collection
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
        AssertionError("batchable nested-ref targets should not use the reader")
    )
    helper.export_entities_list = lambda **kwargs: [
        _nested_ref_root(index) for index in range(1, 4)
    ]

    result = helper.export_list(entity_type="Indicator", mode="full")

    assert nested_ref_collection.list_calls == 2
    assert nested_ref_collection.from_id_queries == [
        ["root-1", "root-2", "root-3"],
        ["target-1", "target-2", "target-3"],
    ]
    assert lister.list_calls == 1
    assert lister.filters == [["target-1", "target-2", "target-3"]]
    assert [item["id"] for item in result["objects"]] == [
        "indicator--root-1",
        "malware--1",
        "indicator--root-2",
        "malware--2",
        "indicator--root-3",
        "malware--3",
    ]


def test_export_selected_batches_relationship_root_endpoint_work_across_roots():
    helper = _helper([])
    nested_ref_collection = _NestedRefRelationshipCollection({})
    access_collection = _CountingAccessCollection()
    lister = _CountingRelatedObjectLister(
        {
            f"{side}-{index}": {
                "id": f"{side}-{index}",
                "standard_id": f"malware--{side}-{index}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(1, 4)
            for side in ("source", "target")
        }
    )
    helper.opencti.stix_nested_ref_relationship = nested_ref_collection
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
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
        AssertionError(
            "batchable relationship-root endpoints should not use the reader"
        )
    )
    entities = [_relationship_root(index) for index in range(1, 4)]

    result = helper.export_selected(entities_list=entities, mode="full")

    assert access_collection.list_calls == 1
    assert access_collection.kwargs[0]["filters"] == [
        "source-1",
        "target-1",
        "source-2",
        "target-2",
        "source-3",
        "target-3",
    ]
    assert nested_ref_collection.list_calls == 2
    assert nested_ref_collection.from_id_queries == [
        ["relationship-root-1", "relationship-root-2", "relationship-root-3"],
        ["source-1", "target-1", "source-2", "target-2", "source-3", "target-3"],
    ]
    assert lister.list_calls == 1
    assert lister.filters == [
        ["source-1", "target-1", "source-2", "target-2", "source-3", "target-3"]
    ]
    assert [item["id"] for item in result["objects"]] == [
        "relationship--root-1",
        "malware--source-1",
        "malware--target-1",
        "relationship--root-2",
        "malware--source-2",
        "malware--target-2",
        "relationship--root-3",
        "malware--source-3",
        "malware--target-3",
    ]


def test_export_list_batches_relationship_root_endpoint_work_across_roots():
    helper = _helper([])
    nested_ref_collection = _NestedRefRelationshipCollection({})
    access_collection = _CountingAccessCollection()
    lister = _CountingRelatedObjectLister(
        {
            f"{side}-{index}": {
                "id": f"{side}-{index}",
                "standard_id": f"malware--{side}-{index}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(1, 4)
            for side in ("source", "target")
        }
    )
    helper.opencti.stix_nested_ref_relationship = nested_ref_collection
    helper.opencti.opencti_stix_object_or_stix_relationship = access_collection
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
        AssertionError(
            "batchable relationship-root endpoints should not use the reader"
        )
    )
    helper.export_entities_list = lambda **kwargs: [
        _relationship_root(index) for index in range(1, 4)
    ]

    result = helper.export_list(entity_type="stix-core-relationship", mode="full")

    assert access_collection.list_calls == 1
    assert access_collection.kwargs[0]["filters"] == [
        "source-1",
        "target-1",
        "source-2",
        "target-2",
        "source-3",
        "target-3",
    ]
    assert nested_ref_collection.list_calls == 2
    assert nested_ref_collection.from_id_queries == [
        ["relationship-root-1", "relationship-root-2", "relationship-root-3"],
        ["source-1", "target-1", "source-2", "target-2", "source-3", "target-3"],
    ]
    assert lister.list_calls == 1
    assert lister.filters == [
        ["source-1", "target-1", "source-2", "target-2", "source-3", "target-3"]
    ]
    assert [item["id"] for item in result["objects"]] == [
        "relationship--root-1",
        "malware--source-1",
        "malware--target-1",
        "relationship--root-2",
        "malware--source-2",
        "malware--target-2",
        "relationship--root-3",
        "malware--source-3",
        "malware--target-3",
    ]


def test_export_selected_batches_unique_related_object_reads_in_bounded_chunks():
    helper = _helper([])
    relationship_collection = _RelationshipCollection(
        {
            f"root-{index}": [
                _relationship(f"relationship--{index}", f"target-{index}")
            ]
            for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
        }
    )
    helper.opencti.stix_core_relationship = relationship_collection
    for index, relationship in enumerate(
        relationship_collection.relationships_by_root.values()
    ):
        relationship[0]["from"]["id"] = f"root-{index}"
        relationship[0]["from"]["standard_id"] = f"indicator--root-{index}"
    helper.opencti.opencti_stix_object_or_stix_relationship = (
        _CountingAccessCollection()
    )
    lister = _CountingRelatedObjectLister(
        {
            f"target-target-{index}": {
                "id": f"target-target-{index}",
                "standard_id": f"malware--target-{index}",
                "entity_type": "Malware",
                "parent_types": ["Stix-Domain-Object"],
            }
            for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
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
    entities = [
        {
            "id": f"indicator--root-{index}",
            "type": "indicator",
            "x_opencti_id": f"root-{index}",
        }
        for index in range(EXPORT_PREFETCH_BATCH_SIZE + 1)
    ]

    helper.export_selected(entities_list=entities, mode="full")

    assert lister.list_calls == 2
    assert lister.filters[0] == [
        f"target-target-{index}" for index in range(EXPORT_PREFETCH_BATCH_SIZE)
    ]
    assert lister.filters[1] == [f"target-target-{EXPORT_PREFETCH_BATCH_SIZE}"]


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


def test_export_selected_simple_batches_nested_ref_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _NestedRefRelationshipCollection(
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

    result = helper.export_selected(entities_list=entities, mode="simple")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.from_id_queries == [["root-1", "root-2", "root-3"]]
    assert [
        item["sample_refs"]
        for item in result["objects"]
        if item["id"].startswith("indicator--root-")
    ] == [
        ["malware--target-1"],
        ["malware--target-2"],
        ["malware--target-3"],
    ]


def test_export_list_simple_batches_nested_ref_relationship_listing_across_roots():
    helper = _helper([])
    relationship_collection = _NestedRefRelationshipCollection(
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

    result = helper.export_list(entity_type="Indicator", mode="simple")

    assert relationship_collection.list_calls == 1
    assert relationship_collection.from_id_queries == [["root-1", "root-2", "root-3"]]
    assert [
        item["sample_refs"]
        for item in result["objects"]
        if item["id"].startswith("indicator--root-")
    ] == [
        ["malware--target-1"],
        ["malware--target-2"],
        ["malware--target-3"],
    ]
