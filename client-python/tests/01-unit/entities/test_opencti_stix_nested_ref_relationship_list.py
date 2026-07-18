from pycti.entities.opencti_stix_nested_ref_relationship import (
    StixNestedRefRelationship,
)


class _NoOpLogger:
    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class _PagedClient:
    def __init__(self):
        self.app_logger = _NoOpLogger()
        self.pages = [
            {
                "items": [{"id": "relationship--1"}, {"id": "relationship--2"}],
                "pageInfo": {"endCursor": "0", "hasNextPage": True},
            },
            {
                "items": [{"id": "relationship--3"}],
                "pageInfo": {"endCursor": "1", "hasNextPage": False},
            },
        ]

    def query(self, query, variables):
        after = variables["after"]
        page_index = 0 if after is None else int(after) + 1
        return {"data": {"stixNestedRefRelationships": self.pages[page_index]}}

    def process_multiple(self, page, with_pagination=False):
        return page["items"]


class _CreateClient:
    def __init__(self):
        self.app_logger = _NoOpLogger()
        self.query_calls = []

    def query(self, query, variables):
        self.query_calls.append((query, variables))
        result_field = (
            "relationsDelete" if "relationsDelete" in query else "relationsAdd"
        )
        if "stixCoreRelationshipEdit(id: $id)" in query:
            return {
                "data": {
                    "stixCoreRelationshipEdit": {result_field: {"id": "source--1"}}
                }
            }
        if "stixSightingRelationshipEdit(id: $id)" in query:
            return {
                "data": {
                    "stixSightingRelationshipEdit": {result_field: {"id": "source--1"}}
                }
            }
        return {"data": {"stixCoreObjectEdit": {result_field: {"id": "source--1"}}}}

    @staticmethod
    def process_multiple_fields(data):
        return data


def test_list_get_all_preserves_page_order():
    entity = StixNestedRefRelationship(_PagedClient())

    result = entity.list(getAll=True)

    assert [item["id"] for item in result] == [
        "relationship--1",
        "relationship--2",
        "relationship--3",
    ]


def test_add_many_to_stix_core_object_uses_one_bulk_edit_query():
    client = _CreateClient()
    entity = StixNestedRefRelationship(client)

    result = entity.add_many_to_stix_core_object(
        "observable--1",
        ["observable--2", "observable--3"],
        "resolves-to",
    )

    assert result == {"id": "source--1"}
    assert len(client.query_calls) == 1
    query, variables = client.query_calls[0]
    assert "stixCoreObjectEdit(id: $id)" in query
    assert "relationsAdd(input: $input)" in query
    assert variables["id"] == "observable--1"
    assert variables["input"]["relationship_type"] == "obs_resolves-to"
    assert variables["input"]["toIds"] == ["observable--2", "observable--3"]


def test_add_many_to_stix_core_relationship_uses_one_bulk_edit_query():
    client = _CreateClient()
    entity = StixNestedRefRelationship(client)

    result = entity.add_many_to_stix_core_relationship(
        "relationship--1",
        ["external-reference--1", "external-reference--2"],
        "external-reference",
    )

    assert result == {"id": "source--1"}
    assert len(client.query_calls) == 1
    query, variables = client.query_calls[0]
    assert "stixCoreRelationshipEdit(id: $id)" in query
    assert "relationsAdd(input: $input)" in query
    assert variables["id"] == "relationship--1"
    assert variables["input"]["relationship_type"] == "external-reference"
    assert variables["input"]["toIds"] == [
        "external-reference--1",
        "external-reference--2",
    ]


def test_add_many_to_stix_sighting_relationship_uses_one_bulk_edit_query():
    client = _CreateClient()
    entity = StixNestedRefRelationship(client)

    result = entity.add_many_to_stix_sighting_relationship(
        "sighting--1",
        ["marking-definition--1", "marking-definition--2"],
        "object-marking",
    )

    assert result == {"id": "source--1"}
    assert len(client.query_calls) == 1
    query, variables = client.query_calls[0]
    assert "stixSightingRelationshipEdit(id: $id)" in query
    assert "relationsAdd(input: $input)" in query
    assert variables["id"] == "sighting--1"
    assert variables["input"]["relationship_type"] == "object-marking"
    assert variables["input"]["toIds"] == [
        "marking-definition--1",
        "marking-definition--2",
    ]


def test_remove_many_to_stix_core_object_uses_one_bulk_edit_query():
    client = _CreateClient()
    entity = StixNestedRefRelationship(client)

    result = entity.remove_many_to_stix_core_object(
        "report--1",
        ["indicator--1", "indicator--2"],
        "object",
    )

    assert result == {"id": "source--1"}
    assert len(client.query_calls) == 1
    query, variables = client.query_calls[0]
    assert "stixCoreObjectEdit(id: $id)" in query
    assert "relationsDelete(input: $input)" in query
    assert variables["id"] == "report--1"
    assert variables["input"]["relationship_type"] == "object"
    assert variables["input"]["toIds"] == ["indicator--1", "indicator--2"]


def test_remove_many_to_stix_core_relationship_uses_one_bulk_edit_query():
    client = _CreateClient()
    entity = StixNestedRefRelationship(client)

    result = entity.remove_many_to_stix_core_relationship(
        "relationship--1",
        ["external-reference--1", "external-reference--2"],
        "external-reference",
    )

    assert result == {"id": "source--1"}
    assert len(client.query_calls) == 1
    query, variables = client.query_calls[0]
    assert "stixCoreRelationshipEdit(id: $id)" in query
    assert "relationsDelete(input: $input)" in query
    assert variables["id"] == "relationship--1"
    assert variables["input"]["relationship_type"] == "external-reference"
    assert variables["input"]["toIds"] == [
        "external-reference--1",
        "external-reference--2",
    ]


def test_remove_many_to_stix_sighting_relationship_uses_one_bulk_edit_query():
    client = _CreateClient()
    entity = StixNestedRefRelationship(client)

    result = entity.remove_many_to_stix_sighting_relationship(
        "sighting--1",
        ["marking-definition--1", "marking-definition--2"],
        "object-marking",
    )

    assert result == {"id": "source--1"}
    assert len(client.query_calls) == 1
    query, variables = client.query_calls[0]
    assert "stixSightingRelationshipEdit(id: $id)" in query
    assert "relationsDelete(input: $input)" in query
    assert variables["id"] == "sighting--1"
    assert variables["input"]["relationship_type"] == "object-marking"
    assert variables["input"]["toIds"] == [
        "marking-definition--1",
        "marking-definition--2",
    ]
