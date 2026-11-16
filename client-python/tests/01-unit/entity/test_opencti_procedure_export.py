# coding: utf-8
"""Procedure export: the links the backend stores once (relationships, kill
chain phases, report containment) are expanded back into the procedure
properties of the exchange format."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2

PROCEDURE_INTERNAL_ID = "proc-internal-id"
PROCEDURE_STANDARD_ID = "x-opencti-procedure--8d1c5a3e-7b52-4f0a-9a4d-3f6a2c1b9e10"
AP1 = "attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7b6e1b8"
VULN = "vulnerability--3ba4b52a-3c26-4dab-8791-e73a2c7bbc78"
IDENTITY = "identity--5a6d1c0e-2b7f-4e83-9d41-6c8b0a7e2f35"
REPORT = "report--c1f4a8d2-6e3b-4b97-8a05-1d2e7f9b3c64"


def _to_stix_payload():
    return {
        "type": "x-opencti-procedure",
        "spec_version": "2.1",
        "id": PROCEDURE_STANDARD_ID,
        "name": "Dump credentials from memory",
        "platforms": ["windows"],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
            {
                "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                "phase_name": "exploitation",
            },
        ],
        "x_observable_refs": [],
        "x_source_refs": [IDENTITY],
        "x_fingerprint": "0123456789abcdef0123456789abcdef",
    }


def _edges(*nodes):
    return {
        "edges": [{"node": node} for node in nodes],
        "pageInfo": {
            "startCursor": None,
            "endCursor": None,
            "hasNextPage": False,
            "hasPreviousPage": False,
            "globalCount": len(nodes),
        },
    }


def _relationship(standard_id):
    return {
        "id": "rel-" + standard_id,
        "to": {"id": "id-" + standard_id, "standard_id": standard_id},
    }


class FakePlatform:
    """Answers the GraphQL queries of the export, by operation name."""

    def __init__(self, stix=None, relationships=None, reports=None):
        self.stix = _to_stix_payload() if stix is None else stix
        self.relationships = (
            {
                "implements-technique": [AP1],
                "exploits": [VULN],
            }
            if relationships is None
            else relationships
        )
        self.reports = [REPORT] if reports is None else reports
        self.calls = []

    def query(self, query, variables=None):
        operation = query.split("query ", 1)[1].split("(", 1)[0].strip()
        self.calls.append((operation, variables))
        if operation == "StixCoreObjectToStix":
            if self.stix is None:
                return {"data": {"stixCoreObject": None}}
            return {"data": {"stixCoreObject": {"toStix": json.dumps(self.stix)}}}
        if operation == "StixCoreRelationships":
            targets = self.relationships.get(variables["relationship_type"], [])
            return {
                "data": {
                    "stixCoreRelationships": _edges(
                        *[_relationship(target) for target in targets]
                    )
                }
            }
        if operation == "Reports":
            return {
                "data": {
                    "reports": _edges(
                        *[
                            {"id": "id-" + report, "standard_id": report}
                            for report in self.reports
                        ]
                    )
                }
            }
        raise AssertionError("Unexpected query " + operation)


def _make_mocks(**platform_kwargs):
    platform = FakePlatform(**platform_kwargs)
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
    client.app_logger = MagicMock()
    client.query = platform.query
    return SimpleNamespace(client=client, platform=platform)


@pytest.fixture
def procedure_api_mocks():
    return _make_mocks()


def test_export_expands_stored_links(procedure_api_mocks):
    stix = procedure_api_mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)
    assert stix["type"] == "x-opencti-procedure"
    assert stix["x_technique_refs"] == [AP1]
    assert stix["x_vulnerability_refs"] == [VULN]
    assert stix["tactics"] == ["execution"]  # lockheed phase excluded
    assert stix["x_source_refs"] == [IDENTITY, REPORT]


def test_export_keeps_other_kill_chain_phases_in_kill_chain_phases_only(
    procedure_api_mocks,
):
    stix = procedure_api_mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)
    assert {
        "kill_chain_name": "lockheed-martin-cyber-kill-chain",
        "phase_name": "exploitation",
    } in stix["kill_chain_phases"]
    assert stix["x_fingerprint"] == "0123456789abcdef0123456789abcdef"


def test_export_queries_links_of_the_procedure(procedure_api_mocks):
    procedure_api_mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)
    calls = dict(
        (variables["relationship_type"], variables)
        for operation, variables in procedure_api_mocks.platform.calls
        if operation == "StixCoreRelationships"
    )
    assert set(calls) == {"implements-technique", "exploits"}
    for variables in calls.values():
        assert variables["fromId"] == PROCEDURE_INTERNAL_ID
    reports_call = [
        variables
        for operation, variables in procedure_api_mocks.platform.calls
        if operation == "Reports"
    ]
    assert len(reports_call) == 1
    assert reports_call[0]["filters"]["filters"] == [
        {"key": "objects", "values": [PROCEDURE_INTERNAL_ID]}
    ]


def test_export_omits_empty_expansions_and_keeps_stored_sources():
    mocks = _make_mocks(
        stix={**_to_stix_payload(), "kill_chain_phases": []},
        relationships={},
        reports=[],
    )
    stix = mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)
    assert "x_technique_refs" not in stix
    assert "x_vulnerability_refs" not in stix
    assert "tactics" not in stix
    assert stix["x_source_refs"] == [IDENTITY]


def test_export_does_not_duplicate_ids():
    mocks = _make_mocks(
        stix={
            **_to_stix_payload(),
            "x_source_refs": [IDENTITY, REPORT],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
            ],
        },
        relationships={"implements-technique": [AP1, AP1]},
    )
    stix = mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)
    assert stix["x_technique_refs"] == [AP1]
    assert stix["tactics"] == ["execution"]
    assert stix["x_source_refs"] == [IDENTITY, REPORT]


def test_export_skips_links_the_user_cannot_read():
    mocks = _make_mocks()
    original_query = mocks.client.query

    def query(query_text, variables=None):
        result = original_query(query_text, variables)
        if "stixCoreRelationships" in result["data"]:
            for edge in result["data"]["stixCoreRelationships"]["edges"]:
                edge["node"]["to"] = None
        return result

    mocks.client.query = query
    stix = mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)
    assert "x_technique_refs" not in stix
    assert "x_vulnerability_refs" not in stix


def test_export_of_unknown_procedure_raises():
    mocks = _make_mocks(stix=None)
    mocks.platform.stix = None
    with pytest.raises(ValueError):
        mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)


def test_generate_export_of_a_procedure_uses_the_expanded_export(
    procedure_api_mocks,
):
    opencti_stix2 = OpenCTIStix2(procedure_api_mocks.client)
    entity = {
        "id": PROCEDURE_INTERNAL_ID,
        "standard_id": PROCEDURE_STANDARD_ID,
        "entity_type": "Procedure",
        "parent_types": ["Basic-Object", "Stix-Object", "Stix-Core-Object"],
        "name": "Dump credentials from memory",
    }

    exported = opencti_stix2.generate_export(entity)

    assert exported["id"] == PROCEDURE_STANDARD_ID
    assert exported["type"] == "x-opencti-procedure"
    assert exported["x_opencti_id"] == PROCEDURE_INTERNAL_ID
    assert exported["x_opencti_type"] == "Procedure"
    assert exported["x_technique_refs"] == [AP1]
    assert exported["x_source_refs"] == [IDENTITY, REPORT]


def test_prepare_export_of_a_procedure_adds_author_and_marking_objects(
    procedure_api_mocks,
):
    tlp_clear = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    original_query = procedure_api_mocks.client.query

    def query(query_text, variables=None):
        if "StixNestedRefRelationships" in query_text:
            return {"data": {"stixNestedRefRelationships": _edges()}}
        return original_query(query_text, variables)

    procedure_api_mocks.client.query = query
    opencti_stix2 = OpenCTIStix2(procedure_api_mocks.client)
    entity = {
        "id": PROCEDURE_INTERNAL_ID,
        "standard_id": PROCEDURE_STANDARD_ID,
        "entity_type": "Procedure",
        "parent_types": [],
        "name": "Dump credentials from memory",
        "createdBy": {
            "id": "author-internal-id",
            "standard_id": IDENTITY,
            "entity_type": "Organization",
            "parent_types": ["Identity"],
            "spec_version": "2.1",
            "identity_class": "organization",
            "name": "Author",
        },
        "createdById": "author-internal-id",
        "objectMarking": [
            {
                "standard_id": tlp_clear,
                "definition_type": "TLP",
                "definition": "TLP:CLEAR",
                "created": "2017-01-20T00:00:00.000Z",
            }
        ],
        "objectMarkingIds": ["marking-internal-id"],
    }

    objects = opencti_stix2.prepare_export(opencti_stix2.generate_export(entity))

    by_id = {stix_object["id"]: stix_object for stix_object in objects}
    assert set(by_id) == {IDENTITY, tlp_clear, PROCEDURE_STANDARD_ID}
    procedure = by_id[PROCEDURE_STANDARD_ID]
    assert procedure["created_by_ref"] == IDENTITY
    assert procedure["object_marking_refs"] == [tlp_clear]
    assert procedure["x_technique_refs"] == [AP1]


ACCESS_FILTER = {
    "mode": "and",
    "filters": [
        {"key": "objectMarking", "operator": "not_eq", "values": ["restricted"]}
    ],
    "filterGroups": [],
}


def test_export_sends_access_filter_with_relationship_and_report_lookups(
    procedure_api_mocks,
):
    procedure_api_mocks.client.procedure.to_stix_export(
        PROCEDURE_INTERNAL_ID, access_filter=ACCESS_FILTER
    )
    calls = procedure_api_mocks.platform.calls
    relationship_calls = [
        variables
        for operation, variables in calls
        if operation == "StixCoreRelationships"
    ]
    assert len(relationship_calls) == 2
    for variables in relationship_calls:
        assert variables["filters"] == ACCESS_FILTER
    report_calls = [
        variables for operation, variables in calls if operation == "Reports"
    ]
    assert len(report_calls) == 1
    assert report_calls[0]["filters"] == {
        "mode": "and",
        "filters": [],
        "filterGroups": [
            {
                "mode": "and",
                "filters": [{"key": "objects", "values": [PROCEDURE_INTERNAL_ID]}],
                "filterGroups": [],
            },
            ACCESS_FILTER,
        ],
    }


def test_generate_export_passes_access_filter_to_the_links(procedure_api_mocks):
    opencti_stix2 = OpenCTIStix2(procedure_api_mocks.client)
    entity = {
        "id": PROCEDURE_INTERNAL_ID,
        "standard_id": PROCEDURE_STANDARD_ID,
        "entity_type": "Procedure",
        "parent_types": [],
        "name": "Dump credentials from memory",
    }

    opencti_stix2.generate_export(entity, access_filter=ACCESS_FILTER)

    link_lookups = [
        variables["filters"]
        for operation, variables in procedure_api_mocks.platform.calls
        if operation == "StixCoreRelationships"
    ]
    assert link_lookups == [ACCESS_FILTER, ACCESS_FILTER]


def test_export_omits_x_source_refs_when_empty():
    payload = _to_stix_payload()
    del payload["x_source_refs"]
    mocks = _make_mocks(stix=payload, reports=[])
    stix = mocks.client.procedure.to_stix_export(PROCEDURE_INTERNAL_ID)
    assert "x_source_refs" not in stix


OBSERVABLE_GREEN = "process--1b0f9f8e-6f0a-4d4e-9b1c-2f3a4b5c6d70"
OBSERVABLE_RED = "process--2c1e8e7d-5e9b-4c3d-8a0b-1e2f3a4b5c60"
COMMAND_RED = "process--3d2f7d6c-4d8a-4b2c-9f1a-0d1e2f3a4b50"


def _nested_ref(relationship_type, standard_id):
    return {
        "id": "nested-" + relationship_type + "-" + standard_id,
        "relationship_type": relationship_type,
        "to": {"id": "id-" + standard_id, "standard_id": standard_id},
    }


ALL_NESTED_REFS = [
    _nested_ref("procedure-observable", OBSERVABLE_GREEN),
    _nested_ref("procedure-observable", OBSERVABLE_RED),
    _nested_ref("procedure-command", COMMAND_RED),
    _nested_ref("procedure-source", IDENTITY),
]
# The TLP:RED observables are excluded by the export access filter
ALLOWED_NESTED_REFS = [ALL_NESTED_REFS[0], ALL_NESTED_REFS[3]]


def _export_with_nested_refs(access_filter):
    payload = _to_stix_payload()
    payload["x_observable_refs"] = [OBSERVABLE_GREEN, OBSERVABLE_RED]
    payload["x_command_ref"] = COMMAND_RED
    mocks = _make_mocks(stix=payload)
    original_query = mocks.client.query

    def query(query_text, variables=None):
        if "StixNestedRefRelationships" in query_text:
            filtered = (variables or {}).get("filters") is not None
            nested_refs = ALLOWED_NESTED_REFS if filtered else ALL_NESTED_REFS
            return {"data": {"stixNestedRefRelationships": _edges(*nested_refs)}}
        return original_query(query_text, variables)

    mocks.client.query = query
    opencti_stix2 = OpenCTIStix2(mocks.client)
    entity = {
        "id": PROCEDURE_INTERNAL_ID,
        "standard_id": PROCEDURE_STANDARD_ID,
        "entity_type": "Procedure",
        "parent_types": [],
        "name": "Dump credentials from memory",
    }
    objects = opencti_stix2.prepare_export(
        opencti_stix2.generate_export(entity, access_filter=access_filter),
        access_filter=access_filter,
    )
    return next(o for o in objects if o["id"] == PROCEDURE_STANDARD_ID)


def test_prepare_export_of_a_procedure_adds_no_legacy_nested_ref_keys():
    procedure = _export_with_nested_refs(access_filter=None)
    for key in (
        "procedure_observable_ref",
        "procedure_command_ref",
        "procedure_source_ref",
        "procedure_observable_refs",
        "procedure_command_refs",
        "procedure_source_refs",
    ):
        assert key not in procedure
    assert procedure["x_observable_refs"] == [OBSERVABLE_GREEN, OBSERVABLE_RED]
    assert procedure["x_command_ref"] == COMMAND_RED
    assert procedure["x_source_refs"] == [IDENTITY, REPORT]


def test_prepare_export_of_a_procedure_removes_refs_excluded_by_the_access_filter():
    procedure = _export_with_nested_refs(access_filter=ACCESS_FILTER)
    assert "procedure_observable_ref" not in procedure
    assert procedure["x_observable_refs"] == [OBSERVABLE_GREEN]
    assert "x_command_ref" not in procedure
    # Report sources come from the filtered report lookup, not from nested refs
    assert procedure["x_source_refs"] == [IDENTITY, REPORT]
