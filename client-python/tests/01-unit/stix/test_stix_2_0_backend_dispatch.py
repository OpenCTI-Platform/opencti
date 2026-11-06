"""Unit tests for the STIX 2.0 backend dispatch of the STIX export.

When the caller opts in with ``stix_version=STIX_VERSION_2_0``, the migrated
entity types are serialized by the GraphQL field
``stixCoreObject(id) { toStix(version: stix_2_0) }`` instead of the legacy
client-side converter. Without the opt-in, the legacy converter is used, so
the existing exports and the enrichment connectors are unchanged.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2
from pycti.utils.opencti_stix2 import _STIX_2_0_REBUILT_KEYS, STIX_VERSION_2_0

MALWARE_STANDARD_ID = "malware--92ddf766-b27c-5159-8f46-27002bba2f04"
MALWARE_INTERNAL_ID = "internal-uuid-malware-1"
MARKING_ID = "marking-definition--33333333-3333-3333-3333-333333333333"
AUTHOR_ID = "identity--44444444-4444-4444-4444-444444444444"
ORGANIZATION_ID = "identity--55555555-5555-5555-5555-555555555555"


def _fake_client():
    return OpenCTIApiClient(
        "http://fake:4000", "fake", ssl_verify=False, perform_health_check=False
    )


@pytest.fixture
def stix_helper():
    """``OpenCTIStix2`` helper whose API sub-clients are mocked."""
    client = _fake_client()
    client.stix_core_object = MagicMock(name="stix_core_object_client")
    client.stix_nested_ref_relationship = MagicMock(
        name="stix_nested_ref_relationship_client"
    )
    client.stix_nested_ref_relationship.list.return_value = []
    client.stix_core_relationship = MagicMock(name="stix_core_relationship_client")
    client.stix_sighting_relationship = MagicMock(
        name="stix_sighting_relationship_client"
    )
    return OpenCTIStix2(client)


def _backend_malware_payload():
    """STIX 2.0 Malware as produced by ``convertMalwareToStix`` (backend)."""
    return {
        "id": MALWARE_STANDARD_ID,
        "type": "malware",
        "spec_version": "2.0",
        "name": "Backend Malware",
        "is_family": False,
        "malware_types": ["trojan"],
        "operating_system_refs": ["software--11111111-1111-1111-1111-111111111111"],
        "sample_refs": ["file--22222222-2222-2222-2222-222222222222"],
        "object_marking_refs": [MARKING_ID],
        "created_by_ref": AUTHOR_ID,
        "labels": ["apt"],
        "x_opencti_id": MALWARE_INTERNAL_ID,
        "x_opencti_granted_refs": [ORGANIZATION_ID],
        "x_opencti_type": "Malware",
        "x_opencti_files": [
            {"name": "sample.bin", "uri": "/storage/get/import/Malware/sample.bin"}
        ],
    }


def _raw_graphql_entity(with_import_files=False):
    """Raw GraphQL Malware, as returned by the reader."""
    entity = {
        "id": MALWARE_INTERNAL_ID,
        "standard_id": MALWARE_STANDARD_ID,
        "entity_type": "Malware",
        "parent_types": ["Stix-Domain-Object"],
        "spec_version": "2.1",
        "name": "Backend Malware",
        "createdBy": None,
        "createdById": None,
        "objectMarking": [],
        "objectMarkingIds": [],
        "objectOrganization": [],
    }
    if with_import_files:
        entity["importFiles"] = [
            {
                "id": "import--file--1",
                "name": "sample.bin",
                "metaData": {"mimetype": "application/octet-stream"},
                "objectMarking": [],
            }
        ]
        entity["importFilesIds"] = ["import--file--1"]
    return entity


def _tlp_amber_marking():
    return {
        "standard_id": MARKING_ID,
        "definition_type": "TLP",
        "definition": "TLP:AMBER",
        "created": "2017-01-20T00:00:00.000Z",
    }


# --- Opt-in -----------------------------------------------------------------


def test_generate_export_without_stix_version_uses_legacy_converter(stix_helper):
    """Default behaviour is unchanged: no backend call, legacy output."""
    result = stix_helper.generate_export(_raw_graphql_entity())

    stix_helper.opencti.stix_core_object.to_stix.assert_not_called()
    assert result["spec_version"] == "2.1"
    assert result["x_opencti_id"] == MALWARE_INTERNAL_ID


def test_prepare_export_without_stix_version_keeps_nested_refs(stix_helper):
    """Legacy entities still get their nested refs from the API."""
    stix_helper.prepare_export(stix_helper.generate_export(_raw_graphql_entity()))

    stix_helper.opencti.stix_nested_ref_relationship.list.assert_called_once()


def test_prepare_export_legacy_entity_with_stored_spec_version_2_0(stix_helper):
    """A stored spec_version "2.0" does not switch the legacy export to 2.0."""
    raw_entity = _raw_graphql_entity()
    raw_entity["spec_version"] = "2.0"
    raw_entity["objectMarking"] = [_tlp_amber_marking()]
    raw_entity["objectMarkingIds"] = [MARKING_ID]

    result = stix_helper.prepare_export(stix_helper.generate_export(raw_entity))

    stix_helper.opencti.stix_nested_ref_relationship.list.assert_called_once()
    markings = [obj for obj in result if obj.get("type") == "marking-definition"]
    assert markings[0]["spec_version"] == "2.1"


def test_generate_export_stix_2_0_non_migrated_type_uses_legacy_converter(
    stix_helper,
):
    """A type not yet migrated keeps the legacy converter, even in 2.0."""
    entity = _raw_graphql_entity()
    entity["entity_type"] = "Tool"

    result = stix_helper.generate_export(entity, stix_version=STIX_VERSION_2_0)

    stix_helper.opencti.stix_core_object.to_stix.assert_not_called()
    assert result["type"] == "tool"


# --- Backend dispatch -------------------------------------------------------


def test_generate_export_stix_2_0_delegates_to_backend(stix_helper):
    """The backend payload is returned, with the raw keys kept."""
    backend_payload = _backend_malware_payload()
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload

    raw_entity = _raw_graphql_entity(with_import_files=True)
    result = stix_helper.generate_export(raw_entity, stix_version=STIX_VERSION_2_0)

    stix_helper.opencti.stix_core_object.to_stix.assert_called_once_with(
        id=MALWARE_INTERNAL_ID, version=STIX_VERSION_2_0
    )
    assert result["id"] == MALWARE_STANDARD_ID
    assert result["spec_version"] == "2.0"
    assert result["operating_system_refs"] == backend_payload["operating_system_refs"]
    # Non-empty raw keys are kept, empty ones are dropped as in the legacy export.
    assert result["importFiles"] == raw_entity["importFiles"]
    assert result["importFilesIds"] == raw_entity["importFilesIds"]
    for empty_key in ("createdBy", "objectMarking", "objectOrganization"):
        assert empty_key not in result, f"{empty_key!r} should be dropped"


@pytest.mark.parametrize("rebuilt_key", _STIX_2_0_REBUILT_KEYS)
def test_generate_export_stix_2_0_drops_keys_rebuilt_by_prepare_export(
    stix_helper, rebuilt_key
):
    """Refs and files are rebuilt by ``prepare_export`` with the legacy rules."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )

    result = stix_helper.generate_export(
        _raw_graphql_entity(), stix_version=STIX_VERSION_2_0
    )

    assert rebuilt_key not in result


def test_generate_export_stix_2_0_raises_when_backend_returns_none(stix_helper):
    """No silent fallback when the backend returns nothing."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = None

    with pytest.raises(ValueError, match="Backend STIX 2.0 conversion"):
        stix_helper.generate_export(
            _raw_graphql_entity(), stix_version=STIX_VERSION_2_0
        )


def test_prepare_export_stix_2_0_skips_nested_ref_enrichment(stix_helper):
    """Without access filter, the backend refs are kept as they are."""
    backend_payload = _backend_malware_payload()
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload
    prepared = stix_helper.generate_export(
        _raw_graphql_entity(), stix_version=STIX_VERSION_2_0
    )

    result = stix_helper.prepare_export(prepared, stix_version=STIX_VERSION_2_0)

    stix_helper.opencti.stix_nested_ref_relationship.list.assert_not_called()
    malware = next(obj for obj in result if obj.get("type") == "malware")
    assert malware["operating_system_refs"] == backend_payload["operating_system_refs"]
    assert malware["sample_refs"] == backend_payload["sample_refs"]


ACCESS_FILTER = {
    "mode": "and",
    "filters": [{"key": "objectMarking", "values": ["green-id"]}],
    "filterGroups": [],
}


def _nested_ref(target_id):
    return {"relationship_type": "sample", "to": {"standard_id": target_id}}


def _mock_nested_refs(stix_helper, all_ids, allowed_ids):
    """Nested refs listed without, then with, the export access filter."""

    def list_nested_refs(**kwargs):
        ids = allowed_ids if kwargs.get("filters") else all_ids
        return [_nested_ref(target_id) for target_id in ids]

    stix_helper.opencti.stix_nested_ref_relationship.list.side_effect = list_nested_refs


def test_prepare_export_stix_2_0_removes_nested_refs_excluded_by_access_filter(
    stix_helper,
):
    """Refs to objects above the export max markings are not exported."""
    backend_payload = _backend_malware_payload()
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload
    operating_system_id = backend_payload["operating_system_refs"][0]
    sample_id = backend_payload["sample_refs"][0]
    _mock_nested_refs(
        stix_helper,
        all_ids=[operating_system_id, sample_id],
        allowed_ids=[operating_system_id],
    )
    prepared = stix_helper.generate_export(
        _raw_graphql_entity(), stix_version=STIX_VERSION_2_0
    )

    result = stix_helper.prepare_export(
        prepared, access_filter=ACCESS_FILTER, stix_version=STIX_VERSION_2_0
    )

    malware = next(obj for obj in result if obj.get("type") == "malware")
    assert malware["operating_system_refs"] == [operating_system_id]
    assert "sample_refs" not in malware
    list_calls = stix_helper.opencti.stix_nested_ref_relationship.list.call_args_list
    assert [call.kwargs.get("filters") for call in list_calls] == [
        None,
        ACCESS_FILTER,
    ]


def test_prepare_export_stix_2_0_keeps_nested_refs_allowed_by_access_filter(
    stix_helper,
):
    """Nothing is removed when the access filter excludes no nested ref."""
    backend_payload = _backend_malware_payload()
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload
    ref_ids = backend_payload["operating_system_refs"] + backend_payload["sample_refs"]
    _mock_nested_refs(stix_helper, all_ids=ref_ids, allowed_ids=ref_ids)
    prepared = stix_helper.generate_export(
        _raw_graphql_entity(), stix_version=STIX_VERSION_2_0
    )

    result = stix_helper.prepare_export(
        prepared, access_filter=ACCESS_FILTER, stix_version=STIX_VERSION_2_0
    )

    malware = next(obj for obj in result if obj.get("type") == "malware")
    assert malware["operating_system_refs"] == backend_payload["operating_system_refs"]
    assert malware["sample_refs"] == backend_payload["sample_refs"]


def test_prepare_export_stix_2_0_marking_definition_is_stix_2_0(stix_helper):
    """Marking definitions attached to a STIX 2.0 entity are STIX 2.0."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )
    raw_entity = _raw_graphql_entity()
    raw_entity["objectMarking"] = [_tlp_amber_marking()]
    raw_entity["objectMarkingIds"] = [MARKING_ID]
    prepared = stix_helper.generate_export(raw_entity, stix_version=STIX_VERSION_2_0)

    result = stix_helper.prepare_export(prepared, stix_version=STIX_VERSION_2_0)

    markings = [obj for obj in result if obj.get("type") == "marking-definition"]
    assert len(markings) == 1
    assert markings[0]["spec_version"] == "2.0"
    malware = next(obj for obj in result if obj.get("type") == "malware")
    assert malware["object_marking_refs"] == [MARKING_ID]


def test_prepare_export_stix_2_0_no_custom_attributes_has_no_dangling_marking(
    stix_helper,
):
    """Without custom attributes, markings are dropped as in the legacy export."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )
    raw_entity = _raw_graphql_entity()
    raw_entity["objectMarking"] = [_tlp_amber_marking()]
    raw_entity["objectMarkingIds"] = [MARKING_ID]
    prepared = stix_helper.generate_export(
        raw_entity, no_custom_attributes=True, stix_version=STIX_VERSION_2_0
    )

    result = stix_helper.prepare_export(
        prepared, no_custom_attributes=True, stix_version=STIX_VERSION_2_0
    )

    assert [obj["type"] for obj in result] == ["malware"]
    assert "object_marking_refs" not in result[0]


def test_prepare_export_stix_2_0_restricted_author_has_no_created_by_ref(
    stix_helper,
):
    """A restricted author is left out, as in the legacy export."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )
    raw_entity = _raw_graphql_entity()
    raw_entity["createdBy"] = {
        "id": "restricted",
        "standard_id": AUTHOR_ID,
        "entity_type": "Organization",
        "name": "Restricted",
        "identity_class": "Restricted",
    }
    raw_entity["createdById"] = "restricted"
    prepared = stix_helper.generate_export(raw_entity, stix_version=STIX_VERSION_2_0)

    result = stix_helper.prepare_export(prepared, stix_version=STIX_VERSION_2_0)

    assert [obj["type"] for obj in result] == ["malware"]
    assert "created_by_ref" not in result[0]


def test_prepare_export_stix_2_0_full_mode(stix_helper):
    """Full mode traverses relations, propagates the version, embeds files."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )
    relationship = {
        "id": "rel-1",
        "from": {"id": MALWARE_INTERNAL_ID},
        "to": {"id": "other-1", "entity_type": "Tool", "parent_types": []},
    }
    stix_helper.opencti.stix_core_relationship.list.return_value = [relationship]
    stix_helper.opencti.stix_sighting_relationship.list.return_value = []
    prepared = stix_helper.generate_export(
        _raw_graphql_entity(with_import_files=True), stix_version=STIX_VERSION_2_0
    )
    # Ref expansion through the readers is out of scope here.
    for ref_key in ("operating_system_refs", "sample_refs"):
        prepared.pop(ref_key)

    with patch.object(
        stix_helper.opencti, "fetch_opencti_file_by_id", return_value="ZmFrZQ=="
    ), patch.object(
        stix_helper,
        "generate_export",
        return_value={"id": "relationship--1", "type": "relationship"},
    ) as generate_export, patch.object(
        stix_helper, "prepare_export", side_effect=lambda **kwargs: [kwargs["entity"]]
    ) as prepare_export, patch.object(
        stix_helper, "get_reader", return_value=lambda **_: None
    ):
        # Call the real method: the patched one only stubs the recursion.
        result = OpenCTIStix2.prepare_export(
            stix_helper, prepared, mode="full", stix_version=STIX_VERSION_2_0
        )

    call_kwargs = stix_helper.opencti.stix_core_relationship.list.call_args.kwargs
    assert call_kwargs["fromOrToId"] == MALWARE_INTERNAL_ID
    generate_export.assert_called_once_with(
        relationship, access_filter=None, stix_version=STIX_VERSION_2_0
    )
    assert prepare_export.call_args.kwargs["stix_version"] == STIX_VERSION_2_0
    stix_helper.opencti.stix_nested_ref_relationship.list.assert_not_called()
    malware = next(obj for obj in result if obj.get("type") == "malware")
    assert malware["x_opencti_files"][0]["name"] == "sample.bin"
    assert malware["x_opencti_files"][0]["data"] == "ZmFrZQ=="


def test_get_stix_bundle_propagates_stix_version(stix_helper):
    """The public entry point passes the version down to the converter."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )
    with patch.object(
        stix_helper,
        "get_reader",
        return_value=lambda **_: _raw_graphql_entity(),
    ):
        bundle = stix_helper.get_stix_bundle_or_object_from_entity_id(
            entity_type="Malware",
            entity_id=MALWARE_INTERNAL_ID,
            stix_version=STIX_VERSION_2_0,
        )

    malware = next(obj for obj in bundle["objects"] if obj.get("type") == "malware")
    assert malware["spec_version"] == "2.0"


# --- StixCoreObject.to_stix -------------------------------------------------


def test_stix_core_object_to_stix_parses_backend_payload():
    client = _fake_client()
    backend_payload = _backend_malware_payload()
    with patch.object(
        client,
        "query",
        return_value={
            "data": {"stixCoreObject": {"toStix": json.dumps(backend_payload)}}
        },
    ) as query:
        result = client.stix_core_object.to_stix(
            id=MALWARE_INTERNAL_ID, version=STIX_VERSION_2_0
        )

    assert result == backend_payload
    assert query.call_args.args[1] == {
        "id": MALWARE_INTERNAL_ID,
        "version": STIX_VERSION_2_0,
    }


def test_stix_core_object_to_stix_returns_none_when_not_found():
    client = _fake_client()
    with patch.object(client, "query", return_value={"data": {"stixCoreObject": None}}):
        assert client.stix_core_object.to_stix(id=MALWARE_INTERNAL_ID) is None


def test_stix_core_object_to_stix_raises_on_invalid_json():
    client = _fake_client()
    with patch.object(
        client,
        "query",
        return_value={"data": {"stixCoreObject": {"toStix": "{not-valid-json"}}},
    ):
        with pytest.raises(json.JSONDecodeError):
            client.stix_core_object.to_stix(id=MALWARE_INTERNAL_ID)
