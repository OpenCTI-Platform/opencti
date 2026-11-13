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
from pycti.utils.opencti_stix2 import (
    _STIX_2_0_BACKEND_ENTITY_TYPES,
    _STIX_2_0_REBUILT_KEYS,
    STIX_VERSION_2_0,
)

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
    entity["entity_type"] = "Language"

    result = stix_helper.generate_export(entity, stix_version=STIX_VERSION_2_0)

    stix_helper.opencti.stix_core_object.to_stix.assert_not_called()
    assert result["type"] == "language"


@pytest.mark.parametrize("entity_type", sorted(_STIX_2_0_BACKEND_ENTITY_TYPES))
def test_stix_2_0_backend_entity_types_are_exportable_types(stix_helper, entity_type):
    """Every migrated type is an OpenCTI entity type the export can read.

    A misspelled type (e.g. ``Security-Platform`` for ``SecurityPlatform``)
    would silently keep the legacy converter.
    """
    reader = stix_helper.get_reader(entity_type)

    assert reader in stix_helper.get_readers().values()


@pytest.mark.parametrize(
    "entity_type",
    # The backend has no STIX 2.0 converter for them: `toStix` raises an error.
    ["Language", "Security-Coverage", "Security-Coverage-Result"],
)
def test_stix_2_0_backend_entity_types_exclude_types_without_converter(
    entity_type,
):
    """The SDOs without a backend STIX 2.0 converter keep the legacy one."""
    assert entity_type not in _STIX_2_0_BACKEND_ENTITY_TYPES


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
    # Both lists are complete: a truncated unfiltered list would miss
    # excluded targets beyond its first page.
    assert all(call.kwargs.get("getAll") for call in list_calls)


def test_prepare_export_stix_2_0_access_filter_ignores_non_string_refs(stix_helper):
    """Custom fields ending with `_ref(s)` but holding other values are kept."""
    backend_payload = _backend_malware_payload()
    sample_id = backend_payload["sample_refs"][0]
    backend_payload["x_opencti_cf_source_ref"] = ["source-a", "source-b"]
    backend_payload["x_opencti_cf_links_refs"] = [{"url": "https://example.com"}]
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload
    _mock_nested_refs(stix_helper, all_ids=[sample_id], allowed_ids=[])
    prepared = stix_helper.generate_export(
        _raw_graphql_entity(), stix_version=STIX_VERSION_2_0
    )

    result = stix_helper.prepare_export(
        prepared, access_filter=ACCESS_FILTER, stix_version=STIX_VERSION_2_0
    )

    malware = next(obj for obj in result if obj.get("type") == "malware")
    assert "sample_refs" not in malware
    assert malware["x_opencti_cf_source_ref"] == ["source-a", "source-b"]
    assert malware["x_opencti_cf_links_refs"] == [{"url": "https://example.com"}]


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


def _raw_external_reference(with_file=False):
    external_reference = {
        "source_name": "mitre-attack",
        "description": None,
        "url": "https://example.com/report",
        "hash": None,
        "external_id": "S0001",
        "importFiles": [],
    }
    if with_file:
        external_reference["importFiles"] = [
            {
                "id": "import/External-Reference/report.pdf",
                "name": "report.pdf",
                "metaData": {"mimetype": "application/pdf", "version": None},
            }
        ]
    return external_reference


def test_generate_export_stix_2_0_embeds_external_reference_files(stix_helper):
    """Files attached to external references are embedded, as in legacy."""
    backend_payload = _backend_malware_payload()
    backend_payload["external_references"] = [
        {
            "source_name": "mitre-attack",
            "url": "https://example.com/report",
            "external_id": "S0001",
        }
    ]
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload
    raw_entity = _raw_graphql_entity()
    raw_entity["externalReferences"] = [_raw_external_reference(with_file=True)]

    with patch.object(
        stix_helper.opencti, "fetch_opencti_file_by_id", return_value="ZmFrZQ=="
    ):
        result = stix_helper.generate_export(raw_entity, stix_version=STIX_VERSION_2_0)

    assert result["external_references"] == [
        {
            "source_name": "mitre-attack",
            "url": "https://example.com/report",
            "external_id": "S0001",
            "x_opencti_files": [
                {
                    "name": "report.pdf",
                    "data": "ZmFrZQ==",
                    "mime_type": "application/pdf",
                    "version": None,
                }
            ],
        }
    ]


def _file_marking(definition):
    return {
        "id": f"{definition}-id",
        "standard_id": f"marking-definition--{definition}",
        "definition_type": "TLP",
        "definition": f"TLP:{definition.upper()}",
        "created": "2017-01-20T00:00:00.000Z",
    }


def test_stix_2_0_external_reference_files_follow_export_access_filter(
    stix_helper,
):
    """External reference files above the export markings are not embedded.

    The kept file carries its markings, added to the bundle in STIX 2.0.
    """
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )
    stix_helper.opencti.stix_nested_ref_relationship.list.return_value = []
    external_reference = _raw_external_reference()
    external_reference["importFiles"] = [
        {
            "id": f"import/External-Reference/{name}",
            "name": name,
            "metaData": {"mimetype": "text/plain", "version": None},
            "objectMarking": [_file_marking(definition)],
        }
        for name, definition in (("green.txt", "green"), ("red.txt", "red"))
    ]
    raw_entity = _raw_graphql_entity()
    raw_entity["externalReferences"] = [external_reference]
    access_filter = {
        "mode": "and",
        "filters": [
            {
                "key": "objectMarking",
                "mode": "and",
                "operator": "not_eq",
                "values": ["red-id"],
            }
        ],
        "filterGroups": [],
    }

    with patch.object(
        stix_helper.opencti, "fetch_opencti_file_by_id", return_value="ZmFrZQ=="
    ):
        prepared = stix_helper.generate_export(
            raw_entity, access_filter=access_filter, stix_version=STIX_VERSION_2_0
        )
        result = stix_helper.prepare_export(
            prepared, access_filter=access_filter, stix_version=STIX_VERSION_2_0
        )

    malware = next(obj for obj in result if obj.get("type") == "malware")
    files = malware["external_references"][0]["x_opencti_files"]
    assert [file["name"] for file in files] == ["green.txt"]
    assert files[0]["object_marking_refs"] == ["marking-definition--green"]
    file_marking = next(
        obj for obj in result if obj.get("id") == "marking-definition--green"
    )
    assert file_marking["spec_version"] == "2.0"
    assert not any(obj.get("id") == "marking-definition--red" for obj in result)


def test_generate_export_stix_2_0_no_custom_attributes_drops_legacy_keys(
    stix_helper,
):
    """Without custom attributes, the keys omitted by legacy are omitted too."""
    backend_payload = _backend_malware_payload()
    backend_payload["kill_chain_phases"] = [
        {
            "kill_chain_name": "mitre-attack",
            "phase_name": "execution",
            "x_opencti_order": 1,
        }
    ]
    backend_payload["external_references"] = [{"source_name": "mitre-attack"}]
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload
    raw_entity = _raw_graphql_entity()
    raw_entity["externalReferences"] = [_raw_external_reference()]

    result = stix_helper.generate_export(
        raw_entity, no_custom_attributes=True, stix_version=STIX_VERSION_2_0
    )

    assert "kill_chain_phases" not in result
    assert "external_references" not in result


def test_generate_export_stix_2_0_without_external_references(stix_helper):
    """No raw external reference: no `external_references` key."""
    backend_payload = _backend_malware_payload()
    backend_payload["external_references"] = []
    stix_helper.opencti.stix_core_object.to_stix.return_value = backend_payload

    result = stix_helper.generate_export(
        _raw_graphql_entity(), stix_version=STIX_VERSION_2_0
    )

    assert "external_references" not in result


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


@pytest.mark.parametrize("stix_version", [None, STIX_VERSION_2_0])
def test_prepare_export_full_mode_skips_non_string_refs(stix_helper, stix_version):
    """List-valued custom fields ending with `_ref(s)` are not resolved."""
    sample_id = "file--22222222-2222-2222-2222-222222222222"
    stix_helper.opencti.stix_core_object.to_stix.return_value = (
        _backend_malware_payload()
    )
    stix_helper.opencti.stix_core_relationship.list.return_value = []
    stix_helper.opencti.stix_sighting_relationship.list.return_value = []
    prepared = stix_helper.generate_export(
        _raw_graphql_entity(), stix_version=stix_version
    )
    prepared.pop("operating_system_refs", None)
    prepared["sample_refs"] = [sample_id]
    prepared["x_opencti_cf_source_ref"] = ["source-a", "source-b"]
    prepared["x_opencti_cf_links_refs"] = [{"url": "https://example.com"}]
    reader = MagicMock(return_value=None)

    with patch.object(stix_helper, "get_reader", return_value=reader), patch.object(
        stix_helper, "prepare_id_filters_export", side_effect=lambda id, _: id
    ):
        result = stix_helper.prepare_export(
            prepared, mode="full", stix_version=stix_version
        )

    assert [call.kwargs["filters"] for call in reader.call_args_list] == [sample_id]
    malware = next(obj for obj in result if obj.get("type") == "malware")
    assert malware["x_opencti_cf_source_ref"] == ["source-a", "source-b"]


# --- Containers and data source ---------------------------------------------

REPORT_STANDARD_ID = "report--66666666-6666-6666-6666-666666666666"
INTRUSION_SET_ID = "intrusion-set--77777777-7777-7777-7777-777777777777"
NOTE_ID = "note--88888888-8888-8888-8888-888888888888"
DATA_COMPONENT_ID = "x-mitre-data-component--99999999-9999-9999-9999-999999999999"
DATA_SOURCE_ID = "x-mitre-data-source--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def _contained_object(object_id, standard_id, entity_type, parent_types):
    return {
        "id": object_id,
        "standard_id": standard_id,
        "entity_type": entity_type,
        "parent_types": parent_types,
    }


def test_prepare_export_stix_2_0_container_rebuilds_object_refs(stix_helper):
    """``object_refs`` follows the legacy filtering of each container type."""
    stix_helper.opencti.stix_core_object.to_stix.return_value = {
        "id": REPORT_STANDARD_ID,
        "type": "report",
        "spec_version": "2.0",
        "name": "Backend Report",
        # The backend keeps the Note, the legacy export filters it out.
        "object_refs": [INTRUSION_SET_ID, NOTE_ID],
        "x_opencti_id": "internal-report",
        "x_opencti_type": "Report",
    }
    contained_objects = [
        _contained_object(
            "internal-intrusion-set",
            INTRUSION_SET_ID,
            "Intrusion-Set",
            ["Stix-Domain-Object"],
        ),
        _contained_object("internal-note", NOTE_ID, "Note", ["Stix-Domain-Object"]),
        _contained_object(
            "internal-ref",
            "relationship--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "object",
            ["basic-relationship", "stix-ref-relationship"],
        ),
    ]
    raw_report = {
        **_raw_graphql_entity(),
        "id": "internal-report",
        "standard_id": REPORT_STANDARD_ID,
        "entity_type": "Report",
        "objects": contained_objects,
        "objectsIds": [item["id"] for item in contained_objects],
    }

    prepared = stix_helper.generate_export(raw_report, stix_version=STIX_VERSION_2_0)
    assert prepared["objects"] == contained_objects
    result = stix_helper.prepare_export(prepared, stix_version=STIX_VERSION_2_0)

    report = next(obj for obj in result if obj["type"] == "report")
    assert report["object_refs"] == [INTRUSION_SET_ID]
    assert "objects" not in report


def test_prepare_export_stix_2_0_data_component_embeds_data_source(stix_helper):
    """The Data-Source is added to the bundle, as in the legacy export."""
    backend_payloads = {
        "internal-data-component": {
            "id": DATA_COMPONENT_ID,
            "type": "x-mitre-data-component",
            "spec_version": "2.0",
            "name": "Backend Data Component",
            "x_mitre_data_source_ref": DATA_SOURCE_ID,
            "x_opencti_id": "internal-data-component",
            "x_opencti_type": "Data-Component",
        },
        "internal-data-source": {
            "id": DATA_SOURCE_ID,
            "type": "x-mitre-data-source",
            "spec_version": "2.0",
            "name": "Backend Data Source",
            "x_opencti_id": "internal-data-source",
            "x_opencti_type": "Data-Source",
        },
    }

    def to_stix(id, version):
        return dict(backend_payloads[id])

    stix_helper.opencti.stix_core_object.to_stix.side_effect = to_stix
    raw_data_component = {
        **_raw_graphql_entity(),
        "id": "internal-data-component",
        "standard_id": "data-component--99999999-9999-9999-9999-999999999999",
        "entity_type": "Data-Component",
        "dataSource": {
            "id": "internal-data-source",
            "standard_id": "data-source--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "entity_type": "Data-Source",
            "parent_types": ["Stix-Domain-Object"],
        },
        "dataSourceId": "internal-data-source",
    }

    prepared = stix_helper.generate_export(
        raw_data_component, stix_version=STIX_VERSION_2_0
    )
    assert "x_mitre_data_source_ref" not in prepared
    result = stix_helper.prepare_export(prepared, stix_version=STIX_VERSION_2_0)

    assert [obj["id"] for obj in result] == [DATA_SOURCE_ID, DATA_COMPONENT_ID]
    data_component = result[1]
    assert data_component["x_mitre_data_source_ref"] == DATA_SOURCE_ID
    assert "dataSource" not in data_component
    assert result[0]["spec_version"] == "2.0"


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


def _nested_refs_page(target_ids, has_next_page, end_cursor=None):
    return {
        "data": {
            "stixNestedRefRelationships": {
                "edges": [
                    {"node": {"id": target_id, "to": {"standard_id": target_id}}}
                    for target_id in target_ids
                ],
                "pageInfo": {
                    "startCursor": None,
                    "endCursor": end_cursor,
                    "hasNextPage": has_next_page,
                    "hasPreviousPage": False,
                    "globalCount": 2,
                },
            }
        }
    }


def test_stix_nested_ref_relationship_list_get_all_follows_pages():
    client = _fake_client()
    pages = [
        _nested_refs_page(["file--1"], has_next_page=True, end_cursor="cursor-1"),
        _nested_refs_page(["file--2"], has_next_page=False),
    ]
    with patch.object(client, "query", side_effect=pages) as query:
        result = client.stix_nested_ref_relationship.list(
            fromId=MALWARE_INTERNAL_ID, getAll=True
        )

    assert [ref["to"]["standard_id"] for ref in result] == ["file--1", "file--2"]
    assert [call.args[1]["after"] for call in query.call_args_list] == [
        None,
        "cursor-1",
    ]


def test_stix_nested_ref_relationship_list_without_get_all_reads_one_page():
    client = _fake_client()
    page = _nested_refs_page(["file--1"], has_next_page=True, end_cursor="cursor-1")
    with patch.object(client, "query", return_value=page) as query:
        result = client.stix_nested_ref_relationship.list(fromId=MALWARE_INTERNAL_ID)

    assert [ref["to"]["standard_id"] for ref in result] == ["file--1"]
    query.assert_called_once()
