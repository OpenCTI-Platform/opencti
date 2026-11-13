"""Unit tests for the export access filter applied to the embedded files.

A full export embeds the content of the attached files. The files carrying a
marking excluded by the export access filter (the max shareable markings of
the user) must not be embedded, like the relationships and the refs.
"""

import json
from unittest.mock import MagicMock

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2

MALWARE_STANDARD_ID = "malware--92ddf766-b27c-5159-8f46-27002bba2f04"
ARTIFACT_STANDARD_ID = "artifact--8c9d0f5b-0f4c-5a5e-9a3b-6f1e0f0b8a11"

TLP_GREEN = {
    "id": "internal-tlp-green",
    "standard_id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "entity_type": "Marking-Definition",
    "definition_type": "TLP",
    "definition": "TLP:GREEN",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "x_opencti_order": 2,
    "x_opencti_color": "#2e7d32",
}
TLP_RED = {
    "id": "internal-tlp-red",
    "standard_id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    "entity_type": "Marking-Definition",
    "definition_type": "TLP",
    "definition": "TLP:RED",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "x_opencti_order": 4,
    "x_opencti_color": "#c62828",
}

# Built like getExportFilter (platform) for a user whose max shareable marking is TLP:GREEN
EXCLUDE_TLP_RED = {
    "mode": "and",
    "filterGroups": [],
    "filters": [
        {
            "key": "objectMarking",
            "mode": "and",
            "operator": "not_eq",
            "values": [TLP_RED["id"]],
        }
    ],
}
NO_RESTRICTION = {"mode": "and", "filterGroups": [], "filters": []}


def _file(file_id, markings):
    return {
        "id": file_id,
        "name": file_id + ".txt",
        "size": 10,
        "metaData": {"mimetype": "text/plain", "version": None},
        "objectMarking": markings,
    }


def _external_reference(files):
    return {
        "id": "internal-external-reference",
        "standard_id": "external-reference--11111111-1111-1111-1111-111111111111",
        "entity_type": "External-Reference",
        "source_name": "source",
        "description": None,
        "url": "https://example.com/report",
        "hash": None,
        "external_id": None,
        "importFiles": files,
    }


def _raw_entity(
    entity_type="Malware",
    standard_id=MALWARE_STANDARD_ID,
    import_files=None,
    external_references=None,
):
    """Entity as returned by a reader (``process_multiple_fields`` applied)."""
    import_files = import_files or []
    external_references = external_references or []
    entity = {
        "id": "internal-" + entity_type.lower(),
        "standard_id": standard_id,
        "entity_type": entity_type,
        "parent_types": ["Basic-Object", "Stix-Object", "Stix-Core-Object"],
        "spec_version": "2.1",
        "createdBy": None,
        "objectMarking": [TLP_GREEN],
        "objectMarkingIds": [TLP_GREEN["id"]],
        "externalReferences": external_references,
        "externalReferencesIds": [e["id"] for e in external_references],
        "importFiles": import_files,
        "importFilesIds": [f["id"] for f in import_files],
    }
    if entity_type == "Malware":
        entity["name"] = "Malware"
    return entity


@pytest.fixture
def stix_helper():
    """``OpenCTIStix2`` helper whose API calls are mocked."""
    client = OpenCTIApiClient(
        "http://fake:4000", "fake", ssl_verify=False, perform_health_check=False
    )
    client.stix_nested_ref_relationship = MagicMock()
    client.stix_nested_ref_relationship.list.return_value = []
    client.stix_core_relationship = MagicMock()
    client.stix_core_relationship.list.return_value = []
    client.stix_sighting_relationship = MagicMock()
    client.stix_sighting_relationship.list.return_value = []
    client.fetch_opencti_file_by_id = MagicMock(
        side_effect=lambda file_id, binary=False, serialize=False: "content-of-"
        + file_id
    )
    return OpenCTIStix2(client)


def _mock_readers(stix_helper, *raw_entities):
    """Readers finding only the given entities, by ``id`` or by an ``ids`` filter."""
    by_id = {raw_entity["id"]: raw_entity for raw_entity in raw_entities}

    def read(**kwargs):
        if kwargs.get("id") is not None:
            return by_id.get(kwargs["id"])
        filters = json.dumps(kwargs.get("filters"))
        return next((e for i, e in by_id.items() if '"' + i + '"' in filters), None)

    stix_helper.get_reader = MagicMock(return_value=read)


def _export(stix_helper, raw_entity, access_filter, mode="full"):
    # Only the exported entity is found, the full export finds no neighbour
    _mock_readers(stix_helper, raw_entity)
    return stix_helper.get_stix_bundle_or_object_from_entity_id(
        entity_type=raw_entity["entity_type"],
        entity_id=raw_entity["id"],
        mode=mode,
        access_filter=access_filter,
    )


def _exported_entity(bundle, standard_id=MALWARE_STANDARD_ID):
    return next(o for o in bundle["objects"] if o["id"] == standard_id)


def _fetched_file_ids(stix_helper):
    return [c.args[0] for c in stix_helper.opencti.fetch_opencti_file_by_id.mock_calls]


def test_file_with_excluded_marking_is_not_embedded(stix_helper):
    raw_entity = _raw_entity(
        import_files=[_file("red-file", [TLP_RED]), _file("green-file", [TLP_GREEN])]
    )

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED)

    exported = _exported_entity(bundle)
    assert [f["name"] for f in exported["x_opencti_files"]] == ["green-file.txt"]
    assert "red-file" not in _fetched_file_ids(stix_helper)
    assert TLP_RED["standard_id"] not in [o["id"] for o in bundle["objects"]]
    assert "importFiles" not in exported
    assert "importFilesIds" not in exported


def test_only_excluded_files_leaves_no_file(stix_helper):
    raw_entity = _raw_entity(import_files=[_file("red-file", [TLP_RED])])

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED, mode="simple")

    exported = _exported_entity(bundle)
    assert "x_opencti_files" not in exported
    assert "importFiles" not in exported
    assert "importFilesIds" not in exported
    stix_helper.opencti.fetch_opencti_file_by_id.assert_not_called()


def test_file_with_allowed_marking_is_embedded(stix_helper):
    raw_entity = _raw_entity(
        import_files=[_file("green-file", [TLP_GREEN]), _file("unmarked-file", [])]
    )

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED)

    files = _exported_entity(bundle)["x_opencti_files"]
    assert [f["name"] for f in files] == ["green-file.txt", "unmarked-file.txt"]
    assert files[0]["data"] == "content-of-green-file"
    assert files[0]["object_marking_refs"] == [TLP_GREEN["standard_id"]]
    assert files[1]["object_marking_refs"] == []


def test_file_without_read_markings_is_not_embedded_under_restriction(stix_helper):
    file = _file("unknown-file", [])
    del file["objectMarking"]
    raw_entity = _raw_entity(import_files=[file])

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED)

    assert "x_opencti_files" not in _exported_entity(bundle)


@pytest.mark.parametrize("access_filter", [None, NO_RESTRICTION])
def test_no_restriction_embeds_every_file(stix_helper, access_filter):
    raw_entity = _raw_entity(
        import_files=[_file("red-file", [TLP_RED]), _file("green-file", [TLP_GREEN])]
    )

    bundle = _export(stix_helper, raw_entity, access_filter)

    files = _exported_entity(bundle)["x_opencti_files"]
    assert [f["name"] for f in files] == ["red-file.txt", "green-file.txt"]
    assert files[0]["data"] == "content-of-red-file"
    assert files[0]["object_marking_refs"] == [TLP_RED["standard_id"]]
    assert TLP_RED["standard_id"] in [o["id"] for o in bundle["objects"]]


def test_file_markings_are_not_duplicated(stix_helper):
    # TLP:GREEN marks the entity and its two files
    raw_entity = _raw_entity(
        import_files=[_file("file-1", [TLP_GREEN]), _file("file-2", [TLP_GREEN])],
        external_references=[_external_reference([_file("ref-file", [TLP_GREEN])])],
    )

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED)

    ids = [o["id"] for o in bundle["objects"]]
    assert ids.count(TLP_GREEN["standard_id"]) == 1


def test_external_reference_file_with_excluded_marking_is_not_embedded(stix_helper):
    raw_entity = _raw_entity(
        external_references=[
            _external_reference(
                [_file("red-ref-file", [TLP_RED]), _file("green-ref-file", [TLP_GREEN])]
            )
        ]
    )

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED)

    external_reference = _exported_entity(bundle)["external_references"][0]
    assert external_reference["x_opencti_files"] == [
        {
            "name": "green-ref-file.txt",
            "data": "content-of-green-ref-file",
            "mime_type": "text/plain",
            "version": None,
            "object_marking_refs": [TLP_GREEN["standard_id"]],
        }
    ]
    assert "red-ref-file" not in _fetched_file_ids(stix_helper)
    assert TLP_RED["standard_id"] not in [o["id"] for o in bundle["objects"]]


def test_external_reference_file_carries_its_markings(stix_helper):
    # TLP:RED marks only the external reference file, no restriction on the export
    raw_entity = _raw_entity(
        external_references=[_external_reference([_file("red-ref-file", [TLP_RED])])]
    )

    bundle = _export(stix_helper, raw_entity, None)

    ref_file = _exported_entity(bundle)["external_references"][0]["x_opencti_files"][0]
    assert ref_file["object_marking_refs"] == [TLP_RED["standard_id"]]
    tlp_red = next(o for o in bundle["objects"] if o["id"] == TLP_RED["standard_id"])
    assert tlp_red["type"] == "marking-definition"
    assert tlp_red["definition"] == {"tlp": "red"}


def test_artifact_payload_is_not_filled_from_an_excluded_file(stix_helper):
    raw_entity = _raw_entity(
        entity_type="Artifact",
        standard_id=ARTIFACT_STANDARD_ID,
        import_files=[_file("red-payload", [TLP_RED])],
    )

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED, mode="simple")

    exported = _exported_entity(bundle, ARTIFACT_STANDARD_ID)
    assert "payload_bin" not in exported
    assert "x_opencti_files" not in exported
    stix_helper.opencti.fetch_opencti_file_by_id.assert_not_called()


def test_artifact_stored_payload_is_removed_when_its_file_is_excluded(stix_helper):
    # The stored payload is a copy of the first file content
    raw_entity = _raw_entity(
        entity_type="Artifact",
        standard_id=ARTIFACT_STANDARD_ID,
        import_files=[_file("red-payload", [TLP_RED])],
    )
    raw_entity["payload_bin"] = "stored-content-of-red-payload"

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED, mode="simple")

    assert "payload_bin" not in _exported_entity(bundle, ARTIFACT_STANDARD_ID)


@pytest.mark.parametrize(
    "import_files,access_filter",
    [([], EXCLUDE_TLP_RED), ([_file("red-payload", [TLP_RED])], None)],
)
def test_artifact_stored_payload_is_kept_without_excluded_file(
    stix_helper, import_files, access_filter
):
    raw_entity = _raw_entity(
        entity_type="Artifact",
        standard_id=ARTIFACT_STANDARD_ID,
        import_files=import_files,
    )
    raw_entity["payload_bin"] = "stored-payload"
    stix_helper.opencti.fetch_opencti_file_by_id.side_effect = lambda *a, **k: None

    bundle = _export(stix_helper, raw_entity, access_filter, mode="simple")

    exported = _exported_entity(bundle, ARTIFACT_STANDARD_ID)
    assert exported["payload_bin"] == "stored-payload"


def test_artifact_payload_is_filled_from_an_allowed_file(stix_helper):
    raw_entity = _raw_entity(
        entity_type="Artifact",
        standard_id=ARTIFACT_STANDARD_ID,
        import_files=[_file("green-payload", [TLP_GREEN])],
    )

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED, mode="simple")

    exported = _exported_entity(bundle, ARTIFACT_STANDARD_ID)
    assert exported["payload_bin"] == "content-of-green-payload"


def test_file_marking_without_id_is_not_embedded_under_restriction(stix_helper):
    marking_without_id = {k: v for k, v in TLP_RED.items() if k != "id"}
    raw_entity = _raw_entity(import_files=[_file("red-file", [marking_without_id])])

    bundle = _export(stix_helper, raw_entity, EXCLUDE_TLP_RED)

    assert "x_opencti_files" not in _exported_entity(bundle)


def test_list_export_filters_files(stix_helper):
    raw_entity = _raw_entity(
        import_files=[_file("red-file", [TLP_RED]), _file("green-file", [TLP_GREEN])],
        external_references=[_external_reference([_file("red-ref-file", [TLP_RED])])],
    )
    stix_helper.export_entities_list = MagicMock(return_value=[raw_entity])
    _mock_readers(stix_helper, raw_entity)

    bundle = stix_helper.export_list(
        entity_type="Malware", mode="full", access_filter=EXCLUDE_TLP_RED
    )

    exported = _exported_entity(bundle)
    assert [f["name"] for f in exported["x_opencti_files"]] == ["green-file.txt"]
    assert "x_opencti_files" not in exported["external_references"][0]
    assert "red-file" not in _fetched_file_ids(stix_helper)
    assert "red-ref-file" not in _fetched_file_ids(stix_helper)


def test_selection_export_filters_artifact_files(stix_helper):
    # A selection reads its entities without files, an Artifact still has its files
    raw_entity = _raw_entity(
        entity_type="Artifact",
        standard_id=ARTIFACT_STANDARD_ID,
        import_files=[_file("red-payload", [TLP_RED])],
    )

    bundle = stix_helper.export_selected([raw_entity], "simple", EXCLUDE_TLP_RED)

    exported = _exported_entity(bundle, ARTIFACT_STANDARD_ID)
    assert "payload_bin" not in exported
    assert "x_opencti_files" not in exported
    stix_helper.opencti.fetch_opencti_file_by_id.assert_not_called()


def test_container_object_files_are_filtered(stix_helper):
    artifact = _raw_entity(
        entity_type="Artifact",
        standard_id=ARTIFACT_STANDARD_ID,
        import_files=[
            _file("red-payload", [TLP_RED]),
            _file("green-file", [TLP_GREEN]),
        ],
    )
    report = _raw_entity(
        entity_type="Report", standard_id="report--33333333-3333-3333-3333-333333333333"
    )
    report["name"] = "Report"
    report["objects"] = [
        {
            "id": artifact["id"],
            "standard_id": ARTIFACT_STANDARD_ID,
            "entity_type": "Artifact",
            "parent_types": artifact["parent_types"],
        }
    ]
    report["objectsIds"] = [artifact["id"]]
    _mock_readers(stix_helper, report, artifact)

    bundle = stix_helper.get_stix_bundle_or_object_from_entity_id(
        entity_type="Report",
        entity_id=report["id"],
        mode="full",
        access_filter=EXCLUDE_TLP_RED,
    )

    exported_artifact = _exported_entity(bundle, ARTIFACT_STANDARD_ID)
    assert "payload_bin" not in exported_artifact
    assert [f["name"] for f in exported_artifact["x_opencti_files"]] == [
        "green-file.txt"
    ]
    assert "red-payload" not in _fetched_file_ids(stix_helper)


@pytest.mark.parametrize(
    "access_filter,expected",
    [
        (None, set()),
        (NO_RESTRICTION, set()),
        (EXCLUDE_TLP_RED, {TLP_RED["id"]}),
        (
            {
                "mode": "and",
                "filters": [
                    {"key": ["objectMarking"], "operator": "not_eq", "values": ["a"]},
                    {"key": "objectMarking", "operator": "eq", "values": ["b"]},
                    {"key": "ids", "operator": "not_eq", "values": ["c"]},
                ],
                "filterGroups": [
                    {
                        "mode": "and",
                        "filters": [
                            {
                                "key": "objectMarking",
                                "operator": "not_eq",
                                "values": ["d"],
                            }
                        ],
                        "filterGroups": [],
                    }
                ],
            },
            {"a", "d"},
        ),
    ],
)
def test_excluded_marking_ids(access_filter, expected):
    assert OpenCTIStix2._get_excluded_marking_ids(access_filter) == expected
