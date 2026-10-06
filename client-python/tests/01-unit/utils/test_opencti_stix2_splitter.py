import json
import uuid

import pytest
from stix2 import Report

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter
from pycti.utils.opencti_stix2_utils import (
    STIX_EXT_OCTI_TIMELINE,
    TIMELINE_REQUIRED_IDS,
)


def test_split_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/enterprise-attack.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 7016


def test_split_test_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/DATA-TEST-STIX2_v2.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 59
    base_bundles = json.loads(content)["objects"]
    for base in base_bundles:
        found = None
        for bundle in bundles:
            json_bundle = json.loads(bundle)
            object_json = json_bundle["objects"][0]
            if object_json["id"] == base["id"]:
                found = object_json
                break
        assert found is not None, "Every object of the bundle must be available"
        del found["nb_deps"]
        assert json.dumps(base) == json.dumps(
            found
        ), "Splitter must not have change the content"


def test_split_mono_entity_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/mono-bundle-entity.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 1
    json_bundle = json.loads(bundles[0])["objects"][0]
    assert json_bundle["created_by_ref"] == "fa42a846-8d90-4e51-bc29-71d5b4802168"
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=content, cleanup_inconsistent_bundle=True
    )
    assert expectations == 1
    json_bundle = json.loads(bundles[0])["objects"][0]
    assert json_bundle["created_by_ref"] is None


def test_split_mono_relationship_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/mono-bundle-relationship.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 1
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=content, cleanup_inconsistent_bundle=True
    )
    assert expectations == 0


def test_split_capec_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/mitre_att_capec.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 2610


def test_split_internal_ids_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/bundle_with_internal_ids.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 4
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=content, cleanup_inconsistent_bundle=True
    )
    assert expectations == 4
    for bundle in bundles:
        json_bundle = json.loads(bundle)
        object_json = json_bundle["objects"][0]
        if object_json["id"] == "relationship--10e8c71d-a1b4-4e35-bca8-2e4a3785ea04":
            assert (
                object_json["created_by_ref"] == "ced3e53e-9663-4c96-9c60-07d2e778d931"
            )


def test_split_missing_refs_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/missing_refs.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 4
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=content, cleanup_inconsistent_bundle=True
    )
    assert expectations == 3


def test_split_cyclic_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/cyclic-bundle.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 6
    for bundle in bundles:
        json_bundle = json.loads(bundle)
        object_json = json_bundle["objects"][0]
        if object_json["id"] == "report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7":
            assert (
                len(object_json["external_references"]) == 1
            )  # References are duplicated
            assert len(object_json["object_refs"]) == 2  # Cleaned cyclic refs
            assert len(object_json["object_marking_refs"]) == 1
            assert (
                object_json["object_marking_refs"][0]
                == "marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27"
            )


def test_create_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    report = Report(
        report_types=["campaign"],
        name="Bad Cybercrime",
        published="2016-04-06T20:03:00.000Z",
        object_refs=["indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7"],
    ).serialize()
    observables = [report]

    bundle = stix_splitter.stix2_create_bundle(
        "bundle--" + str(uuid.uuid4()),
        0,
        observables,
        use_json=False,
        event_version=None,
    )

    for key in ["type", "id", "spec_version", "objects", "x_opencti_seq"]:
        assert key in bundle
    assert len(bundle.keys()) == 5

    bundle = stix_splitter.stix2_create_bundle(
        "bundle--" + str(uuid.uuid4()), 0, observables, use_json=False, event_version=1
    )
    for key in [
        "type",
        "id",
        "spec_version",
        "objects",
        "x_opencti_event_version",
        "x_opencti_seq",
    ]:
        assert key in bundle
    assert len(bundle.keys()) == 6


def test_split_timeline_extension_refs_are_dependencies():
    # The case comes first in the bundle, but the elements, author and marking named only in its
    # timeline extension must be imported before it
    case = {
        "type": "case-incident",
        "spec_version": "2.1",
        "id": "case-incident--6b0cbf59-1fd4-4b5a-9c55-1f2f4f5b8d11",
        "name": "Ransomware on the finance file servers",
        "extensions": {
            STIX_EXT_OCTI_TIMELINE: {
                "extension_type": "property-extension",
                "events": [
                    {
                        "id": "timeline-event--0f3d6a2e-7c51-4f0b-9d7e-2b8c4e1a5f60",
                        "title": "Hosts isolated",
                        "event_time": "2026-02-05T10:00:00.000Z",
                        "element_ref": "malware--0b2b1f4a-6f4e-4e3c-9a7e-3c1e2f3a4b5c",
                        "created_by_ref": "identity--8f5d1a3e-2b4c-4d6e-8f1a-3b5c7d9e1f20",
                        "object_marking_refs": [
                            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                        ],
                    }
                ],
                "annotations": [
                    {
                        "rule_id": "technique-kill-chain",
                        "kind": "technique_used",
                        "element_ref": "attack-pattern--3c1e2f3a-4b5c-4e3c-9a7e-0b2b1f4a6f4e",
                        "pinned": True,
                    }
                ],
            }
        },
    }
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--0b2b1f4a-6f4e-4e3c-9a7e-3c1e2f3a4b5c",
        "name": "Loader",
        "is_family": True,
    }
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--8f5d1a3e-2b4c-4d6e-8f1a-3b5c7d9e1f20",
        "name": "SOC",
        "identity_class": "organization",
    }
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "definition_type": "statement",
        "definition": {"statement": "Amber"},
    }
    attack_pattern = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--3c1e2f3a-4b5c-4e3c-9a7e-0b2b1f4a6f4e",
        "name": "Spearphishing",
    }
    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": [case, malware, identity, marking, attack_pattern],
    }
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=json.dumps(bundle)
    )
    assert expectations == 5
    order = [json.loads(b)["objects"][0]["id"] for b in bundles]
    assert order[-1] == case["id"]
    sequences = {
        json.loads(b)["objects"][0]["id"]: json.loads(b)["x_opencti_seq"]
        for b in bundles
    }
    for dependency in [malware, identity, marking, attack_pattern]:
        assert sequences[dependency["id"]] < sequences[case["id"]]
    # The extension travels unchanged, a ref missing from the bundle included
    split_case = json.loads(bundles[-1])["objects"][0]
    assert split_case["extensions"][STIX_EXT_OCTI_TIMELINE] == (
        case["extensions"][STIX_EXT_OCTI_TIMELINE]
    )


@pytest.mark.parametrize("case_first", [True, False])
@pytest.mark.parametrize("through_report", [False, True])
def test_split_timeline_extension_keeps_the_reverse_refs_of_its_elements(
    case_first, through_report
):
    # The element of a contribution refers back to the case (a note about the case, directly or
    # through a report): the case cannot wait for it, the note keeps its reference to the case,
    # and the case is sent again after the note, requiring it, for its timeline to attach it
    case = {
        "type": "case-incident",
        "spec_version": "2.1",
        "id": "case-incident--6b0cbf59-1fd4-4b5a-9c55-1f2f4f5b8d13",
        "name": "Ransomware on the finance file servers",
        "extensions": {
            STIX_EXT_OCTI_TIMELINE: {
                "events": [
                    {
                        "id": "timeline-event--0f3d6a2e-7c51-4f0b-9d7e-2b8c4e1a5f62",
                        "title": "Analyst note on the scope",
                        "event_time": "2026-02-05T10:00:00.000Z",
                        "element_ref": "note--3a1b2c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                    }
                ],
                "annotations": [],
            }
        },
    }
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": "report--7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a",
        "name": "Weekly incident digest",
        "published": "2026-02-05T12:00:00.000Z",
        "object_refs": [case["id"]],
    }
    note = {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--3a1b2c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
        "content": "The file servers of the finance team only",
        "object_refs": [report["id"] if through_report else case["id"]],
    }
    objects = [note, report] if through_report else [note]
    objects = [case] + objects if case_first else objects + [case]
    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": objects,
    }
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=json.dumps(bundle)
    )
    assert expectations == len(objects) + 1
    split = [json.loads(b) for b in bundles]
    order = [b["objects"][0]["id"] for b in split]
    assert order.index(case["id"]) < order.index(note["id"])
    split_by_id = {b["objects"][0]["id"]: b["objects"][0] for b in split}
    assert split_by_id[note["id"]]["object_refs"] == note["object_refs"]
    if through_report:
        assert split_by_id[report["id"]]["object_refs"] == [case["id"]]
    first_case, resent_case = [b for b in split if b["objects"][0]["id"] == case["id"]]
    assert TIMELINE_REQUIRED_IDS not in first_case["objects"][0]
    assert resent_case["objects"][0][TIMELINE_REQUIRED_IDS] == [note["id"]]
    note_sequence = next(b for b in split if b["objects"][0]["id"] == note["id"])[
        "x_opencti_seq"
    ]
    assert first_case["x_opencti_seq"] < note_sequence < resent_case["x_opencti_seq"]
    assert order[-1] == case["id"]
    # The first copy creates the case without its timeline, the resent one carries it:
    # the milestones are imported once, with the elements they point to
    assert STIX_EXT_OCTI_TIMELINE not in first_case["objects"][0]["extensions"]
    assert resent_case["objects"][0]["extensions"][STIX_EXT_OCTI_TIMELINE] == (
        case["extensions"][STIX_EXT_OCTI_TIMELINE]
    )
    # The other extensions of the case travel with both copies
    for split_case in [first_case, resent_case]:
        assert set(split_case["objects"][0]["extensions"]) >= (
            set(case["extensions"]) - {STIX_EXT_OCTI_TIMELINE}
        )


def test_split_timeline_extension_missing_refs_are_kept():
    case = {
        "type": "incident",
        "spec_version": "2.1",
        "id": "incident--6b0cbf59-1fd4-4b5a-9c55-1f2f4f5b8d12",
        "name": "Suspicious sign-ins",
        "extensions": {
            STIX_EXT_OCTI_TIMELINE: {
                "events": [
                    {
                        "id": "timeline-event--0f3d6a2e-7c51-4f0b-9d7e-2b8c4e1a5f61",
                        "title": "Accounts reset",
                        "event_time": "2026-02-05T10:00:00.000Z",
                        "element_ref": "malware--00000000-0000-4000-8000-000000000000",
                    }
                ],
                "annotations": [],
            }
        },
    }
    bundle = {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": [case]}
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=json.dumps(bundle), cleanup_inconsistent_bundle=True
    )
    assert expectations == 1
    split_case = json.loads(bundles[0])["objects"][0]
    events = split_case["extensions"][STIX_EXT_OCTI_TIMELINE]["events"]
    assert events[0]["element_ref"] == "malware--00000000-0000-4000-8000-000000000000"
