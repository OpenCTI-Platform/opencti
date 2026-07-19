import json
import uuid

from stix2 import Report

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter, is_id_supported


def test_split_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/enterprise-attack.json") as file:
        content = file.read()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 7016


def test_is_id_supported_preserves_stix_and_non_stix_behavior():
    assert is_id_supported("malware--known") is True
    assert is_id_supported("unsupported--unknown") is False
    assert is_id_supported("not-a-stix-id") is True


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


def test_split_bundle_deduplicates_refs_preserving_order():
    stix_splitter = OpenCTIStix2Splitter()
    bundle = {
        "type": "bundle",
        "id": "bundle--dedup",
        "objects": [
            {
                "id": "report--root",
                "type": "report",
                "object_refs": [
                    "indicator--2",
                    "indicator--1",
                    "indicator--2",
                ],
            },
            {"id": "indicator--1", "type": "indicator"},
            {"id": "indicator--2", "type": "indicator"},
        ],
    }

    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle, use_json=False
    )
    root = next(
        item
        for split_bundle in bundles
        for item in split_bundle["objects"]
        if item["id"] == "report--root"
    )

    assert expectations == 3
    assert root["object_refs"] == ["indicator--2", "indicator--1"]


def test_split_bundle_groups_only_same_dependency_levels():
    stix_splitter = OpenCTIStix2Splitter()
    bundle = {
        "type": "bundle",
        "id": "bundle--chunked",
        "objects": [
            {
                "id": "report--root",
                "type": "report",
                "object_refs": ["indicator--1"],
            },
            {"id": "indicator--1", "type": "indicator"},
            {"id": "indicator--2", "type": "indicator"},
        ],
    }

    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle, use_json=False, max_bundle_objects=2
    )

    assert expectations == 3
    assert [
        [item["id"] for item in split_bundle["objects"]] for split_bundle in bundles
    ] == [["indicator--1", "indicator--2"], ["report--root"]]
    assert [split_bundle["x_opencti_seq"] for split_bundle in bundles] == [1, 2]


def test_split_bundle_respects_max_serialized_bytes_for_grouped_objects():
    stix_splitter = OpenCTIStix2Splitter()
    objects = [
        {
            "id": f"indicator--{index}",
            "type": "indicator",
            "description": "x" * 128,
        }
        for index in range(3)
    ]
    sized_objects = [{**item, "nb_deps": 1} for item in objects]
    max_bundle_bytes = (
        len(
            OpenCTIStix2Splitter.stix2_create_bundle(
                "bundle--byte-chunked",
                1,
                sized_objects,
                True,
            ).encode("utf-8")
        )
        - 1
    )
    bundle = {
        "type": "bundle",
        "id": "bundle--byte-chunked",
        "objects": objects,
    }

    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        json.dumps(bundle),
        use_json=True,
        max_bundle_objects=3,
        max_bundle_bytes=max_bundle_bytes,
    )

    assert expectations == 3
    assert [
        [item["id"] for item in json.loads(split_bundle)["objects"]]
        for split_bundle in bundles
    ] == [["indicator--0", "indicator--1"], ["indicator--2"]]
    assert all(
        len(split_bundle.encode("utf-8")) <= max_bundle_bytes
        for split_bundle in bundles
    )


def test_split_bundle_emits_single_oversized_object_as_is():
    stix_splitter = OpenCTIStix2Splitter()
    obj = {
        "id": "indicator--oversized",
        "type": "indicator",
        "description": "x" * 128,
    }
    max_bundle_bytes = (
        len(
            OpenCTIStix2Splitter.stix2_create_bundle(
                "bundle--oversized",
                1,
                [{**obj, "nb_deps": 1}],
                True,
            ).encode("utf-8")
        )
        - 1
    )

    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        json.dumps(
            {
                "type": "bundle",
                "id": "bundle--oversized",
                "objects": [obj],
            }
        ),
        use_json=True,
        max_bundle_objects=3,
        max_bundle_bytes=max_bundle_bytes,
    )

    assert expectations == 1
    assert len(bundles) == 1
    assert len(bundles[0].encode("utf-8")) > max_bundle_bytes


def test_split_bundle_skips_json_serialization_for_unbounded_dict_output(monkeypatch):
    json_dumps_calls = []
    original_json_dumps = json.dumps

    def count_json_dumps(*args, **kwargs):
        json_dumps_calls.append(args[0])
        return original_json_dumps(*args, **kwargs)

    monkeypatch.setattr(
        "pycti.utils.opencti_stix2_splitter.json.dumps",
        count_json_dumps,
    )
    stix_splitter = OpenCTIStix2Splitter()
    bundle = {
        "type": "bundle",
        "id": "bundle--dict-output",
        "objects": [
            {"id": "indicator--1", "type": "indicator"},
            {"id": "indicator--2", "type": "indicator"},
        ],
    }

    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle,
        use_json=False,
    )

    assert expectations == 2
    assert all(isinstance(split_bundle, dict) for split_bundle in bundles)
    assert json_dumps_calls == []


def test_split_bundle_reuses_external_reference_ids_across_objects(monkeypatch):
    generate_id_calls = []

    def generate_id(url=None, source_name=None, external_id=None):
        generate_id_calls.append((url, source_name, external_id))
        return f"external-reference--{url or source_name}|{external_id}"

    monkeypatch.setattr(
        "pycti.utils.opencti_stix2_splitter.external_reference_generate_id",
        generate_id,
    )
    stix_splitter = OpenCTIStix2Splitter()
    shared_reference = {
        "source_name": "benchmark",
        "url": "https://example.test/shared",
    }
    bundle = {
        "type": "bundle",
        "id": "bundle--external-reference-cache",
        "objects": [
            {
                "id": "malware--1",
                "type": "malware",
                "external_references": [shared_reference, dict(shared_reference)],
            },
            {
                "id": "malware--2",
                "type": "malware",
                "external_references": [dict(shared_reference)],
            },
            {
                "id": "malware--3",
                "type": "malware",
                "external_references": [
                    {
                        "source_name": "benchmark",
                        "url": "https://example.test/other",
                    }
                ],
            },
        ],
    }

    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle, use_json=False
    )
    references_by_id = {
        split_bundle["objects"][0]["id"]: split_bundle["objects"][0][
            "external_references"
        ]
        for split_bundle in bundles
    }

    assert expectations == 3
    assert len(references_by_id["malware--1"]) == 1
    assert len(references_by_id["malware--2"]) == 1
    assert len(references_by_id["malware--3"]) == 1
    assert generate_id_calls == [
        ("https://example.test/shared", "benchmark", None),
        ("https://example.test/other", "benchmark", None),
    ]


def test_splitter_external_reference_id_cache_keeps_non_string_inputs_uncached(
    monkeypatch,
):
    generate_id_calls = []

    def generate_id(url=None, source_name=None, external_id=None):
        generate_id_calls.append((url, source_name, external_id))
        return f"external-reference--{url or source_name}|{external_id}"

    monkeypatch.setattr(
        "pycti.utils.opencti_stix2_splitter.external_reference_generate_id",
        generate_id,
    )
    stix_splitter = OpenCTIStix2Splitter()
    reference = {"source_name": "benchmark", "url": 123}

    first = stix_splitter._get_external_reference_id(reference)
    second = stix_splitter._get_external_reference_id(reference)

    assert first == second
    assert generate_id_calls == [(123, "benchmark", None), (123, "benchmark", None)]


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
