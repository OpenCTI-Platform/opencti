import json
import uuid

from stix2 import Report

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def test_split_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/enterprise-attack.json") as file:
        content = file.read()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 7016


def test_split_test_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/DATA-TEST-STIX2_v2.json") as file:
        content = file.read()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
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
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 1
    json_bundle = json.loads(bundles[0])["objects"][0]
    assert json_bundle["created_by_ref"] == "fa42a846-8d90-4e51-bc29-71d5b4802168"
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=content, cleanup_inconsistent_bundle=True
    )
    assert expectations == 1
    json_bundle = json.loads(bundles[0])["objects"][0]
    assert json_bundle["created_by_ref"] is None


def test_split_mono_relationship_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/mono-bundle-relationship.json") as file:
        content = file.read()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 1
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=content, cleanup_inconsistent_bundle=True
    )
    assert expectations == 0


def test_split_capec_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/mitre_att_capec.json") as file:
        content = file.read()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 2610


def test_split_internal_ids_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/bundle_with_internal_ids.json") as file:
        content = file.read()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 4
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(
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
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
    assert expectations == 4
    # Split with cleanup_inconsistent_bundle
    stix_splitter = OpenCTIStix2Splitter()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(
        bundle=content, cleanup_inconsistent_bundle=True
    )
    assert expectations == 3


def test_split_cyclic_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/cyclic-bundle.json") as file:
        content = file.read()
    expectations, bundles = stix_splitter.split_bundle_with_expectations(content)
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
