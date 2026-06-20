import json
import uuid

from stix2 import Report

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


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


def test_split_bundle_group_by_deps_partition():
    # group_by_deps must still emit every object exactly once (disjoint partition),
    # so the work expectation count is unchanged versus one-object-per-bundle splitting.
    with open("./tests/data/DATA-TEST-STIX2_v2.json") as file:
        content = file.read()
    base_ids = {obj["id"] for obj in json.loads(content)["objects"]}
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        content, group_by_deps=True
    )
    assert expectations == 59
    seen = [obj["id"] for b in bundles for obj in json.loads(b)["objects"]]
    assert len(seen) == len(set(seen)), "no object duplicated across grouped bundles"
    assert set(seen) == base_ids, "every input object emitted exactly once"
    assert any(
        len(json.loads(b)["objects"]) > 1 for b in bundles
    ), "grouping must produce at least one multi-object bundle"


def test_split_bundle_group_by_deps_colocates_relationship():
    # A relationship and both of its endpoints must land in the same bundle, endpoints
    # first, so a single worker creates them in order with no cross-worker race.
    ind = "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7"
    mal = "malware--9c4638ec-f1de-4ddb-b58d-a0e0b1c2d3e4"
    rel = "relationship--0c4638ec-f1de-4ddb-b58d-a0e0b1c2d3e5"
    bundle = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [
                {
                    "type": "malware",
                    "id": mal,
                    "spec_version": "2.1",
                    "name": "X",
                    "is_family": True,
                },
                {
                    "type": "indicator",
                    "id": ind,
                    "spec_version": "2.1",
                    "name": "h",
                    "pattern_type": "stix",
                    "pattern": "[file:name = 'x']",
                },
                {
                    "type": "relationship",
                    "id": rel,
                    "spec_version": "2.1",
                    "relationship_type": "indicates",
                    "source_ref": ind,
                    "target_ref": mal,
                },
            ],
        }
    )
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle, group_by_deps=True
    )
    assert expectations == 3
    rel_bundle = next(
        json.loads(b)["objects"]
        for b in bundles
        if any(obj["id"] == rel for obj in json.loads(b)["objects"])
    )
    order = [obj["id"] for obj in rel_bundle]
    assert {ind, mal, rel} <= set(order), "relationship grouped with both endpoints"
    assert order.index(ind) < order.index(rel), "source precedes the relationship"
    assert order.index(mal) < order.index(rel), "target precedes the relationship"


def test_split_bundle_group_by_deps_orders_shared_dependency_first():
    # A shared dependency can live in only one group. The bundle that holds it must be
    # emitted before any bundle that only references it across a group boundary, even
    # when the holding group is heavier (rel_a carries an extra author dep). Guards
    # against re-ordering the groups, which would reintroduce a MISSING_REFERENCE race.
    shared = "malware--11111111-1111-4111-8111-111111111111"
    author = "identity--22222222-2222-4222-8222-222222222222"
    ind_a = "indicator--aaaaaaaa-1111-4111-8111-111111111111"
    ind_b = "indicator--bbbbbbbb-1111-4111-8111-111111111111"
    rel_a = "relationship--aaaaaaaa-2222-4222-8222-222222222222"
    rel_b = "relationship--bbbbbbbb-2222-4222-8222-222222222222"

    def indicator(identifier, name, created_by=None):
        obj = {
            "type": "indicator",
            "id": identifier,
            "spec_version": "2.1",
            "name": name,
            "pattern_type": "stix",
            "pattern": "[file:name = '%s']" % name,
        }
        if created_by is not None:
            obj["created_by_ref"] = created_by
        return obj

    def relationship(identifier, source):
        return {
            "type": "relationship",
            "id": identifier,
            "spec_version": "2.1",
            "relationship_type": "indicates",
            "source_ref": source,
            "target_ref": shared,
        }

    bundle = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [
                {
                    "type": "malware",
                    "id": shared,
                    "spec_version": "2.1",
                    "name": "Fam",
                    "is_family": True,
                },
                {
                    "type": "identity",
                    "id": author,
                    "spec_version": "2.1",
                    "name": "A",
                    "identity_class": "organization",
                },
                indicator(ind_a, "a", created_by=author),
                indicator(ind_b, "b"),
                relationship(rel_a, ind_a),
                relationship(rel_b, ind_b),
            ],
        }
    )
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle, group_by_deps=True
    )
    assert expectations == 6

    def ids(serialized):
        return [obj["id"] for obj in json.loads(serialized)["objects"]]

    holder_idx = next(i for i, b in enumerate(bundles) if shared in ids(b))
    for i, b in enumerate(bundles):
        objects = json.loads(b)["objects"]
        references_shared = any(obj.get("target_ref") == shared for obj in objects)
        if references_shared and shared not in ids(b):
            assert (
                holder_idx < i
            ), "bundle holding the shared dependency must come first"


def test_split_bundle_group_by_deps_keeps_endpoints_under_small_cap():
    # Breadth-first traversal must take the relationship's direct source/target before
    # any transitive ref, so even a tight max_group_size keeps both endpoints with the
    # relationship. The target carries an author; a depth-first walk could pull that
    # author into the cap and drop the source endpoint.
    author = "identity--22222222-2222-4222-8222-222222222222"
    ind = "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7"
    mal = "malware--9c4638ec-f1de-4ddb-b58d-a0e0b1c2d3e4"
    rel = "relationship--0c4638ec-f1de-4ddb-b58d-a0e0b1c2d3e5"
    bundle = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid4()),
            "objects": [
                {
                    "type": "identity",
                    "id": author,
                    "spec_version": "2.1",
                    "name": "A",
                    "identity_class": "organization",
                },
                {
                    "type": "malware",
                    "id": mal,
                    "spec_version": "2.1",
                    "name": "X",
                    "is_family": True,
                    "created_by_ref": author,
                },
                {
                    "type": "indicator",
                    "id": ind,
                    "spec_version": "2.1",
                    "name": "h",
                    "pattern_type": "stix",
                    "pattern": "[file:name = 'x']",
                },
                {
                    "type": "relationship",
                    "id": rel,
                    "spec_version": "2.1",
                    "relationship_type": "indicates",
                    "source_ref": ind,
                    "target_ref": mal,
                },
            ],
        }
    )
    stix_splitter = OpenCTIStix2Splitter()
    expectations, _, bundles = stix_splitter.split_bundle_with_expectations(
        bundle, group_by_deps=True, max_group_size=3
    )
    assert expectations == 4
    rel_bundle = next(
        json.loads(b)["objects"]
        for b in bundles
        if any(obj["id"] == rel for obj in json.loads(b)["objects"])
    )
    grouped = {obj["id"] for obj in rel_bundle}
    assert {ind, mal, rel} <= grouped, "both endpoints kept with the relationship"
    assert len(rel_bundle) <= 3
