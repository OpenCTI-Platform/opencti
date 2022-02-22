from stix2 import Report

from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def test_split_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/enterprise-attack.json") as file:
        content = file.read()
    bundles = stix_splitter.split_bundle(content)
    assert len(bundles) == 7029
    #
    # with open("./tests/data/test.pdf", 'w') as file:
    #     content = file.read()
    # with pytest.raises(Exception):
    #     stix_splitter.split_bundle(content)


def test_crate_bundle():
    stix_splitter = OpenCTIStix2Splitter()
    report = Report(
        report_types=["campaign"],
        name="Bad Cybercrime",
        published="2016-04-06T20:03:00.000Z",
        object_refs=["indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7"],
    ).serialize()
    observables = [report]

    bundle = stix_splitter.stix2_create_bundle(
        observables, use_json=False, event_version=None
    )

    for key in ["type", "id", "spec_version", "objects"]:
        assert key in bundle
    assert len(bundle.keys()) == 4

    bundle = stix_splitter.stix2_create_bundle(
        observables, use_json=False, event_version=1
    )
    for key in ["type", "id", "spec_version", "objects", "x_opencti_event_version"]:
        assert key in bundle
    assert len(bundle.keys()) == 5
