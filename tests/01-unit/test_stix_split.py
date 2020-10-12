from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def test_split_bundle():

    stix_splitter = OpenCTIStix2Splitter()
    with open("./tests/data/enterprise-attack.json") as file:
        content = file.read()
    bundles = stix_splitter.split_bundle(content)
    assert len(bundles) == 7028

    with open("./tests/data/enterprise-attack-orphan.json") as file_orphan:
        content_orphan = file_orphan.read()
    # With orphan removal
    stix_no_orphan_splitter = OpenCTIStix2Splitter(remove_orphan=False)
    bundles_orphan = stix_no_orphan_splitter.split_bundle(content_orphan)
    assert len(bundles_orphan) == 7029
    # With orphan removal
    stix_no_orphan_splitter = OpenCTIStix2Splitter(remove_orphan=True)
    bundles_orphan = stix_no_orphan_splitter.split_bundle(content_orphan)
    assert len(bundles_orphan) == 7021
