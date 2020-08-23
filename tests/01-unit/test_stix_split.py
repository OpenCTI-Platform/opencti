from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


def test_split_bundle():

    stix_splitter = OpenCTIStix2Splitter()
    with open("./data/enterprise-attack.json") as file:
        content = file.read()
        bundles = stix_splitter.split_bundle(content)
    assert len(bundles) == 7029
