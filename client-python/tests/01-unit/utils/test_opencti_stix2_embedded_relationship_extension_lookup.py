from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _CountingOpenCTI:
    def __init__(self):
        self.extension_lookup_keys = []

    @staticmethod
    def get_draft_id():
        return ""

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_keys.append(key)
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def test_extract_embedded_relationships_reads_root_extension_fields_once():
    opencti = _CountingOpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    stix_object = {
        "id": "malware--benchmark",
        "type": "malware",
        "extensions": {
            _OPENCTI_EXTENSION: {
                "created_by_ref": "identity--benchmark",
                "labels": [],
                "kill_chain_phases": [],
                "external_references": [],
                "granted_refs": ["organization--benchmark"],
            }
        },
    }

    result = stix2.extract_embedded_relationships(stix_object)

    assert result["created_by"] == "identity--benchmark"
    assert result["object_label"] == []
    assert result["kill_chain_phases"] == []
    assert result["external_references"] == []
    assert result["granted_refs"] == ["organization--benchmark"]
    assert opencti.extension_lookup_keys == [
        "created_by_ref",
        "labels",
        "kill_chain_phases",
        "external_references",
        "granted_refs",
    ]
