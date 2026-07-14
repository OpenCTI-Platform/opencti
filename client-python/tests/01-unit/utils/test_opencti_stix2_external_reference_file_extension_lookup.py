from collections import Counter
from types import SimpleNamespace

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _ExternalReference:
    @staticmethod
    def generate_id(url, source_name, external_id):
        return f"external-reference--{url}|{source_name}|{external_id}"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.external_reference = _ExternalReference()
        self.app_logger = SimpleNamespace(warning=lambda *_args, **_kwargs: None)

    @staticmethod
    def get_draft_id():
        return ""

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    @staticmethod
    def query(_query):
        return {"data": {"vocabularyCategories": []}}

    @staticmethod
    def logger_class(_name):
        return SimpleNamespace(warning=lambda *_args, **_kwargs: None)


@pytest.mark.parametrize(
    "field_name", ["external_references", "x_opencti_external_references"]
)
def test_external_reference_file_extension_is_read_once(field_name):
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    stix2._create_or_get_external_reference = (
        lambda generated_ref_id, *_args: generated_ref_id
    )
    stix_object = {
        "id": "malware--1",
        "type": "malware",
        "created_by_ref": None,
        "object_marking_refs": [],
        "labels": [],
        "kill_chain_phases": [],
        "x_opencti_granted_refs": [],
        field_name: [
            {
                "source_name": "benchmark",
                "url": "https://example.test/reference",
                "external_id": "REF-1",
                "extensions": {
                    _OPENCTI_EXTENSION: {"files": [{"name": "payload.txt"}]}
                },
            }
        ],
    }

    result = stix2.extract_embedded_relationships(stix_object)

    assert result["external_references"] == [
        "external-reference--https://example.test/reference|benchmark|REF-1"
    ]
    assert opencti.extension_lookup_counts["files"] == 1
