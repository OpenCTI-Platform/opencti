from collections import Counter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_marking_definition import MarkingDefinition

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def test_marking_definition_order_extension_is_read_once():
    opencti = _OpenCTI()
    marking_definition = MarkingDefinition(opencti)
    marking_definition.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "marking-definition--1",
        "type": "marking-definition",
        "definition_type": "statement",
        "definition": "benchmark",
        "extensions": {_OPENCTI_EXTENSION: {"order": 42}},
    }

    result = marking_definition.import_from_stix2(stixObject=stix_object)

    assert result["x_opencti_order"] == 42
    assert opencti.extension_lookup_counts["order"] == 1
