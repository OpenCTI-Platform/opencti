from collections import Counter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_location import Location

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def pick_aliases(_stix_object):
        return []


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.stix2 = _Stix2()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def test_location_type_extension_is_read_once():
    opencti = _OpenCTI()
    location = Location(opencti)
    location.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "location--1",
        "type": "location",
        "name": "Benchmark location",
        "extensions": {_OPENCTI_EXTENSION: {"type": "City"}},
    }

    result = location.import_from_stix2(stixObject=stix_object)

    assert result["type"] == "City"
    assert opencti.extension_lookup_counts["type"] == 1
