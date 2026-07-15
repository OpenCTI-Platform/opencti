from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_location import Location

_PRIMARY_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def pick_aliases(stix_object):
        return stix_object.get("x_opencti_aliases")


class _OpenCTI:
    def __init__(self):
        self.stix2 = _Stix2()
        self.bulk_lookup_keys = []
        self.type_lookup_calls = 0

    def get_attribute_in_extension(self, key, stix_object):
        if key == "type":
            self.type_lookup_calls += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def copy_attributes_from_extension(self, attribute_map, stix_object):
        self.bulk_lookup_keys.append(tuple(attribute_map))
        OpenCTIApiClient.copy_attributes_from_extension(attribute_map, stix_object)


def test_location_import_bulk_copies_ordinary_extension_fields():
    opencti = _OpenCTI()
    location = Location(opencti)
    location.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "location--benchmark",
        "type": "location",
        "name": "Benchmark Location",
        "extensions": {
            _PRIMARY_EXTENSION: {
                "type": "City",
                "aliases": ["Location Alias"],
                "workflow_id": "workflow--location",
            }
        },
    }

    result = location.import_from_stix2(stixObject=stix_object)

    assert result["type"] == "City"
    assert result["x_opencti_aliases"] == ["Location Alias"]
    assert result["x_opencti_workflow_id"] == "workflow--location"
    assert opencti.type_lookup_calls == 1
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_workflow_id", "workflow_id") in opencti.bulk_lookup_keys[0]
