from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_event import Event

_PRIMARY_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def pick_aliases(stix_object):
        return stix_object.get("x_opencti_aliases")


class _OpenCTI:
    def __init__(self):
        self.stix2 = _Stix2()
        self.bulk_lookup_keys = []

    def get_attribute_in_extension(self, key, stix_object):
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def copy_attributes_from_extension(self, attribute_map, stix_object):
        self.bulk_lookup_keys.append(tuple(attribute_map))
        OpenCTIApiClient.copy_attributes_from_extension(attribute_map, stix_object)


def test_event_import_bulk_copies_extension_fields():
    opencti = _OpenCTI()
    event = Event(opencti)
    event.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "event--benchmark",
        "type": "event",
        "name": "Benchmark Event",
        "extensions": {
            _PRIMARY_EXTENSION: {
                "granted_refs": ["identity--organization"],
                "modified_at": "2026-07-16T00:00:00.000Z",
            }
        },
    }

    result = event.import_from_stix2(stixObject=stix_object)

    assert stix_object["x_opencti_granted_refs"] == ["identity--organization"]
    assert result["x_opencti_modified_at"] == "2026-07-16T00:00:00.000Z"
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_modified_at", "modified_at") in opencti.bulk_lookup_keys[0]
