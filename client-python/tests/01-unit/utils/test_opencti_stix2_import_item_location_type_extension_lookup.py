from collections import Counter
from types import SimpleNamespace

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.app_logger = SimpleNamespace(debug=lambda *_args, **_kwargs: None)

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def test_import_item_location_type_extension_is_read_once():
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    import_object_calls = []
    stix2.import_object = lambda *args, **kwargs: import_object_calls.append(
        (args, kwargs)
    )
    stix_object = {
        "id": "location--1",
        "type": "location",
        "extensions": {_OPENCTI_EXTENSION: {"location_type": "city"}},
    }

    result = stix2.import_item(stix_object, types=["city"])

    assert result is True
    assert len(import_object_calls) == 1
    assert opencti.extension_lookup_counts["location_type"] == 1
