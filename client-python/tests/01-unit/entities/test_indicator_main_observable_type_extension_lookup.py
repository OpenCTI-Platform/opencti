from collections import Counter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_indicator import Indicator

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.mitre_extension_lookup_counts = Counter()
        self.bulk_lookup_keys = []

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def get_attribute_in_mitre_extension(self, key, stix_object):
        self.mitre_extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_mitre_extension(key, stix_object)

    def copy_attributes_from_extension(self, attribute_map, stix_object):
        self.bulk_lookup_keys.append(tuple(attribute_map))
        OpenCTIApiClient.copy_attributes_from_extension(attribute_map, stix_object)


def test_indicator_main_observable_type_extension_is_read_once():
    opencti = _OpenCTI()
    indicator = Indicator(opencti)
    indicator.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "indicator--1",
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '192.0.2.1']",
        "extensions": {
            _OPENCTI_EXTENSION: {"main_observable_type": "IPv4-Addr"},
        },
    }

    result = indicator.import_from_stix2(stixObject=stix_object)

    assert result["x_opencti_main_observable_type"] == "IPv4-Addr"
    assert opencti.extension_lookup_counts["main_observable_type"] == 1


def test_indicator_import_bulk_copies_ordinary_extension_fields():
    opencti = _OpenCTI()
    indicator = Indicator(opencti)
    indicator.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "indicator--2",
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '192.0.2.2']",
        "x_opencti_score": 99,
        "extensions": {
            _OPENCTI_EXTENSION: {
                "score": 50,
                "detection": True,
                "create_observables": True,
                "workflow_id": "workflow--indicator",
            },
        },
    }

    result = indicator.import_from_stix2(stixObject=stix_object)

    assert result["x_opencti_score"] == 99
    assert result["x_opencti_detection"] is True
    assert result["x_opencti_create_observables"] is True
    assert result["x_opencti_workflow_id"] == "workflow--indicator"
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_score", "score") in opencti.bulk_lookup_keys[0]
