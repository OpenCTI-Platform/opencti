from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_grouping import Grouping

_PRIMARY_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def convert_markdown(value):
        return value

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


def test_grouping_import_bulk_copies_ordinary_extension_fields():
    opencti = _OpenCTI()
    grouping = Grouping(opencti)
    grouping.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "grouping--benchmark",
        "type": "grouping",
        "name": "Benchmark Grouping",
        "context": "suspicious-activity",
        "x_opencti_content": "Root content",
        "extensions": {
            _PRIMARY_EXTENSION: {
                "aliases": ["Grouping Alias"],
                "content": "Extension content",
                "workflow_id": "workflow--grouping",
            }
        },
    }

    result = grouping.import_from_stix2(stixObject=stix_object)

    assert result["content"] == "Root content"
    assert result["x_opencti_aliases"] == ["Grouping Alias"]
    assert result["x_opencti_workflow_id"] == "workflow--grouping"
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_workflow_id", "workflow_id") in opencti.bulk_lookup_keys[0]
