from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship

_PRIMARY_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def convert_markdown(value):
        return value


class _OpenCTI:
    def __init__(self):
        self.stix2 = _Stix2()
        self.bulk_lookup_keys = []

    def get_attribute_in_extension(self, key, stix_object):
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def copy_attributes_from_extension(self, attribute_map, stix_object):
        self.bulk_lookup_keys.append(tuple(attribute_map))
        OpenCTIApiClient.copy_attributes_from_extension(attribute_map, stix_object)


def test_stix_core_relationship_import_bulk_copies_extension_fields():
    opencti = _OpenCTI()
    relationship = StixCoreRelationship(opencti)
    relationship.create = lambda **kwargs: kwargs
    stix_relation = {
        "id": "relationship--benchmark",
        "type": "relationship",
        "relationship_type": "uses",
        "source_ref": "identity--source",
        "target_ref": "malware--target",
        "extensions": {
            _PRIMARY_EXTENSION: {
                "granted_refs": ["identity--organization"],
                "workflow_id": "workflow--relationship",
            }
        },
    }

    result = relationship.import_from_stix2(stixRelation=stix_relation)

    assert result["objectOrganization"] == ["identity--organization"]
    assert result["x_opencti_workflow_id"] == "workflow--relationship"
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_workflow_id", "workflow_id") in opencti.bulk_lookup_keys[0]
