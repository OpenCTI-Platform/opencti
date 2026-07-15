from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_identity import Identity

_PRIMARY_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def pick_aliases(stix_object):
        return stix_object.get("x_opencti_aliases")


class _OpenCTI:
    def __init__(self):
        self.stix2 = _Stix2()
        self.bulk_lookup_keys = []

    def copy_attributes_from_extension(self, attribute_map, stix_object):
        self.bulk_lookup_keys.append(tuple(attribute_map))
        OpenCTIApiClient.copy_attributes_from_extension(attribute_map, stix_object)


def test_identity_import_copies_extension_fields_in_one_bulk_lookup():
    opencti = _OpenCTI()
    identity = Identity(opencti)
    identity.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "identity--benchmark",
        "type": "identity",
        "identity_class": "organization",
        "name": "Benchmark Identity",
        "x_opencti_score": 99,
        "extensions": {
            _PRIMARY_EXTENSION: {
                "aliases": ["Benchmark Alias"],
                "organization_type": "vendor",
                "score": 50,
                "stix_ids": ["identity--legacy"],
                "workflow_id": "workflow--benchmark",
            }
        },
    }

    result = identity.import_from_stix2(stixObject=stix_object)

    assert result["x_opencti_aliases"] == ["Benchmark Alias"]
    assert result["x_opencti_organization_type"] == "vendor"
    assert result["x_opencti_score"] == 99
    assert result["x_opencti_stix_ids"] == ["identity--legacy"]
    assert result["x_opencti_workflow_id"] == "workflow--benchmark"
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_score", "score") in opencti.bulk_lookup_keys[0]
