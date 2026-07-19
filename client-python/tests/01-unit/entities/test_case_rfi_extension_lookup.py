from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_case_rfi import CaseRfi

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


def test_case_rfi_import_bulk_copies_ordinary_extension_fields():
    opencti = _OpenCTI()
    case_rfi = CaseRfi(opencti)
    case_rfi.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "case-rfi--benchmark",
        "type": "case-rfi",
        "name": "Benchmark Case RFI",
        "x_opencti_content": "Root content",
        "extensions": {
            _PRIMARY_EXTENSION: {
                "content": "Extension content",
                "assignee_ids": ["identity--assignee"],
                "participant_ids": ["identity--participant"],
                "workflow_id": "workflow--case-rfi",
            }
        },
    }

    result = case_rfi.import_from_stix2(stixObject=stix_object)

    assert result["content"] == "Root content"
    assert result["objectAssignee"] == ["identity--assignee"]
    assert result["objectParticipant"] == ["identity--participant"]
    assert result["x_opencti_workflow_id"] == "workflow--case-rfi"
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_workflow_id", "workflow_id") in opencti.bulk_lookup_keys[0]
