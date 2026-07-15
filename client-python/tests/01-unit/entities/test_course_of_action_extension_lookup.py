from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_course_of_action import CourseOfAction

_PRIMARY_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
_MITRE_EXTENSION = "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"


class _Stix2:
    @staticmethod
    def pick_aliases(stix_object):
        return stix_object.get("x_opencti_aliases")


class _OpenCTI:
    def __init__(self):
        self.stix2 = _Stix2()
        self.bulk_lookup_keys = []
        self.mitre_lookup_calls = 0

    def get_attribute_in_extension(self, key, stix_object):
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def get_attribute_in_mitre_extension(self, key, stix_object):
        self.mitre_lookup_calls += 1
        return OpenCTIApiClient.get_attribute_in_mitre_extension(key, stix_object)

    def copy_attributes_from_extension(self, attribute_map, stix_object):
        self.bulk_lookup_keys.append(tuple(attribute_map))
        OpenCTIApiClient.copy_attributes_from_extension(attribute_map, stix_object)


def test_course_of_action_import_bulk_copies_ordinary_extension_fields():
    opencti = _OpenCTI()
    course_of_action = CourseOfAction(opencti)
    course_of_action.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "course-of-action--benchmark",
        "type": "course-of-action",
        "name": "Benchmark Course of Action",
        "extensions": {
            _PRIMARY_EXTENSION: {
                "aliases": ["Course Alias"],
                "workflow_id": "workflow--course-of-action",
            },
            _MITRE_EXTENSION: {"id": "M1"},
        },
    }

    result = course_of_action.import_from_stix2(stixObject=stix_object)

    assert result["x_opencti_aliases"] == ["Course Alias"]
    assert result["x_opencti_workflow_id"] == "workflow--course-of-action"
    assert result["x_mitre_id"] == "M1"
    assert opencti.mitre_lookup_calls == 1
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_workflow_id", "workflow_id") in opencti.bulk_lookup_keys[0]
