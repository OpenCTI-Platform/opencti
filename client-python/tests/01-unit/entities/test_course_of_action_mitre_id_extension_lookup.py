from collections import Counter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_course_of_action import CourseOfAction

_MITRE_EXTENSION = "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"


class _Stix2:
    @staticmethod
    def pick_aliases(_stix_object):
        return []


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.mitre_extension_lookup_counts = Counter()
        self.stix2 = _Stix2()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)

    def get_attribute_in_mitre_extension(self, key, stix_object):
        self.mitre_extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_mitre_extension(key, stix_object)


def test_course_of_action_mitre_id_extension_is_read_once():
    opencti = _OpenCTI()
    course_of_action = CourseOfAction(opencti)
    course_of_action.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "course-of-action--1",
        "type": "course-of-action",
        "name": "Benchmark course of action",
        "extensions": {_MITRE_EXTENSION: {"id": "M1"}},
    }

    result = course_of_action.import_from_stix2(stixObject=stix_object)

    assert result["x_mitre_id"] == "M1"
    assert opencti.mitre_extension_lookup_counts["id"] == 1
