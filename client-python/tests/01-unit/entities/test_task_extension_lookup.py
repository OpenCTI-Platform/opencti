from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_task import Task

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


def test_task_import_bulk_copies_extension_fields():
    opencti = _OpenCTI()
    task = Task(opencti)
    task.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "task--benchmark",
        "type": "task",
        "name": "Benchmark Task",
        "extensions": {
            _PRIMARY_EXTENSION: {
                "assignee_ids": ["identity--assignee"],
                "participant_ids": ["identity--participant"],
                "workflow_id": "workflow--task",
            }
        },
    }

    result = task.import_from_stix2(stixObject=stix_object)

    assert result["objectAssignee"] == ["identity--assignee"]
    assert result["objectParticipant"] == ["identity--participant"]
    assert result["x_opencti_workflow_id"] == "workflow--task"
    assert len(opencti.bulk_lookup_keys) == 1
    assert ("x_opencti_workflow_id", "workflow_id") in opencti.bulk_lookup_keys[0]
