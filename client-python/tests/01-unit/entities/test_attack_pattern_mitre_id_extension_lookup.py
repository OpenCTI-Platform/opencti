from collections import Counter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_attack_pattern import AttackPattern

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


def test_attack_pattern_mitre_id_extension_is_read_once():
    opencti = _OpenCTI()
    attack_pattern = AttackPattern(opencti)
    attack_pattern.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "attack-pattern--1",
        "type": "attack-pattern",
        "name": "Benchmark attack pattern",
        "x_opencti_order": 0,
        "x_mitre_platforms": [],
        "x_mitre_permissions_required": [],
        "x_mitre_detection": "",
        "x_opencti_stix_ids": [],
        "x_opencti_granted_refs": [],
        "x_opencti_workflow_id": None,
        "x_opencti_modified_at": None,
        "opencti_upsert_operations": None,
        "extensions": {_MITRE_EXTENSION: {"id": "T1"}},
    }

    result = attack_pattern.import_from_stix2(stixObject=stix_object)

    assert result["x_mitre_id"] == "T1"
    assert opencti.mitre_extension_lookup_counts["id"] == 1
