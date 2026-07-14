from collections import Counter

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_attack_pattern import AttackPattern

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _Stix2:
    @staticmethod
    def pick_aliases(_stix_object):
        return []


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.stix2 = _Stix2()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def test_attack_pattern_order_extension_is_read_once():
    opencti = _OpenCTI()
    attack_pattern = AttackPattern(opencti)
    attack_pattern.create = lambda **kwargs: kwargs
    stix_object = {
        "id": "attack-pattern--1",
        "type": "attack-pattern",
        "name": "Benchmark attack pattern",
        "x_mitre_id": "T1",
        "x_mitre_platforms": [],
        "x_mitre_permissions_required": [],
        "x_mitre_detection": "",
        "x_opencti_stix_ids": [],
        "x_opencti_granted_refs": [],
        "x_opencti_workflow_id": None,
        "x_opencti_modified_at": None,
        "opencti_upsert_operations": None,
        "extensions": {_OPENCTI_EXTENSION: {"order": 42}},
    }

    attack_pattern.import_from_stix2(stixObject=stix_object)

    assert stix_object["x_opencti_order"] == 42
    assert opencti.extension_lookup_counts["order"] == 1
