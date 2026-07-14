from collections import Counter

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _KillChainPhase:
    def __init__(self):
        self.create_calls = []

    def create(self, **kwargs):
        self.create_calls.append(kwargs)
        return {
            "id": "kill-chain-phase--benchmark",
            "entity_type": "Kill-Chain-Phase",
        }


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()
        self.kill_chain_phase = _KillChainPhase()

    @staticmethod
    def get_draft_id():
        return ""

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


@pytest.mark.parametrize(
    "phase_field",
    ["kill_chain_phases", "x_opencti_kill_chain_phases"],
)
def test_extract_embedded_relationships_reads_kill_chain_order_extension_once(
    phase_field,
):
    opencti = _OpenCTI()
    stix2 = OpenCTIStix2(opencti)
    stix2.mapping_cache_permanent["vocabularies_definition_fields"] = []
    stix_object = {
        "id": "malware--benchmark",
        "type": "malware",
        "created_by_ref": None,
        "labels": [],
        "external_references": [],
        "x_opencti_granted_refs": [],
        phase_field: [
            {
                "kill_chain_name": "benchmark",
                "phase_name": "phase",
                "extensions": {_OPENCTI_EXTENSION: {"order": 42}},
            }
        ],
    }

    result = stix2.extract_embedded_relationships(stix_object)

    assert result["kill_chain_phases"] == ["kill-chain-phase--benchmark"]
    assert opencti.kill_chain_phase.create_calls[0]["x_opencti_order"] == 42
    assert opencti.extension_lookup_counts["order"] == 1
