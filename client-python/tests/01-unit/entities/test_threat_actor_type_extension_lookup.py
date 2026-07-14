from collections import Counter
from types import SimpleNamespace

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_threat_actor import ThreatActor

_OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


class _OpenCTI:
    def __init__(self):
        self.extension_lookup_counts = Counter()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


def _build_threat_actor():
    return {
        "id": "threat-actor--1",
        "type": "threat-actor",
        "name": "benchmark",
        "extensions": {_OPENCTI_EXTENSION: {"type": "Threat-Actor-Group"}},
    }


@pytest.mark.parametrize("operation", ["generate_id_from_data", "import_from_stix2"])
def test_threat_actor_type_extension_is_read_once(operation):
    opencti = _OpenCTI()
    threat_actor = ThreatActor(opencti)
    threat_actor.threat_actor_group = SimpleNamespace(
        import_from_stix2=lambda **_kwargs: "group"
    )
    threat_actor.threat_actor_individual = SimpleNamespace(
        import_from_stix2=lambda **_kwargs: "individual"
    )

    if operation == "generate_id_from_data":
        result = threat_actor.generate_id_from_data(_build_threat_actor())
        assert result.startswith("threat-actor--")
    else:
        result = threat_actor.import_from_stix2(stixObject=_build_threat_actor())
        assert result == "group"

    assert opencti.extension_lookup_counts["type"] == 1
