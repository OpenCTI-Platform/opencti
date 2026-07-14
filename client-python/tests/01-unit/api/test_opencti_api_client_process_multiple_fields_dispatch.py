from types import SimpleNamespace

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils


class _Processor:
    def __init__(self):
        self.calls = 0

    def process_multiple_fields(self, data):
        self.calls += 1
        return data


def test_process_multiple_fields_caches_entity_type_dispatch(monkeypatch):
    client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    client.indicator = SimpleNamespace()
    client.user = _Processor()
    resolver_calls = []
    original_resolver = OpenCTIStix2Utils.retrieve_class_for_method

    def count_resolver_calls(*args, **kwargs):
        resolver_calls.append(args[1]["entity_type"])
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(
        OpenCTIStix2Utils,
        "retrieve_class_for_method",
        staticmethod(count_resolver_calls),
    )

    for _ in range(3):
        client.process_multiple_fields({"entity_type": "Indicator"})
        client.process_multiple_fields({"entity_type": "User"})

    assert resolver_calls == ["Indicator", "User"]
    assert client.user.calls == 3
