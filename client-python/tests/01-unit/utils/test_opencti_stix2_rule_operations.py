from types import SimpleNamespace

from pycti.utils.opencti_stix2 import OpenCTIStix2


def test_rules_rescan_uses_available_async_rescan_helper():
    calls = []
    helper = OpenCTIStix2(
        SimpleNamespace(
            stix_core_object=SimpleNamespace(
                rule_rescan_async=lambda **kwargs: calls.append(kwargs)
            )
        )
    )

    helper.rules_rescan({"id": "indicator--1"}, "execution--1")

    assert calls == [{"element_id": "indicator--1", "execution_id": "execution--1"}]
