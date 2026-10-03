"""Unit tests covering the propagation of the observed data counters
(number_seen, max_distinct_count) from a STIX object to the
observedDataAdd mutation (see issue #18399).
"""

from unittest.mock import MagicMock

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_observed_data import ObservedData

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


@pytest.fixture
def opencti_mock():
    mock = MagicMock()
    mock.query.return_value = {"data": {"observedDataAdd": {}}}
    mock.process_multiple_fields.side_effect = lambda x: x
    mock.get_attribute_in_extension.side_effect = (
        OpenCTIApiClient.get_attribute_in_extension
    )
    return mock


def _stix_observed_data(**properties):
    return {
        "id": "observed-data--7d258c31-9a26-4543-aecb-2abc5ed366be",
        "type": "observed-data",
        "spec_version": "2.1",
        "first_observed": "2026-09-25T02:18:37.000Z",
        "last_observed": "2026-09-29T17:25:17.000Z",
        "number_observed": 23,
        "object_refs": ["domain-name--00000000-0000-4000-8000-000000000000"],
        **properties,
    }


def _mutation_input(opencti_mock):
    _, variables = opencti_mock.query.call_args[0]
    return variables["input"]


class TestObservedDataCounters:
    def test_counters_read_from_opencti_extension(self, opencti_mock):
        stix_object = _stix_observed_data(
            extensions={
                OPENCTI_EXTENSION_ID: {
                    "extension_type": "property-extension",
                    "number_seen": 4,
                    "max_distinct_count": 12,
                }
            }
        )

        ObservedData(opencti_mock).import_from_stix2(stixObject=stix_object)

        mutation_input = _mutation_input(opencti_mock)
        assert mutation_input["number_seen"] == 4
        assert mutation_input["max_distinct_count"] == 12

    def test_counters_read_from_top_level_properties(self, opencti_mock):
        stix_object = _stix_observed_data(number_seen=2, max_distinct_count=7)

        ObservedData(opencti_mock).import_from_stix2(stixObject=stix_object)

        mutation_input = _mutation_input(opencti_mock)
        assert mutation_input["number_seen"] == 2
        assert mutation_input["max_distinct_count"] == 7

    def test_missing_counters_are_sent_as_none(self, opencti_mock):
        ObservedData(opencti_mock).import_from_stix2(stixObject=_stix_observed_data())

        mutation_input = _mutation_input(opencti_mock)
        assert mutation_input["number_seen"] is None
        assert mutation_input["max_distinct_count"] is None

    def test_create_forwards_counters(self, opencti_mock):
        ObservedData(opencti_mock).create(
            first_observed="2026-09-25T02:18:37.000Z",
            last_observed="2026-09-29T17:25:17.000Z",
            number_observed=23,
            number_seen=3,
            max_distinct_count=9,
            objects=["domain-name--00000000-0000-4000-8000-000000000000"],
        )

        mutation_input = _mutation_input(opencti_mock)
        assert mutation_input["number_seen"] == 3
        assert mutation_input["max_distinct_count"] == 9
