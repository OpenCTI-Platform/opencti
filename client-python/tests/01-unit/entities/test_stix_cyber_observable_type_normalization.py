from collections import Counter

import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable


class _NullLogger:
    @staticmethod
    def info(*_args, **_kwargs):
        return None

    @staticmethod
    def error(*_args, **_kwargs):
        raise AssertionError("unexpected observable create error")


class _RecordingClient:
    def __init__(self):
        self.app_logger = _NullLogger()
        self.variables = None

    @staticmethod
    def get_attribute_in_extension(_key, _stix_object):
        return None

    def query(self, _query, variables):
        self.variables = variables
        return {
            "data": {
                "stixCyberObservableAdd": {
                    "id": "observable--benchmark",
                    "standard_id": "observable--benchmark",
                    "entity_type": variables["type"],
                    "parent_types": [],
                }
            }
        }

    @staticmethod
    def process_multiple_fields(value):
        return value


class _ExtensionRecordingClient(_RecordingClient):
    def __init__(self):
        super().__init__()
        self.extension_lookup_counts = Counter()

    def get_attribute_in_extension(self, key, stix_object):
        self.extension_lookup_counts[key] += 1
        return OpenCTIApiClient.get_attribute_in_extension(key, stix_object)


@pytest.mark.parametrize(
    ("observable_data", "expected_type", "expected_input_key"),
    [
        (
            {"type": "domain-name", "value": "example.test"},
            "Domain-Name",
            "DomainName",
        ),
        (
            {
                "type": "x-opencti-payment-card",
                "card_number": "4111111111111111",
            },
            "Payment-Card",
            "PaymentCard",
        ),
        (
            {"type": "x-opencti-imsi", "value": "123456789012345"},
            "IMSI",
            "IMSI",
        ),
    ],
)
def test_create_preserves_observable_type_normalization(
    observable_data, expected_type, expected_input_key
):
    client = _RecordingClient()
    observable_api = StixCyberObservable(client)

    result = observable_api.create(observableData=observable_data)

    assert result["entity_type"] == expected_type
    assert client.variables["type"] == expected_type
    assert expected_input_key in client.variables


@pytest.mark.parametrize(
    (
        "observable_data",
        "expected_input_key",
        "expected_field",
        "expected_lookup_key",
        "expected_value",
    ),
    [
        (
            {
                "type": "artifact",
                "mime_type": "application/octet-stream",
                "extensions": {
                    "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82": {
                        "score": 80,
                        "additional_names": ["payload.bin"],
                    }
                },
            },
            "Artifact",
            "x_opencti_additional_names",
            "additional_names",
            ["payload.bin"],
        ),
        (
            {
                "type": "file",
                "name": "payload.bin",
                "extensions": {
                    "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82": {
                        "score": 80,
                        "additional_names": ["payload.bin"],
                    }
                },
            },
            "StixFile",
            "x_opencti_additional_names",
            "additional_names",
            ["payload.bin"],
        ),
        (
            {
                "type": "software",
                "name": "benchmark",
                "extensions": {
                    "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82": {
                        "score": 80,
                        "x_opencti_product": "benchmark",
                    }
                },
            },
            "Software",
            "x_opencti_product",
            "x_opencti_product",
            "benchmark",
        ),
    ],
)
def test_create_reads_extension_backed_fields_once(
    observable_data,
    expected_input_key,
    expected_field,
    expected_lookup_key,
    expected_value,
):
    client = _ExtensionRecordingClient()
    observable_api = StixCyberObservable(client)

    observable_api.create(observableData=observable_data)

    assert client.variables["x_opencti_score"] == 80
    assert client.variables[expected_input_key][expected_field] == expected_value
    assert client.extension_lookup_counts["score"] == 1
    assert client.extension_lookup_counts[expected_lookup_key] == 1
