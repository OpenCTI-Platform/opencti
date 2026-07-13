import pytest

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
