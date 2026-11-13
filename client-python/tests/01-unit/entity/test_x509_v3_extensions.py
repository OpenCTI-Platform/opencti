"""Unit tests for the import of X.509 v3 extensions of an x509-certificate
(STIX 2.1 nested ``x509_v3_extensions`` object, see issue #19896).
"""

from unittest.mock import MagicMock

import pytest

from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable

X509_ID = "x509-certificate--bf86f034-2390-54d7-8426-d08433db3fbe"


@pytest.fixture
def observable_api():
    opencti = MagicMock()
    opencti.query.return_value = {"data": {"stixCyberObservableAdd": {"id": "abc"}}}
    opencti.get_attribute_in_extension.return_value = None
    opencti.process_multiple_fields.side_effect = lambda x: x
    return StixCyberObservable(opencti)


def _create(api, **observable_properties):
    api.create(
        observableData={
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": X509_ID,
            "serial_number": "36:f7:d4",
            **observable_properties,
        }
    )
    _, variables = api.opencti.query.call_args[0]
    return variables["X509Certificate"]


class TestX509V3Extensions:
    def test_nested_extensions_are_imported(self, observable_api):
        sent = _create(
            observable_api,
            x509_v3_extensions={
                "subject_alternative_name": "www.example.com, example.com",
                "key_usage": "digitalSignature, keyEncipherment",
                "basic_constraints": "CA:FALSE",
            },
        )
        assert sent["subject_alternative_name"] == "www.example.com, example.com"
        assert sent["key_usage"] == "digitalSignature, keyEncipherment"
        assert sent["basic_constraints"] == "CA:FALSE"

    def test_flat_extensions_still_work(self, observable_api):
        sent = _create(observable_api, subject_alternative_name="example.com")
        assert sent["subject_alternative_name"] == "example.com"

    def test_flat_value_wins_over_nested(self, observable_api):
        sent = _create(
            observable_api,
            key_usage="flat",
            x509_v3_extensions={"key_usage": "nested"},
        )
        assert sent["key_usage"] == "flat"

    def test_missing_extensions_stay_none(self, observable_api):
        sent = _create(observable_api)
        assert sent["subject_alternative_name"] is None
