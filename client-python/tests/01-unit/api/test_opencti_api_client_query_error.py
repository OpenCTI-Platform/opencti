from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient


@pytest.fixture
def api_client():
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        return client


def query_error(api_client, error):
    response = MagicMock(status_code=200)
    response.json.return_value = {"errors": [error]}
    with patch.object(api_client.session, "post", return_value=response):
        with pytest.raises(ValueError) as raised:
            api_client.query("{ reports { edges { node { id } } } }")
    return raised.value.args[0]


def test_keeps_the_request_id_of_a_hidden_error(api_client):
    error = query_error(
        api_client,
        {
            "message": "An unexpected error occurred",
            "name": "DATABASE_ERROR",
            "extensions": {"code": "DATABASE_ERROR", "request_id": "req-20495"},
        },
    )
    assert error == {
        "name": "DATABASE_ERROR",
        "error_message": "An unexpected error occurred",
        "request_id": "req-20495",
    }


def test_has_no_request_id_when_the_platform_sends_none(api_client):
    error = query_error(
        api_client,
        {
            "message": "Business validation",
            "name": "FUNCTIONAL_ERROR",
            "extensions": {"code": "FUNCTIONAL_ERROR", "data": {"reason": "too_large"}},
        },
    )
    assert error == {
        "name": "FUNCTIONAL_ERROR",
        "error_message": "Business validation",
        "reason": "too_large",
    }
