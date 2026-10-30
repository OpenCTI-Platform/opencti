"""Tests for the global TLS certificate verification switch."""

import os
from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient
from pycti.utils import opencti_tls
from pycti.utils.opencti_tls import (
    get_tls_reject_unauthorized,
    log_tls_verification_disabled,
)


@patch.dict(os.environ, {}, clear=True)
def test_tls_reject_unauthorized_is_disabled_by_default():
    assert get_tls_reject_unauthorized() is False
    assert get_tls_reject_unauthorized({"opencti": None}) is False


@pytest.mark.parametrize(
    "value, expected",
    [
        ("true", True),
        ("TRUE", True),
        (" yes ", True),
        ("1", True),
        ("On", True),
        ("false", False),
        ("False", False),
        ("no", False),
        ("0", False),
        ("OFF", False),
        ("", False),
    ],
)
def test_tls_reject_unauthorized_reads_environment(value, expected):
    with patch.dict(os.environ, {"OPENCTI_TLS_REJECT_UNAUTHORIZED": value}, clear=True):
        assert get_tls_reject_unauthorized() is expected


@pytest.mark.parametrize("value", ["ture", "2", "enabled"])
def test_tls_reject_unauthorized_rejects_unknown_environment_value(value):
    with patch.dict(os.environ, {"OPENCTI_TLS_REJECT_UNAUTHORIZED": value}, clear=True):
        with pytest.raises(ValueError, match="OPENCTI_TLS_REJECT_UNAUTHORIZED"):
            get_tls_reject_unauthorized()


@patch.dict(os.environ, {"OPENCTI_TLS_REJECT_UNAUTHORIZED": ""}, clear=True)
def test_tls_reject_unauthorized_empty_environment_falls_back_to_config():
    assert get_tls_reject_unauthorized({"opencti": {"tls_reject_unauthorized": True}})


@patch.dict(os.environ, {}, clear=True)
def test_tls_reject_unauthorized_reads_config():
    assert get_tls_reject_unauthorized({"opencti": {"tls_reject_unauthorized": True}})
    assert not get_tls_reject_unauthorized(
        {"opencti": {"tls_reject_unauthorized": "false"}}
    )
    assert get_tls_reject_unauthorized({"opencti": {"tls_reject_unauthorized": 1}})
    with pytest.raises(ValueError, match="opencti.tls_reject_unauthorized"):
        get_tls_reject_unauthorized({"opencti": {"tls_reject_unauthorized": "maybe"}})


@patch.dict(os.environ, {"OPENCTI_TLS_REJECT_UNAUTHORIZED": "false"}, clear=True)
def test_tls_reject_unauthorized_environment_wins_over_config():
    assert not get_tls_reject_unauthorized(
        {"opencti": {"tls_reject_unauthorized": True}}
    )


@pytest.mark.parametrize(
    "env, expected", [({}, False), ({"OPENCTI_TLS_REJECT_UNAUTHORIZED": "true"}, True)]
)
def test_api_client_ssl_verify_defaults_to_global_switch(env, expected):
    with patch.dict(os.environ, env, clear=True), patch.object(
        OpenCTIApiClient, "_setup_proxy_certificates"
    ):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            perform_health_check=False,
        )
    assert client.ssl_verify is expected


@patch.dict(os.environ, {"OPENCTI_TLS_REJECT_UNAUTHORIZED": "false"}, clear=True)
def test_api_client_explicit_ssl_verify_wins_over_global_switch():
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=True,
            perform_health_check=False,
        )
    assert client.ssl_verify is True


@patch.dict(os.environ, {}, clear=True)
def test_tls_verification_disabled_warning_is_logged_once():
    app_logger = MagicMock()
    with patch.object(opencti_tls, "_tls_warning_logged", False):
        log_tls_verification_disabled(app_logger)
        log_tls_verification_disabled(app_logger)
    app_logger.warning.assert_called_once()
    assert "OPENCTI_TLS_REJECT_UNAUTHORIZED=true" in app_logger.warning.call_args[0][0]


@pytest.mark.parametrize(
    "env, config",
    [
        ({"OPENCTI_TLS_REJECT_UNAUTHORIZED": "true"}, None),
        ({}, {"opencti": {"tls_reject_unauthorized": True}}),
    ],
)
def test_tls_verification_disabled_warning_is_skipped_when_enabled_globally(
    env, config
):
    app_logger = MagicMock()
    with patch.dict(os.environ, env, clear=True), patch.object(
        opencti_tls, "_tls_warning_logged", False
    ):
        log_tls_verification_disabled(app_logger, config)
    app_logger.warning.assert_not_called()


def _build_api_client(setup_proxy_certificates=None, **kwargs):
    with patch.object(
        OpenCTIApiClient,
        "_setup_proxy_certificates",
        autospec=True,
        side_effect=setup_proxy_certificates,
    ), patch(
        "pycti.api.opencti_api_client.log_tls_verification_disabled"
    ) as log_warning:
        OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            perform_health_check=False,
            **kwargs,
        )
    return log_warning


@patch.dict(os.environ, {}, clear=True)
def test_api_client_warns_when_using_the_disabled_global_default():
    _build_api_client().assert_called_once()


@patch.dict(os.environ, {}, clear=True)
def test_api_client_does_not_warn_on_explicit_ssl_verify():
    _build_api_client(ssl_verify=False).assert_not_called()


@patch.dict(os.environ, {}, clear=True)
def test_api_client_does_not_warn_when_proxy_certificates_enable_verification():
    def use_proxy_bundle(client):
        client.ssl_verify = "/tmp/combined-ca-bundle.crt"

    _build_api_client(setup_proxy_certificates=use_proxy_bundle).assert_not_called()
