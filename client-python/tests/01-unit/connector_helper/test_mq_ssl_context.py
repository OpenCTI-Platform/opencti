"""Tests for the RabbitMQ TLS context built by the connector helper.

Verifies that the server certificate is not verified by default, that the
global OPENCTI_TLS_REJECT_UNAUTHORIZED switch enables it and that
MQ_USE_SSL_REJECT_UNAUTHORIZED overrides the global switch.
"""

import os
import ssl
from unittest.mock import patch

from pycti.connector.opencti_connector_helper import create_mq_ssl_context


@patch.dict(os.environ, {}, clear=True)
def test_mq_ssl_context_skips_verification_by_default():
    ssl_context = create_mq_ssl_context({})

    assert ssl_context.verify_mode == ssl.CERT_NONE
    assert ssl_context.check_hostname is False


@patch.dict(os.environ, {"OPENCTI_TLS_REJECT_UNAUTHORIZED": "true"}, clear=True)
def test_mq_ssl_context_verifies_certificate_when_enabled_globally():
    ssl_context = create_mq_ssl_context({})

    assert ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert ssl_context.check_hostname is True


@patch.dict(os.environ, {}, clear=True)
def test_mq_ssl_context_verifies_certificate_when_enabled_globally_by_config():
    ssl_context = create_mq_ssl_context({"opencti": {"tls_reject_unauthorized": True}})

    assert ssl_context.verify_mode == ssl.CERT_REQUIRED


@patch.dict(
    os.environ,
    {
        "OPENCTI_TLS_REJECT_UNAUTHORIZED": "true",
        "MQ_USE_SSL_REJECT_UNAUTHORIZED": "false",
    },
    clear=True,
)
def test_mq_ssl_context_specific_setting_overrides_global_switch():
    ssl_context = create_mq_ssl_context({})

    assert ssl_context.verify_mode == ssl.CERT_NONE
    assert ssl_context.check_hostname is False
