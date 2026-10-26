"""Tests for the RabbitMQ TLS context built by the connector helper.

Verifies that the server certificate is verified by default and that
MQ_USE_SSL_REJECT_UNAUTHORIZED=false is the only way to disable it.
"""

import os
import ssl
from unittest.mock import patch

from pycti.connector.opencti_connector_helper import create_mq_ssl_context


@patch.dict(os.environ, {}, clear=True)
def test_mq_ssl_context_verifies_certificate_by_default():
    ssl_context = create_mq_ssl_context({})

    assert ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert ssl_context.check_hostname is True


@patch.dict(os.environ, {"MQ_USE_SSL_REJECT_UNAUTHORIZED": "false"}, clear=True)
def test_mq_ssl_context_skips_verification_when_disabled_by_env():
    ssl_context = create_mq_ssl_context({})

    assert ssl_context.verify_mode == ssl.CERT_NONE
    assert ssl_context.check_hostname is False


@patch.dict(os.environ, {}, clear=True)
def test_mq_ssl_context_skips_verification_when_disabled_by_config():
    ssl_context = create_mq_ssl_context({"mq": {"use_ssl_reject_unauthorized": False}})

    assert ssl_context.verify_mode == ssl.CERT_NONE
