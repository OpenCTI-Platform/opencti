# coding: utf-8
"""Tests for Config loading (config.py)."""

from __future__ import annotations

import pytest

from opencti_mcp.config import load_config


class TestSslVerifyParsing:
    """Verify that ssl_verify is parsed correctly for all input forms."""

    def test_true_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", "true")
        cfg = load_config()
        assert cfg.ssl_verify is True

    def test_false_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", "false")
        cfg = load_config()
        assert cfg.ssl_verify is False

    def test_zero_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", "0")
        cfg = load_config()
        assert cfg.ssl_verify is False

    def test_one_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", "1")
        cfg = load_config()
        assert cfg.ssl_verify is True

    def test_ca_bundle_path_preserved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CA bundle path must NOT be lowercased."""
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", "/etc/pki/tls/certs/CA-bundle.crt")
        cfg = load_config()
        # Path must be returned exactly as supplied — lowercasing would break cert loading
        assert cfg.ssl_verify == "/etc/pki/tls/certs/CA-bundle.crt"

    def test_uppercase_true_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("OPENCTI_SSL_VERIFY", "TRUE")
        cfg = load_config()
        assert cfg.ssl_verify is True

    def test_default_is_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.delenv("OPENCTI_SSL_VERIFY", raising=False)
        cfg = load_config()
        assert cfg.ssl_verify is True


class TestRequiredVariables:
    def test_missing_url_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENCTI_URL", raising=False)
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        with pytest.raises(ValueError, match="OPENCTI_URL"):
            load_config()

    def test_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
        with pytest.raises(ValueError, match="OPENCTI_TOKEN"):
            load_config()


class TestApiKey:
    def test_api_key_populated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("MCP_API_KEY", "supersecret")
        cfg = load_config()
        assert cfg.api_key == "supersecret"

    def test_api_key_defaults_to_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.delenv("MCP_API_KEY", raising=False)
        cfg = load_config()
        assert cfg.api_key == ""


class TestTransportValidation:
    def test_invalid_transport_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("MCP_TRANSPORT", "http")
        with pytest.raises(ValueError, match="MCP_TRANSPORT"):
            load_config()

    def test_invalid_port_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("MCP_SSE_PORT", "invalid")
        with pytest.raises(ValueError, match="MCP_SSE_PORT"):
            load_config()

    def test_port_out_of_range_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("MCP_SSE_PORT", "70000")
        with pytest.raises(ValueError, match="MCP_SSE_PORT"):
            load_config()

    def test_unauthenticated_sse_flag_defaults_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.delenv("MCP_ALLOW_UNAUTHENTICATED_SSE", raising=False)
        cfg = load_config()
        assert cfg.allow_unauthenticated_sse is False

    def test_request_control_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        cfg = load_config()
        assert cfg.max_request_body_bytes == 1_048_576
        assert cfg.max_concurrent_requests == 20
        assert cfg.rate_limit_per_minute == 60

    def test_invalid_request_control_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "tok")
        monkeypatch.setenv("MCP_RATE_LIMIT_PER_MINUTE", "0")
        with pytest.raises(ValueError, match="MCP_RATE_LIMIT_PER_MINUTE"):
            load_config()
