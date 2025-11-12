import os
import tempfile
from unittest.mock import MagicMock, mock_open, patch

import pytest

from pycti import OpenCTIApiClient


class TestOpenCTIApiClient:
    """Test OpenCTIApiClient certificate handling functionality."""

    SAMPLE_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKLdQVPy90WjMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA0Z3VS5JJcds3xfn/ygWyF0qJDr9oYRH/9dMfqHCOq45DqMVJLJBJnMzN
-----END CERTIFICATE-----"""

    INVALID_CONTENT = "This is not a certificate"

    @pytest.fixture
    def api_client(self):
        """Create an API client instance without performing health check."""
        with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
            client = OpenCTIApiClient(
                url="http://localhost:4000",
                token="test-token",
                ssl_verify=False,
                perform_health_check=False,
            )
            # Mock the logger
            client.app_logger = MagicMock()
            return client

    def test_get_certificate_content_inline_pem(self, api_client):
        """Test _get_certificate_content with inline PEM certificate."""
        result = api_client._get_certificate_content(self.SAMPLE_CERTIFICATE)

        assert result == self.SAMPLE_CERTIFICATE
        api_client.app_logger.debug.assert_called_with(
            "HTTPS_CA_CERTIFICATES contains inline certificate content"
        )

    def test_get_certificate_content_file_path(self, api_client):
        """Test _get_certificate_content with a file path containing certificate."""
        # Create a temporary file with certificate content
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".crt", delete=False
        ) as cert_file:
            cert_file.write(self.SAMPLE_CERTIFICATE)
            cert_file_path = cert_file.name

        try:
            result = api_client._get_certificate_content(cert_file_path)

            assert result == self.SAMPLE_CERTIFICATE
            api_client.app_logger.debug.assert_called_with(
                "HTTPS_CA_CERTIFICATES contains valid certificate file path",
                {"file_path": cert_file_path},
            )
        finally:
            # Clean up
            os.unlink(cert_file_path)

    def test_get_certificate_content_invalid_file_content(self, api_client):
        """Test _get_certificate_content with a file containing invalid certificate."""
        # Create a temporary file with invalid content
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as invalid_file:
            invalid_file.write(self.INVALID_CONTENT)
            invalid_file_path = invalid_file.name

        try:
            with pytest.raises(
                ValueError,
                match="File at HTTPS_CA_CERTIFICATES path does not contain valid certificate",
            ):
                api_client._get_certificate_content(invalid_file_path)
        finally:
            # Clean up
            os.unlink(invalid_file_path)

    def test_get_certificate_content_nonexistent_file(self, api_client):
        """Test _get_certificate_content with a nonexistent file path."""
        nonexistent_path = "/tmp/nonexistent_certificate.crt"

        with pytest.raises(
            ValueError,
            match="HTTPS_CA_CERTIFICATES is not a valid certificate or file path",
        ):
            api_client._get_certificate_content(nonexistent_path)

    def test_get_certificate_content_invalid_content(self, api_client):
        """Test _get_certificate_content with invalid content (not PEM, not file)."""
        with pytest.raises(
            ValueError,
            match="HTTPS_CA_CERTIFICATES is not a valid certificate or file path",
        ):
            api_client._get_certificate_content(self.INVALID_CONTENT)

    def test_get_certificate_content_whitespace_handling(self, api_client):
        """Test _get_certificate_content handles whitespace correctly."""
        # Test with certificate content with leading/trailing whitespace
        cert_with_whitespace = f"  \n{self.SAMPLE_CERTIFICATE}  \n"
        result = api_client._get_certificate_content(cert_with_whitespace)

        assert result == cert_with_whitespace  # Should return as-is
        api_client.app_logger.debug.assert_called_with(
            "HTTPS_CA_CERTIFICATES contains inline certificate content"
        )

    @patch.dict(os.environ, {"HTTPS_CA_CERTIFICATES": ""})
    def test_setup_proxy_certificates_no_env(self, api_client):
        """Test _setup_proxy_certificates when HTTPS_CA_CERTIFICATES is not set."""
        api_client._setup_proxy_certificates()

        # Should return early without setting ssl_verify
        assert not hasattr(api_client, "ssl_verify") or api_client.ssl_verify is False

    @patch.dict(os.environ, {})
    def test_setup_proxy_certificates_env_not_present(self, api_client):
        """Test _setup_proxy_certificates when HTTPS_CA_CERTIFICATES env var doesn't exist."""
        api_client._setup_proxy_certificates()

        # Should return early without setting ssl_verify
        assert not hasattr(api_client, "ssl_verify") or api_client.ssl_verify is False

    @patch("tempfile.mkdtemp")
    @patch("os.path.isfile")
    @patch("builtins.open", new_callable=mock_open)
    @patch.dict(
        os.environ,
        {
            "HTTPS_CA_CERTIFICATES": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        },
    )
    def test_setup_proxy_certificates_with_inline_cert(
        self, mock_file, mock_isfile, mock_mkdtemp, api_client
    ):
        """Test _setup_proxy_certificates with inline certificate content."""
        # Setup mocks
        mock_mkdtemp.return_value = "/tmp/test_certs"
        mock_isfile.side_effect = (
            lambda path: path == "/etc/ssl/certs/ca-certificates.crt"
        )

        # Mock system certificate content
        system_cert_content = (
            "-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----"
        )

        def open_side_effect(path, mode="r"):
            if path == "/etc/ssl/certs/ca-certificates.crt" and mode == "r":
                return mock_open(read_data=system_cert_content)()
            return mock_file()

        with patch("builtins.open", side_effect=open_side_effect):
            api_client._setup_proxy_certificates()

        # Verify proxy certificates were processed
        api_client.app_logger.info.assert_called()

    @patch("tempfile.mkdtemp")
    @patch.dict(os.environ, {"HTTPS_CA_CERTIFICATES": "/path/to/cert.crt"})
    def test_setup_proxy_certificates_with_invalid_path(self, mock_mkdtemp, api_client):
        """Test _setup_proxy_certificates with invalid certificate file path."""
        from pycti.api import opencti_api_client

        # Reset global state to ensure clean test
        opencti_api_client._PROXY_CERT_BUNDLE = None
        opencti_api_client._PROXY_CERT_DIR = None

        mock_mkdtemp.return_value = "/tmp/test_certs"

        # Mock _get_certificate_content to raise ValueError (invalid)
        with patch.object(
            api_client,
            "_get_certificate_content",
            side_effect=ValueError("Invalid certificate"),
        ):
            with pytest.raises(ValueError, match="Invalid certificate"):
                api_client._setup_proxy_certificates()

        # Should log error before raising
        api_client.app_logger.error.assert_called_with(
            "Failed to setup proxy certificates", {"error": "Invalid certificate"}
        )

        # Cleanup
        opencti_api_client._PROXY_CERT_BUNDLE = None
        opencti_api_client._PROXY_CERT_DIR = None

    def test_setup_proxy_certificates_exception_handling(self, api_client):
        """Test _setup_proxy_certificates raises exception on error."""
        from pycti.api import opencti_api_client

        # Reset global state to ensure clean test
        opencti_api_client._PROXY_CERT_BUNDLE = None
        opencti_api_client._PROXY_CERT_DIR = None

        with patch.dict(os.environ, {"HTTPS_CA_CERTIFICATES": self.SAMPLE_CERTIFICATE}):
            with patch("tempfile.mkdtemp", side_effect=Exception("Mock error")):
                with pytest.raises(Exception, match="Mock error"):
                    api_client._setup_proxy_certificates()

        # Should log error before raising
        api_client.app_logger.error.assert_called_with(
            "Failed to setup proxy certificates", {"error": "Mock error"}
        )

        # Cleanup
        opencti_api_client._PROXY_CERT_BUNDLE = None
        opencti_api_client._PROXY_CERT_DIR = None

    def test_cleanup_proxy_certificates_successful(self):
        """Test _cleanup_proxy_certificates successfully removes temporary directory."""
        from pycti.api import opencti_api_client

        # Create a real temporary directory
        temp_dir = tempfile.mkdtemp(prefix="opencti_test_")
        opencti_api_client._PROXY_CERT_DIR = temp_dir

        # Call cleanup
        opencti_api_client._cleanup_proxy_certificates()

        # Verify directory was removed and _PROXY_CERT_DIR reset
        assert not os.path.exists(temp_dir)
        assert opencti_api_client._PROXY_CERT_DIR is None

    @patch("pycti.api.opencti_api_client.shutil.rmtree")
    @patch("pycti.api.opencti_api_client.os.path.exists")
    def test_cleanup_proxy_certificates_with_error(self, mock_exists, mock_rmtree):
        """Test _cleanup_proxy_certificates handles errors during removal."""
        from pycti.api import opencti_api_client

        temp_dir = "/tmp/opencti_test_certs"
        opencti_api_client._PROXY_CERT_DIR = temp_dir
        mock_exists.return_value = True
        mock_rmtree.side_effect = OSError("Permission denied")

        # Call cleanup - should not raise exception
        opencti_api_client._cleanup_proxy_certificates()

        # Should reset _PROXY_CERT_DIR
        assert opencti_api_client._PROXY_CERT_DIR is None

    def test_singleton_behavior_multiple_instances(self):
        """Test that multiple instances reuse the same certificate bundle."""
        from pycti.api import opencti_api_client

        # Reset global state
        opencti_api_client._PROXY_CERT_BUNDLE = None
        opencti_api_client._PROXY_CERT_DIR = None

        with patch.dict(os.environ, {"HTTPS_CA_CERTIFICATES": self.SAMPLE_CERTIFICATE}):
            with patch("tempfile.mkdtemp", return_value="/tmp/test_certs"):
                with patch("builtins.open", mock_open()):
                    with patch("os.path.exists", return_value=True):
                        # Create first instance
                        client1 = OpenCTIApiClient(
                            url="http://localhost:4000",
                            token="test-token",
                            ssl_verify=False,
                            perform_health_check=False,
                        )

                        # Verify certificate bundle was created
                        assert opencti_api_client._PROXY_CERT_BUNDLE is not None
                        first_bundle = opencti_api_client._PROXY_CERT_BUNDLE
                        assert client1.ssl_verify == first_bundle

                        # Create second instance
                        client2 = OpenCTIApiClient(
                            url="http://localhost:4000",
                            token="test-token2",
                            ssl_verify=False,
                            perform_health_check=False,
                        )

                        # Verify same bundle is reused
                        assert opencti_api_client._PROXY_CERT_BUNDLE == first_bundle
                        assert client2.ssl_verify == first_bundle

        # Cleanup
        opencti_api_client._PROXY_CERT_BUNDLE = None
        opencti_api_client._PROXY_CERT_DIR = None
