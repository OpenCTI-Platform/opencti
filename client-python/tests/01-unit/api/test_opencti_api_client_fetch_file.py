from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient


class TestFetchOpenctiFileById:
    """Test OpenCTIApiClient.fetch_opencti_file_by_id functionality."""

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
            client.app_logger = MagicMock()
            return client

    def test_builds_url_from_base_url_and_file_id(self, api_client):
        """The storage URL should be derived from base_url, not api_url string replace."""
        captured_calls = []

        def fake_fetch_opencti_file(fetch_uri, binary=False, serialize=False):
            captured_calls.append((fetch_uri, binary, serialize))
            return "content"

        with patch.object(
            api_client, "fetch_opencti_file", side_effect=fake_fetch_opencti_file
        ):
            result = api_client.fetch_opencti_file_by_id("file-id-123")

        assert result == "content"
        assert captured_calls == [
            ("http://localhost:4000/storage/get/file-id-123", False, False)
        ]

    def test_passes_binary_and_serialize_flags_through(self, api_client):
        """binary and serialize flags must be forwarded unchanged."""
        with patch.object(
            api_client, "fetch_opencti_file", return_value="Zm9v"
        ) as mocked_fetch:
            result = api_client.fetch_opencti_file_by_id(
                "file-id-123", binary=True, serialize=True
            )

        assert result == "Zm9v"
        mocked_fetch.assert_called_once_with(
            "http://localhost:4000/storage/get/file-id-123",
            binary=True,
            serialize=True,
        )

    def test_returns_none_on_failed_fetch(self, api_client):
        """When the underlying fetch fails, None is propagated as-is."""
        with patch.object(api_client, "fetch_opencti_file", return_value=None):
            result = api_client.fetch_opencti_file_by_id("missing-file-id")

        assert result is None

    def test_uses_real_http_layer_and_honors_response_status(self, api_client):
        """End-to-end (mocking only session.get) to verify delegation to fetch_opencti_file."""
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.content = b"binary-data"
        mock_response.text = "text-data"

        with patch.object(
            api_client.session, "get", return_value=mock_response
        ) as mocked_get:
            result = api_client.fetch_opencti_file_by_id("file-id-456")

        assert result == "text-data"
        called_url = mocked_get.call_args[0][0]
        assert called_url == "http://localhost:4000/storage/get/file-id-456"

    def test_uses_real_http_layer_on_failed_response(self, api_client):
        """A non-ok HTTP response should result in None and a warning log."""
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 404

        with patch.object(api_client.session, "get", return_value=mock_response):
            result = api_client.fetch_opencti_file_by_id("missing-file-id")

        assert result is None
        api_client.app_logger.warning.assert_called_with(
            "Failed to fetch file",
            {
                "uri": "http://localhost:4000/storage/get/missing-file-id",
                "status_code": 404,
            },
        )

    def test_builds_url_without_double_slash_when_url_has_trailing_slash(self):
        """A trailing slash on the platform url must not produce a double slash
        in the generated storage url."""
        with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
            client = OpenCTIApiClient(
                url="http://localhost:4000/",
                token="test-token",
                ssl_verify=False,
                perform_health_check=False,
            )
            client.app_logger = MagicMock()

        with patch.object(
            client, "fetch_opencti_file", return_value="content"
        ) as mocked_fetch:
            client.fetch_opencti_file_by_id("file-id-123")

        mocked_fetch.assert_called_once_with(
            "http://localhost:4000/storage/get/file-id-123",
            binary=False,
            serialize=False,
        )

    def test_passes_file_id_with_special_characters_unchanged(self, api_client):
        """A file id that looks like a path (with spaces/subfolders) must be
        forwarded as-is, with no accidental encoding."""
        file_id = "import/Artifact/some-id/my file (v2).bin"

        with patch.object(
            api_client, "fetch_opencti_file", return_value="content"
        ) as mocked_fetch:
            api_client.fetch_opencti_file_by_id(file_id, binary=True, serialize=True)

        mocked_fetch.assert_called_once_with(
            f"http://localhost:4000/storage/get/{file_id}",
            binary=True,
            serialize=True,
        )

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:4000",
            "https://opencti.example.com",
            "http://192.168.1.10:4000",
        ],
    )
    def test_url_equivalent_to_legacy_replace_based_construction(self, url):
        """Characterization test: the new base_url-based storage url must be
        byte-identical to the old api_url.replace("graphql", "storage/get/")
        construction it replaces at the opencti_stix2.py call sites."""
        with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
            client = OpenCTIApiClient(
                url=url,
                token="test-token",
                ssl_verify=False,
                perform_health_check=False,
            )
            client.app_logger = MagicMock()

        file_id = "some-file-id"
        legacy_url = client.api_url.replace("graphql", "storage/get/") + file_id

        with patch.object(
            client, "fetch_opencti_file", return_value="content"
        ) as mocked_fetch:
            client.fetch_opencti_file_by_id(file_id)

        new_url = mocked_fetch.call_args[0][0]
        assert new_url == legacy_url
