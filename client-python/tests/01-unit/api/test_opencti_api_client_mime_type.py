"""Unit tests covering the mime_type inference logic used by file-upload
methods on OpenCTIApiClient, after the switch from `python-magic` to the
standard library `mimetypes` module (see issue #13517).
"""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient


@pytest.fixture
def api_client():
    """Create an API client instance without performing health check or any
    real network I/O."""
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
    client.app_logger = MagicMock()
    return client


class TestUploadFileMimeType:
    """OpenCTIApiClient.upload_file mime_type resolution."""

    def test_happy_path_known_extension_infers_mime_type_from_filename(
        self, api_client, tmp_path
    ):
        """A common, well-known extension must resolve to its expected mime type."""
        file_path = tmp_path / "report.pdf"
        file_path.write_bytes(b"%PDF-1.4 fake content")

        with patch.object(
            api_client, "query", return_value={"ok": True}
        ) as mocked_query:
            api_client.upload_file(file_name=str(file_path))

        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "application/pdf"

    def test_json_extension_still_forces_application_json(self, api_client, tmp_path):
        """The pre-existing `.json` special-case must remain untouched and take
        precedence over mimetypes.guess_type."""
        file_path = tmp_path / "bundle.json"
        file_path.write_text('{"type": "bundle"}')

        with patch.object(
            api_client, "query", return_value={"ok": True}
        ) as mocked_query:
            api_client.upload_file(file_name=str(file_path))

        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "application/json"

    def test_unknown_extension_falls_back_to_octet_stream(self, api_client, tmp_path):
        """Worst case: an unrecognized/unknown extension must not crash and must
        fall back to a sane default mime type instead of returning None."""
        file_path = tmp_path / "payload.unknownext"
        file_path.write_bytes(b"\x00\x01binary-ish-data")

        with patch.object(
            api_client, "query", return_value={"ok": True}
        ) as mocked_query:
            api_client.upload_file(file_name=str(file_path))

        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "application/octet-stream"

    def test_missing_extension_falls_back_to_octet_stream(self, api_client, tmp_path):
        """Worst case: a filename without any extension at all."""
        file_path = tmp_path / "README"
        file_path.write_text("no extension here")

        with patch.object(
            api_client, "query", return_value={"ok": True}
        ) as mocked_query:
            api_client.upload_file(file_name=str(file_path))

        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "application/octet-stream"

    def test_provided_data_and_mime_type_skip_filename_inference(self, api_client):
        """Edge case: when `data` is already provided by the caller, mime_type
        detection must not run at all (no filesystem access, no guessing) and
        the caller-provided mime_type must be preserved unchanged."""
        with patch(
            "pycti.api.opencti_api_client.mimetypes.guess_type"
        ) as mocked_guess_type, patch.object(
            api_client, "query", return_value={"ok": True}
        ) as mocked_query:
            api_client.upload_file(
                file_name="does-not-need-to-exist.bin",
                data=b"raw-bytes",
                mime_type="application/custom",
            )

        mocked_guess_type.assert_not_called()
        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "application/custom"

    def test_missing_file_name_returns_none_and_logs_error(self, api_client):
        """Pre-existing behavior must be preserved: no file_name -> None + error log."""
        result = api_client.upload_file(data=b"raw-bytes")

        assert result is None
        api_client.app_logger.error.assert_called_once()


class TestUploadPendingFileMimeType:
    """OpenCTIApiClient.upload_pending_file mime_type resolution."""

    def test_happy_path_known_extension_infers_mime_type_from_filename(
        self, api_client, tmp_path
    ):
        file_path = tmp_path / "screenshot.png"
        file_path.write_bytes(b"\x89PNG\r\n\x1a\nfake")

        with patch.object(
            api_client, "query", return_value={"ok": True}
        ) as mocked_query:
            api_client.upload_pending_file(file_name=str(file_path))

        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "image/png"

    def test_unknown_extension_falls_back_to_octet_stream(self, api_client, tmp_path):
        file_path = tmp_path / "artifact.xyz123"
        file_path.write_bytes(b"binary")

        with patch.object(
            api_client, "query", return_value={"ok": True}
        ) as mocked_query:
            api_client.upload_pending_file(file_name=str(file_path))

        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "application/octet-stream"

    def test_no_libmagic_import_error_possible(self, api_client, tmp_path):
        """Regression guard: uploading must not require the (removed)
        `magic`/libmagic native dependency to be importable."""
        file_path = tmp_path / "notes.txt"
        file_path.write_text("hello")

        with patch.dict("sys.modules", {"magic": None}):
            with patch.object(
                api_client, "query", return_value={"ok": True}
            ) as mocked_query:
                api_client.upload_pending_file(file_name=str(file_path))

        query_vars = mocked_query.call_args[0][1]
        assert query_vars["file"].mime == "text/plain"
