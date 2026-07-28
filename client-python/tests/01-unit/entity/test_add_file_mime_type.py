"""Unit tests covering the mime_type inference logic used by file-upload
methods on the entity helper classes, after the switch from `python-magic`
to the standard library `mimetypes` module (see issue #13517).

All these classes only need a mocked `opencti` client (no live server, no
network I/O, no libmagic).
"""

from unittest.mock import MagicMock, patch

import pytest

from pycti.entities.opencti_external_reference import ExternalReference
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable
from pycti.entities.opencti_stix_domain_object import StixDomainObject


@pytest.fixture
def opencti_mock():
    mock = MagicMock()
    mock.query.return_value = {"data": {"artifactImport": {}}}
    mock.process_multiple_fields.side_effect = lambda x: x
    return mock


class TestExternalReferenceAddFile:
    """ExternalReference.add_file mime_type resolution."""

    def test_happy_path_known_extension_infers_mime_type_from_filename(
        self, opencti_mock, tmp_path
    ):
        file_path = tmp_path / "report.pdf"
        file_path.write_bytes(b"fake-pdf-content")

        ExternalReference(opencti_mock).add_file(
            id="external-reference--id", file_name=str(file_path)
        )

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/pdf"

    def test_json_extension_still_forces_application_json(self, opencti_mock, tmp_path):
        file_path = tmp_path / "bundle.json"
        file_path.write_text('{"type": "bundle"}')

        ExternalReference(opencti_mock).add_file(
            id="external-reference--id", file_name=str(file_path)
        )

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/json"

    def test_unknown_extension_falls_back_to_octet_stream(self, opencti_mock, tmp_path):
        """Worst case: unrecognized extension must not raise and must default
        to a generic binary mime type."""
        file_path = tmp_path / "payload.unknownext"
        file_path.write_bytes(b"\x00\x01binary-ish")

        ExternalReference(opencti_mock).add_file(
            id="external-reference--id", file_name=str(file_path)
        )

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/octet-stream"

    def test_provided_data_skips_filename_inference(self, opencti_mock):
        """Edge case: when data is provided, no filesystem access or mime
        guessing should happen; the caller-provided mime_type is preserved."""
        with patch(
            "pycti.entities.opencti_external_reference.mimetypes.guess_type"
        ) as mocked_guess_type:
            ExternalReference(opencti_mock).add_file(
                id="external-reference--id",
                file_name="does-not-need-to-exist.bin",
                data=b"raw-bytes",
                mime_type="application/custom",
            )

        mocked_guess_type.assert_not_called()
        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/custom"

    def test_missing_required_params_returns_none(self, opencti_mock):
        """Pre-existing behavior must be preserved when required params are missing."""
        result = ExternalReference(opencti_mock).add_file(file_name="only-name.txt")

        assert result is None
        opencti_mock.query.assert_not_called()


class TestStixDomainObjectAddFile:
    """StixDomainObject.add_file mime_type resolution (smoke coverage: the
    inference block is identical to ExternalReference.add_file)."""

    def test_happy_path_known_extension_infers_mime_type_from_filename(
        self, opencti_mock, tmp_path
    ):
        file_path = tmp_path / "diagram.png"
        file_path.write_bytes(b"\x89PNG\r\n\x1a\nfake")

        StixDomainObject(opencti_mock).add_file(
            id="intrusion-set--id", file_name=str(file_path)
        )

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "image/png"

    def test_missing_extension_falls_back_to_octet_stream(self, opencti_mock, tmp_path):
        file_path = tmp_path / "README"
        file_path.write_text("no extension here")

        StixDomainObject(opencti_mock).add_file(
            id="intrusion-set--id", file_name=str(file_path)
        )

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/octet-stream"


class TestStixCyberObservableAddFile:
    """StixCyberObservable.add_file mime_type resolution (smoke coverage)."""

    def test_happy_path_known_extension_infers_mime_type_from_filename(
        self, opencti_mock, tmp_path
    ):
        file_path = tmp_path / "notes.txt"
        file_path.write_text("plain text content")

        StixCyberObservable(opencti_mock).add_file(
            id="observable--id", file_name=str(file_path)
        )

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "text/plain"

    def test_unknown_extension_falls_back_to_octet_stream(self, opencti_mock, tmp_path):
        file_path = tmp_path / "artifact.xyz123"
        file_path.write_bytes(b"binary")

        StixCyberObservable(opencti_mock).add_file(
            id="observable--id", file_name=str(file_path)
        )

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/octet-stream"


class TestStixCyberObservableUploadArtifact:
    """StixCyberObservable.upload_artifact mime_type resolution (second,
    independent call site reusing the same inference block)."""

    def test_happy_path_known_extension_infers_mime_type_from_filename(
        self, opencti_mock, tmp_path
    ):
        file_path = tmp_path / "sample.pdf"
        file_path.write_bytes(b"fake-pdf-content")

        StixCyberObservable(opencti_mock).upload_artifact(file_name=str(file_path))

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/pdf"

    def test_unknown_extension_falls_back_to_octet_stream(self, opencti_mock, tmp_path):
        file_path = tmp_path / "sample.unknownext"
        file_path.write_bytes(b"binary")

        StixCyberObservable(opencti_mock).upload_artifact(file_name=str(file_path))

        _, _, mime_type = opencti_mock.file.call_args[0]
        assert mime_type == "application/octet-stream"
