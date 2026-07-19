import base64

import pytest

from pycti.api.opencti_api_client import File
from pycti.entities.opencti_external_reference import ExternalReference
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable
from pycti.entities.opencti_stix_domain_object import StixDomainObject
from pycti.utils.opencti_file_utils import BASE64_FILE_MEMORY_THRESHOLD


class _NullLogger:
    def info(self, *args, **kwargs):
        del args, kwargs

    def error(self, *args, **kwargs):
        raise AssertionError("unexpected error log")


class _RetainingClient:
    def __init__(self):
        self.app_logger = _NullLogger()
        self.retained_uploads = []

    @staticmethod
    def file(name, data, mime):
        return File(name, data, mime)

    def query(self, query, variables):
        del query
        self.retained_uploads.append(variables["file"])
        return {"data": {"artifactImport": {"id": "artifact--1"}}}

    @staticmethod
    def process_multiple_fields(data):
        return data


class _ArtifactCreateClient(_RetainingClient):
    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    def query(self, query, variables):
        if "StixCyberObservableAdd" in query:
            return {
                "data": {
                    "stixCyberObservableAdd": {
                        "id": "artifact--1",
                        "entity_type": "Artifact",
                    }
                }
            }
        return super().query(query, variables)


@pytest.mark.parametrize(
    ("entity_class", "method_name", "kwargs"),
    [
        (ExternalReference, "add_file", {"id": "external-reference--1"}),
        (StixDomainObject, "add_file", {"id": "report--1"}),
        (StixCyberObservable, "add_file", {"id": "artifact--1"}),
        (StixCyberObservable, "upload_artifact", {}),
    ],
)
def test_entity_path_upload_helpers_close_owned_file_handles(
    tmp_path, entity_class, method_name, kwargs
):
    upload_path = tmp_path / "payload.json"
    upload_path.write_bytes(b"payload")
    client = _RetainingClient()
    entity = entity_class(client)

    getattr(entity, method_name)(file_name=str(upload_path), **kwargs)

    assert client.retained_uploads[-1].data.closed


@pytest.mark.parametrize(
    ("entity_class", "method_name", "kwargs"),
    [
        (ExternalReference, "add_file", {"id": "external-reference--1"}),
        (StixDomainObject, "add_file", {"id": "report--1"}),
        (StixCyberObservable, "add_file", {"id": "artifact--1"}),
        (StixCyberObservable, "upload_artifact", {}),
    ],
)
def test_entity_upload_helpers_leave_caller_owned_file_handles_open(
    tmp_path, entity_class, method_name, kwargs
):
    upload_path = tmp_path / "payload.json"
    upload_path.write_bytes(b"payload")
    client = _RetainingClient()
    entity = entity_class(client)

    with upload_path.open("rb") as data:
        getattr(entity, method_name)(file_name=str(upload_path), data=data, **kwargs)

        assert not data.closed


def test_artifact_payload_upload_closes_large_decoded_stream():
    payload = b"x" * (BASE64_FILE_MEMORY_THRESHOLD + 1)
    client = _ArtifactCreateClient()
    entity = StixCyberObservable(client)

    entity.create(
        observableData={
            "type": "artifact",
            "mime_type": "application/octet-stream",
            "payload_bin": base64.b64encode(payload).decode("ascii"),
        }
    )

    assert client.retained_uploads[-1].data.closed
