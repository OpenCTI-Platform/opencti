import pytest

from pycti.api.opencti_api_client import File
from pycti.entities.opencti_external_reference import ExternalReference
from pycti.entities.opencti_stix_cyber_observable import StixCyberObservable
from pycti.entities.opencti_stix_domain_object import StixDomainObject


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
