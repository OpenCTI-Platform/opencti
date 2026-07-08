import json

import pytest

from pycti.entities.opencti_feedback import Feedback
from pycti.entities.opencti_task import Task


class _CaptureLogger:
    def __init__(self):
        self.records = []

    def info(self, message, meta=None):
        self.records.append((message, meta() if callable(meta) else meta))

    def error(self, *args, **kwargs):
        raise AssertionError("unexpected error log")


class _FakeClient:
    def __init__(self, result):
        self.app_logger = _CaptureLogger()
        self.result = result

    def query(self, query, variables):
        return self.result

    @staticmethod
    def process_multiple_fields(data):
        return data


@pytest.mark.parametrize(
    ("entity_class", "result", "message"),
    [
        (
            Feedback,
            {"data": {"stixDomainObjectEdit": {"fieldPatch": {"id": "feedback--1"}}}},
            "Updating Feedback",
        ),
        (
            Task,
            {"data": {"taskFieldPatch": {"id": "task--1"}}},
            "Updating Task",
        ),
    ],
)
def test_update_field_preserves_info_log_metadata(entity_class, result, message):
    client = _FakeClient(result)
    entity = entity_class(client)
    update_input = [{"key": "name", "value": ["updated"], "operation": "replace"}]

    entity.update_field(id="entity--1", input=update_input)

    assert client.app_logger.records == [
        (
            message,
            {"data": json.dumps({"id": "entity--1", "input": update_input})},
        )
    ]
