"""Tests for the work error that ListenQueue._data_handler reports when the
message callback raises.

A standard error (class-level ``code`` and ``criticity``, like the connectors
SDK errors) is reported as a JSON message the OpenCTI front end classifies;
any other exception keeps its plain text. This holds for every connector type
served by the queue listener.
"""

import json
from enum import IntEnum
from unittest.mock import MagicMock

import pytest

from pycti.connector.opencti_connector_helper import ListenQueue

WORK_ID = "work-1"
ENTITY_ID = "indicator--00000000-0000-4000-8000-000000000000"


class Criticity(IntEnum):
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class ApiTimeoutError(Exception):
    code = "api.timeout"
    criticity = Criticity.ERROR


class RejectedError(Exception):
    code = "target.rejected"
    criticity = Criticity.WARNING


def _build_listen_queue(connect_type, error):
    listen_queue = ListenQueue.__new__(ListenQueue)
    listen_queue.helper = MagicMock()
    listen_queue.helper.connect_type = connect_type
    listen_queue.helper.api.stix2.get_reader.return_value = lambda **_: {
        "standard_id": ENTITY_ID
    }
    listen_queue.connector_applicant_id = "test-applicant"
    listen_queue.callback = MagicMock(side_effect=error)
    return listen_queue


def _build_message(connect_type):
    event = {}
    if connect_type == "INTERNAL_ENRICHMENT":
        event = {
            "entity_id": ENTITY_ID,
            "entity_type": "Indicator",
            "stix_entity": json.dumps({"id": ENTITY_ID}),
            "stix_objects": json.dumps([{"id": ENTITY_ID}]),
        }
    return {"event": event, "internal": {"work_id": WORK_ID, "applicant_id": None}}


def _reported_error(connect_type, error):
    listen_queue = _build_listen_queue(connect_type, error)
    listen_queue._data_handler(_build_message(connect_type))
    listen_queue.callback.assert_called_once()
    to_processed = listen_queue.helper.api.work.to_processed
    to_processed.assert_called_once()
    work_id, message, in_error = to_processed.call_args.args
    assert work_id == WORK_ID
    assert in_error is True
    return message


CONNECTOR_TYPES = ["INTERNAL_ENRICHMENT", "INTERNAL_IMPORT_FILE"]


@pytest.mark.parametrize("connect_type", CONNECTOR_TYPES)
def test_error_criticity_is_reported_as_critical(connect_type):
    message = _reported_error(connect_type, ApiTimeoutError("Read timed out"))
    assert json.loads(message) == {
        "name": "INTERNAL_SERVER_ERROR",
        "error_message": "[api.timeout] Read timed out",
    }


@pytest.mark.parametrize("connect_type", CONNECTOR_TYPES)
def test_warning_criticity_is_reported_as_warning(connect_type):
    message = _reported_error(connect_type, RejectedError("Item refused"))
    assert json.loads(message) == {
        "name": "VALIDATION_ERROR",
        "error_message": "[target.rejected] Item refused",
    }


@pytest.mark.parametrize("connect_type", CONNECTOR_TYPES)
def test_plain_exception_is_reported_as_its_text(connect_type):
    message = _reported_error(connect_type, ValueError("Connection refused"))
    assert message == "Connection refused"


def test_enrichment_error_before_the_callback_is_reported_as_its_text():
    listen_queue = _build_listen_queue("INTERNAL_ENRICHMENT", None)
    message = _build_message("INTERNAL_ENRICHMENT")
    del message["event"]["entity_id"]
    listen_queue._data_handler(message)
    listen_queue.callback.assert_not_called()
    listen_queue.helper.api.work.to_processed.assert_called_once_with(
        WORK_ID, "Internal enrichment must be based on a specific id", True
    )
