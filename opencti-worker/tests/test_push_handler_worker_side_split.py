"""Unit test covering the fallback path in PushHandler.handle_message where a
multi-object bundle arrives without `no_split`, forcing the worker to split it
itself (the case Proposal B's backend pre-splitting is meant to eliminate).
Asserts the new warning log fires with the fields needed to trace the
offending connector/work/bundle.
"""

import base64
import json
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from opencti_worker.push_handler import PushHandler


def make_push_handler() -> PushHandler:
    handler = PushHandler.__new__(PushHandler)
    handler.logger = MagicMock()
    handler.api = MagicMock()
    handler.connector_id = "connector-under-test"
    handler.push_exchange = "push-exchange"
    handler.listen_exchange = "listen-exchange"
    handler.push_routing = "push-routing"
    handler.dead_letter_routing = "dead-letter-routing"
    handler.pika_parameters = MagicMock()
    handler.bundles_global_counter = MagicMock()
    handler.bundles_processing_time_gauge = MagicMock()
    handler.objects_max_refs = 0
    return handler


def encode_message(bundle: dict, **extra) -> str:
    content_json = json.dumps(bundle)
    content_b64 = base64.b64encode(content_json.encode("utf-8")).decode("utf-8")
    data = {"type": "bundle", "content": content_b64, **extra}
    return json.dumps(data)


@contextmanager
def fake_blocking_connection(*_args, **_kwargs):
    channel = MagicMock()
    channel.__enter__.return_value = channel
    channel.__exit__.return_value = False
    connection = MagicMock()
    connection.channel.return_value = channel
    yield connection


class TestWorkerSideSplitWarning:
    def test_warns_with_connector_work_and_bundle_context_when_splitting_in_worker(
        self,
    ):
        handler = make_push_handler()
        bundle = {
            "id": "bundle--test-id",
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1"},
                {"type": "malware", "id": "malware--2"},
            ],
        }
        handler.api.work.add_expectations.return_value = True

        with patch("opencti_worker.push_handler.pika.BlockingConnection", fake_blocking_connection):
            result = handler.handle_message(
                encode_message(bundle, work_id="work-1")
            )

        assert result == "ack"
        warning_calls = [
            call
            for call in handler.logger.warning.call_args_list
            if call.args[0] == "Received a multi-object bundle without no_split, splitting in worker"
        ]
        assert len(warning_calls) == 1
        _, extra = warning_calls[0].args
        assert extra["connector_id"] == "connector-under-test"
        assert extra["work_id"] == "work-1"
        assert extra["object_count"] == 2

    def test_does_not_warn_when_bundle_is_pre_split(self):
        handler = make_push_handler()
        bundle = {"type": "bundle", "objects": [{"type": "malware", "id": "malware--1"}]}
        handler.api.stix2.import_bundle_from_json.return_value = ([], [])

        result = handler.handle_message(encode_message(bundle, no_split=True))

        assert result == "ack"
        for call in handler.logger.warning.call_args_list:
            assert call.args[0] != "Received a multi-object bundle without no_split, splitting in worker"
