"""Unit tests of PushHandler.handle_batch: messages received together are imported as one bundle when they share
their context and the platform has the lock-free batch import, and one by one otherwise.
"""

import base64
import json
import time
from unittest.mock import MagicMock

import pytest

from push_handler import (
    MAX_GROUP_OBJECTS,
    MAX_MISSING_REF_DEFERRALS,
    MISSING_REF_DEFERRAL_DELAYS,
    PushHandler,
)


def make_push_handler(supported=True) -> PushHandler:
    handler = PushHandler.__new__(PushHandler)
    handler.logger = MagicMock()
    handler.api = MagicMock()
    handler.api.stix2.import_bundle.return_value = ([], [])
    handler.connector_id = "connector-under-test"
    handler.listen_exchange = "listen-exchange"
    handler.dead_letter_routing = "dead-letter-routing"
    handler.pika_parameters = MagicMock()
    handler.bundles_global_counter = MagicMock()
    handler.bundles_processing_time_gauge = MagicMock()
    handler.objects_max_refs = 0
    handler._batch_supported = supported
    handler._batch_checked_at = 0.0
    handler.handle_message = MagicMock(return_value="ack")
    return handler


def message(objects, **extra) -> str:
    bundle = {"type": "bundle", "id": "bundle--1", "objects": objects}
    content = base64.b64encode(json.dumps(bundle).encode("utf-8")).decode("utf-8")
    return json.dumps({"type": "bundle", "content": content, "work_id": "w1", **extra})


def malware(i):
    return {"type": "malware", "id": f"malware--{i}", "name": f"m{i}"}


class TestHandleBatch:
    def test_imports_messages_of_one_context_as_one_bundle(self):
        handler = make_push_handler()
        bodies = [message([malware(i)]) for i in range(3)]
        assert handler.handle_batch(bodies) == ["ack", "ack", "ack"]
        handler.api.stix2.import_bundle.assert_called_once()
        bundle = handler.api.stix2.import_bundle.call_args.args[0]
        assert [o["id"] for o in bundle["objects"]] == [
            "malware--0",
            "malware--1",
            "malware--2",
        ]
        handler.handle_message.assert_not_called()

    def test_batch_mode_is_on_only_during_the_import(self):
        handler = make_push_handler()
        seen = []
        handler.api.stix2.import_bundle.side_effect = lambda *a, **k: (
            seen.append(handler.api.batch_import_enabled) or ([], [])
        )
        handler.handle_batch([message([malware(i)]) for i in range(2)])
        assert seen == [True]
        assert handler.api.batch_import_enabled is False

    def test_another_context_starts_another_group(self):
        handler = make_push_handler()
        bodies = [
            message([malware(0)]),
            message([malware(1)]),
            message([malware(2)], work_id="w2"),
            message([malware(3)], work_id="w2"),
        ]
        handler.handle_batch(bodies)
        assert handler.api.stix2.import_bundle.call_count == 2

    def test_drafts_go_one_by_one(self):
        handler = make_push_handler()
        bodies = [
            message([malware(0)], draft_id="d1"),
            message([malware(1)], draft_id="d1"),
        ]
        handler.handle_batch(bodies)
        assert handler.handle_message.call_count == 2
        handler.api.stix2.import_bundle.assert_not_called()

    def test_a_single_object_alone_goes_through_the_batch_import(self):
        handler = make_push_handler()
        handler.api.stix2.last_batch_deferred = []
        seen = []
        handler.api.stix2.import_bundle.side_effect = lambda *a, **k: (
            seen.append(handler.api.defer_missing_references) or ([], [])
        )
        assert handler.handle_batch([message([malware(0)])]) == ["ack"]
        handler.handle_message.assert_not_called()
        assert seen == [True]  # so that a missing reference can be sent again

    def test_a_repeated_object_is_imported_on_its_own(self):
        handler = make_push_handler()
        bodies = [message([malware(0)]), message([malware(1)]), message([malware(0)])]
        assert handler.handle_batch(bodies) == ["ack", "ack", "ack"]
        bundle = handler.api.stix2.import_bundle.call_args.args[0]
        assert len(bundle["objects"]) == 2
        handler.handle_message.assert_called_once_with(bodies[2])

    def test_groups_hold_at_most_max_objects(self):
        handler = make_push_handler()
        half = MAX_GROUP_OBJECTS // 2
        bodies = [message([malware(f"{m}-{i}") for i in range(half)]) for m in range(3)]
        handler.handle_batch(bodies)
        sizes = [
            len(c.args[0]["objects"])
            for c in handler.api.stix2.import_bundle.call_args_list
        ]
        assert sizes == [2 * half, half]

    def test_without_platform_support_every_message_goes_one_by_one(self):
        handler = make_push_handler(supported=False)
        handler._batch_checked_at = float("inf")  # no new check
        bodies = [message([malware(i)]) for i in range(3)]
        handler.handle_batch(bodies)
        assert handler.handle_message.call_count == 3
        handler.api.stix2.import_bundle.assert_not_called()

    def test_a_failed_group_falls_back_to_one_by_one(self):
        handler = make_push_handler()
        handler.api.stix2.import_bundle.side_effect = RuntimeError("platform down")
        bodies = [message([malware(i)]) for i in range(2)]
        assert handler.handle_batch(bodies) == ["ack", "ack"]
        assert handler.handle_message.call_count == 2


class TestMissingReferenceDeferral:
    """Items whose references another worker is still importing go to the end of the queue again, a few times,
    instead of waiting in the worker."""

    @staticmethod
    def handler_with_queue():
        handler = make_push_handler()
        handler.push_exchange = "push-exchange"
        handler.push_routing = "push-routing"
        handler.send_bundle_to_specific_queue = MagicMock()
        return handler

    def test_deferred_items_go_back_to_the_queue_as_one_message(self, monkeypatch):
        handler = self.handler_with_queue()
        monkeypatch.setattr("push_handler.pika.BlockingConnection", MagicMock())
        handler.api.stix2.last_batch_deferred = [malware(1), malware(2)]
        handler.handle_batch([message([malware(i)]) for i in range(3)])
        handler.send_bundle_to_specific_queue.assert_called_once()
        _, exchange, routing, data, bundle, _ = (
            handler.send_bundle_to_specific_queue.call_args.args
        )
        assert (exchange, routing) == ("push-exchange", "push-routing")
        assert data["missing_ref_deferrals"] == 1 and data["no_split"] is True
        assert data["work_id"] == "w1"
        assert data["missing_ref_retry_at"] == pytest.approx(
            time.time() + MISSING_REF_DEFERRAL_DELAYS[0], abs=1
        )
        assert [o["id"] for o in bundle["objects"]] == ["malware--1", "malware--2"]

    def test_a_message_back_before_its_delay_waits_for_the_rest(self, monkeypatch):
        slept = []
        monkeypatch.setattr("push_handler.time.sleep", slept.append)
        handler = make_push_handler()
        handler.api.stix2.last_batch_deferred = []
        retry_at = time.time() + 3
        handler.handle_batch(
            [
                message(
                    [malware(i)], missing_ref_deferrals=1, missing_ref_retry_at=retry_at
                )
                for i in range(2)
            ]
        )
        assert len(slept) == 1 and 2 < slept[0] <= 3
        slept.clear()
        handler.handle_batch(
            [
                message([malware(i)], missing_ref_deferrals=1, missing_ref_retry_at=1)
                for i in range(2)
            ]
        )
        assert slept == []  # its delay has passed: no wait

    def test_messages_not_due_go_back_to_the_queue_when_others_are_due(
        self, monkeypatch
    ):
        slept = []
        monkeypatch.setattr("push_handler.time.sleep", slept.append)
        handler = self.handler_with_queue()
        monkeypatch.setattr("push_handler.pika.BlockingConnection", MagicMock())
        handler.api.stix2.last_batch_deferred = []
        retry_at = time.time() + 8
        results = handler.handle_batch(
            [
                message([malware(0)]),
                message(
                    [malware(1)], missing_ref_deferrals=3, missing_ref_retry_at=retry_at
                ),
                message([malware(2)]),
            ]
        )
        assert slept == []  # the new messages do not wait for the one sent again
        assert results == ["ack", "ack", "ack"]
        imported = handler.api.stix2.import_bundle.call_args.args[0]["objects"]
        assert [o["id"] for o in imported] == ["malware--0", "malware--2"]
        handler.send_bundle_to_specific_queue.assert_called_once()
        _, _, _, data, bundle, _ = handler.send_bundle_to_specific_queue.call_args.args
        assert data["missing_ref_deferrals"] == 3
        assert data["missing_ref_retry_at"] == retry_at  # as it was: not one more round
        assert [o["id"] for o in bundle["objects"]] == ["malware--1"]

    def test_a_single_item_sent_again_is_imported_in_batch_mode(self):
        handler = make_push_handler()
        handler.batch_import_supported = MagicMock(return_value=True)
        handler.api.stix2.last_batch_deferred = []
        seen = []
        handler.api.stix2.import_bundle_from_json.side_effect = lambda *a, **k: (
            seen.append(
                (handler.api.batch_import_enabled, handler.api.defer_missing_references)
            )
            or ([], [])
        )
        PushHandler.handle_message(
            handler, message([malware(0)], missing_ref_deferrals=1, no_split=True)
        )
        assert seen == [(True, True)]

    def test_deferral_is_on_during_the_import_until_the_limit(self):
        for deferrals, expected in ((0, True), (MAX_MISSING_REF_DEFERRALS, False)):
            handler = make_push_handler()
            handler.api.stix2.last_batch_deferred = []
            seen = []
            handler.api.stix2.import_bundle.side_effect = lambda *a, **k: (
                seen.append(handler.api.defer_missing_references) or ([], [])
            )
            handler.handle_batch(
                [
                    message([malware(i)], missing_ref_deferrals=deferrals)
                    for i in range(2)
                ]
            )
            assert seen == [expected]
            assert handler.api.defer_missing_references is False

    def test_messages_sent_again_are_not_grouped_with_new_ones(self):
        handler = make_push_handler()
        handler.api.stix2.last_batch_deferred = []
        bodies = [
            message([malware(0)]),
            message([malware(1)]),
            message([malware(2)], missing_ref_deferrals=1),
            message([malware(3)], missing_ref_deferrals=1),
        ]
        handler.handle_batch(bodies)
        assert handler.api.stix2.import_bundle.call_count == 2
