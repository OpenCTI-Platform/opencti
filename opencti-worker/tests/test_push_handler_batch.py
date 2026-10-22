"""Unit tests of PushHandler.handle_batch: messages received together are imported as one bundle when they share
their context and the platform has the lock-free batch import, and one by one otherwise.
"""

import base64
import json
from unittest.mock import MagicMock

from push_handler import MAX_GROUP_OBJECTS, PushHandler


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

    def test_drafts_and_single_objects_alone_go_one_by_one(self):
        handler = make_push_handler()
        bodies = [
            message([malware(0)], draft_id="d1"),
            message([malware(1)], draft_id="d1"),
        ]
        handler.handle_batch(bodies)
        assert handler.handle_message.call_count == 2
        handler.api.stix2.import_bundle.assert_not_called()

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
