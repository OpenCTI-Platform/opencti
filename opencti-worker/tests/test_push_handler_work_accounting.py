"""Work accounting of a bundle the worker imports whole (ADR 0007).

The sender states in `declared_expectations` what it declared for the message (pycti at
send time, the platform when it pushes); a message without it comes from an older client,
which declared 1. The worker declares only the difference with the objects it will report:
one per distinct object, incompatible ones included (reported in error).
"""

from unittest.mock import MagicMock

from push_handler import PushHandler

BUNDLE = {
    "type": "bundle",
    "id": "bundle--1",
    "objects": [
        {"type": "malware", "id": "malware--1"},
        {"type": "malware", "id": "malware--1"},
        {"type": "intrusion-set", "id": "intrusion-set--1"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1"},
    ],
}


def make_handler() -> PushHandler:
    handler = PushHandler.__new__(PushHandler)
    handler.api = MagicMock()
    handler.api.work.add_expectations = MagicMock(return_value=True)
    return handler


def test_bundle_object_count_counts_distinct_ids():
    assert PushHandler.bundle_object_count(BUNDLE) == 3


def test_no_work_declares_nothing():
    handler = make_handler()
    assert handler.declare_bundle_expectations(None, {}, BUNDLE) is True
    handler.api.work.add_expectations.assert_not_called()


def test_older_sender_declared_one():
    handler = make_handler()
    handler.declare_bundle_expectations("work_1", {}, BUNDLE)
    handler.api.work.add_expectations.assert_called_once_with("work_1", 2)


def test_sender_that_declared_everything_leaves_nothing_to_declare():
    handler = make_handler()
    handler.declare_bundle_expectations("work_1", {"declared_expectations": 3}, BUNDLE)
    handler.api.work.add_expectations.assert_not_called()


def test_platform_push_without_declaration_is_declared_by_the_worker():
    handler = make_handler()
    handler.declare_bundle_expectations("work_1", {"declared_expectations": 0}, BUNDLE)
    handler.api.work.add_expectations.assert_called_once_with("work_1", 3)


def test_dead_work_stops_the_import():
    handler = make_handler()
    handler.api.work.add_expectations.return_value = False
    assert handler.declare_bundle_expectations("work_1", {}, BUNDLE) is False


def test_incompatible_elements_are_reported_in_error():
    handler = make_handler()
    handler.report_incompatible("work_1", [{"id": "x-mitre-tactic--1"}])
    work_id, error = handler.api.work.report_expectation.call_args[0]
    assert work_id == "work_1"
    assert "x-mitre-tactic--1" in error["source"]


def test_a_fallback_after_a_full_declaration_declares_nothing():
    handler = make_handler()
    data = {}
    handler.declare_bundle_expectations("work_1", data, BUNDLE)
    data["declared_expectations"] = PushHandler.bundle_object_count(BUNDLE)
    handler.declare_bundle_expectations("work_1", data, BUNDLE)
    handler.api.work.add_expectations.assert_called_once_with("work_1", 2)
