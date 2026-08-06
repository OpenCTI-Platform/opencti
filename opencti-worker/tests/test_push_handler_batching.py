"""Unit tests for the Proposal D v1 batching structural pre-filter in PushHandler.

These tests exercise only the pure/static logic (`_extract_batch_candidate`,
`_has_only_free_refs`, `is_batchable`) that decides whether an incoming queue
message is a candidate for batch accumulation. They intentionally avoid
constructing a fully-initialized PushHandler (its __post_init__ opens a real
OpenCTIApiClient/network session), since none of this logic touches self.api.
"""

import base64
import json

import pytest
from push_handler import PushHandler


def make_push_handler() -> PushHandler:
    """Build a PushHandler instance without running __post_init__ (bypasses the
    real OpenCTIApiClient construction), since is_batchable() only calls
    classmethod/staticmethod helpers that don't touch any instance state."""
    return PushHandler.__new__(PushHandler)


def encode_message(message_type: str, bundle_or_event: dict, **extra) -> str:
    content_json = json.dumps(bundle_or_event)
    content_b64 = base64.b64encode(content_json.encode("utf-8")).decode("utf-8")
    data = {"type": message_type, "content": content_b64, **extra}
    return json.dumps(data)


class TestHasOnlyFreeRefs:
    def test_no_ref_fields_is_free(self):
        assert PushHandler._has_only_free_refs({"type": "malware", "name": "Emotet"})

    def test_created_by_ref_to_identity_is_free(self):
        stix_object = {
            "type": "ipv4-addr",
            "value": "1.1.1.1",
            "created_by_ref": "identity--11111111-1111-1111-1111-111111111111",
        }
        assert PushHandler._has_only_free_refs(stix_object)

    def test_object_marking_refs_to_marking_definitions_is_free(self):
        stix_object = {
            "type": "ipv4-addr",
            "value": "1.1.1.1",
            "object_marking_refs": [
                "marking-definition--22222222-2222-2222-2222-222222222222",
                "marking-definition--33333333-3333-3333-3333-333333333333",
            ],
        }
        assert PushHandler._has_only_free_refs(stix_object)

    def test_ref_to_non_identity_marking_type_is_not_free(self):
        stix_object = {
            "type": "file",
            "created_by_ref": "malware--44444444-4444-4444-4444-444444444444",
        }
        assert not PushHandler._has_only_free_refs(stix_object)

    def test_unsafe_ref_key_is_not_free(self):
        # parent_directory_ref is a real intra-bundle dependency ref, not one of
        # the SAFE_OBSERVABLE_REF_KEYS resolved inline by import_observable().
        stix_object = {
            "type": "file",
            "name": "evil.exe",
            "parent_directory_ref": "directory--55555555-5555-5555-5555-555555555555",
        }
        assert not PushHandler._has_only_free_refs(stix_object)

    def test_custom_x_opencti_ref_not_in_safe_list_is_not_free(self):
        stix_object = {
            "type": "ipv4-addr",
            "value": "1.1.1.1",
            "x_opencti_custom_ref": "identity--11111111-1111-1111-1111-111111111111",
        }
        assert not PushHandler._has_only_free_refs(stix_object)

    def test_non_string_ref_value_is_not_free(self):
        stix_object = {
            "type": "ipv4-addr",
            "value": "1.1.1.1",
            "created_by_ref": 12345,
        }
        assert not PushHandler._has_only_free_refs(stix_object)

    def test_empty_or_none_ref_value_is_ignored(self):
        stix_object = {
            "type": "ipv4-addr",
            "value": "1.1.1.1",
            "object_marking_refs": [],
            "created_by_ref": None,
        }
        assert PushHandler._has_only_free_refs(stix_object)


class TestExtractBatchCandidate:
    def test_bundle_with_single_object_and_no_seq(self):
        data = {"type": "bundle"}
        content = {"objects": [{"type": "malware", "name": "Emotet"}]}
        candidate = PushHandler._extract_batch_candidate(data, content)
        assert candidate is not None
        stix_object, needs_free_ref_check = candidate
        assert stix_object == {"type": "malware", "name": "Emotet"}
        # No x_opencti_seq computed at all: treated the same as seq == 1 today.
        assert needs_free_ref_check is False

    def test_bundle_with_seq_equal_one_skips_free_ref_check(self):
        data = {"type": "bundle"}
        content = {"objects": [{"type": "malware"}], "x_opencti_seq": 1}
        _, needs_free_ref_check = PushHandler._extract_batch_candidate(data, content)
        assert needs_free_ref_check is False

    def test_bundle_with_seq_greater_than_one_requires_free_ref_check(self):
        data = {"type": "bundle"}
        content = {"objects": [{"type": "malware"}], "x_opencti_seq": 2}
        _, needs_free_ref_check = PushHandler._extract_batch_candidate(data, content)
        assert needs_free_ref_check is True

    def test_bundle_with_multiple_objects_is_not_a_candidate(self):
        data = {"type": "bundle"}
        content = {"objects": [{"type": "malware"}, {"type": "tool"}]}
        assert PushHandler._extract_batch_candidate(data, content) is None

    def test_bundle_with_zero_objects_is_not_a_candidate(self):
        data = {"type": "bundle"}
        content = {"objects": []}
        assert PushHandler._extract_batch_candidate(data, content) is None

    def test_sync_event_create_always_requires_free_ref_check(self):
        data = {"type": "event"}
        content = {"type": "create", "data": {"type": "malware", "name": "Emotet"}}
        candidate = PushHandler._extract_batch_candidate(data, content)
        assert candidate is not None
        stix_object, needs_free_ref_check = candidate
        assert stix_object == {"type": "malware", "name": "Emotet"}
        assert needs_free_ref_check is True

    def test_sync_event_update_always_requires_free_ref_check(self):
        data = {"type": "event"}
        content = {"type": "update", "data": {"type": "malware", "name": "Emotet"}}
        _, needs_free_ref_check = PushHandler._extract_batch_candidate(data, content)
        assert needs_free_ref_check is True

    def test_sync_event_with_non_dict_data_is_not_a_candidate(self):
        data = {"type": "event"}
        content = {"type": "create", "data": None}
        assert PushHandler._extract_batch_candidate(data, content) is None

    def test_sync_event_delete_is_not_a_candidate(self):
        data = {"type": "event"}
        content = {"type": "delete", "data": {"type": "malware"}}
        assert PushHandler._extract_batch_candidate(data, content) is None

    def test_unknown_message_type_is_not_a_candidate(self):
        data = {"type": "webhook"}
        content = {}
        assert PushHandler._extract_batch_candidate(data, content) is None


class TestIsBatchable:
    def test_leaf_bundle_with_seq_one_is_batchable(self):
        handler = make_push_handler()
        body = encode_message(
            "bundle",
            {"type": "bundle", "objects": [{"type": "malware", "name": "Emotet"}], "x_opencti_seq": 1},
        )
        assert handler.is_batchable(body) is True

    def test_bundle_with_unsafe_ref_and_seq_greater_one_is_not_batchable(self):
        handler = make_push_handler()
        body = encode_message(
            "bundle",
            {
                "type": "bundle",
                "objects": [{
                    "type": "file",
                    "parent_directory_ref": "directory--55555555-5555-5555-5555-555555555555",
                }],
                "x_opencti_seq": 2,
            },
        )
        assert handler.is_batchable(body) is False

    def test_bundle_with_only_free_refs_and_seq_greater_one_is_batchable(self):
        handler = make_push_handler()
        body = encode_message(
            "bundle",
            {
                "type": "bundle",
                "objects": [{
                    "type": "ipv4-addr",
                    "value": "1.1.1.1",
                    "created_by_ref": "identity--11111111-1111-1111-1111-111111111111",
                }],
                "x_opencti_seq": 2,
            },
        )
        assert handler.is_batchable(body) is True

    def test_multi_object_bundle_is_not_batchable(self):
        handler = make_push_handler()
        body = encode_message(
            "bundle",
            {"type": "bundle", "objects": [{"type": "malware"}, {"type": "tool"}]},
        )
        assert handler.is_batchable(body) is False

    def test_malformed_message_is_not_batchable(self):
        handler = make_push_handler()
        assert handler.is_batchable("not-json") is False
        assert handler.is_batchable(json.dumps({"type": "bundle", "content": "not-base64!!"})) is False

    def test_sync_event_create_is_batchable_when_only_free_refs(self):
        handler = make_push_handler()
        body = encode_message(
            "event",
            {"type": "create", "data": {"type": "malware", "name": "Emotet"}},
        )
        assert handler.is_batchable(body) is True

    def test_sync_event_create_is_not_batchable_with_unsafe_ref(self):
        handler = make_push_handler()
        body = encode_message(
            "event",
            {
                "type": "create",
                "data": {
                    "type": "file",
                    "parent_directory_ref": "directory--55555555-5555-5555-5555-555555555555",
                },
            },
        )
        assert handler.is_batchable(body) is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
