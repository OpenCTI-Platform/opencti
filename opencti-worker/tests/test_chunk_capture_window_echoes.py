"""A9: echo ids are visible only inside the capture window that minted them.

Two capture windows open on the same client (one handler, two bundles in flight): a
sub-object cached by window A with an echo id must read as a MISS from window B, so B
re-creates the sub-object with a producer of its own; and a bundle whose operations
reference an echo with no producer is reported by the chunk builder.
"""

import threading
from unittest.mock import MagicMock

from cachetools import LRUCache

from chunk_transport import ECHO_PREFIX, ChunkCapture, build_chunks

LABEL_MUTATION = "mutation LabelAdd($input: LabelAddInput!) { labelAdd(input: $input) { id } }"
INDICATOR_MUTATION = "mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }"


class FakeStix2:
    def __init__(self):
        self.mapping_cache = LRUCache(maxsize=5000)
        self.opencti = MagicMock()
        self.opencti.get_draft_id.return_value = ""

    def get_in_cache(self, data_id):
        if data_id in self.mapping_cache:
            return self.mapping_cache[data_id]
        return None

    def set_in_cache(self, data_id, data):
        self.mapping_cache[data_id] = data


def make_client():
    api = MagicMock()
    api.query = MagicMock(return_value={"data": {}})
    api.stix2 = FakeStix2()
    return api


def test_foreign_window_echo_is_a_miss():
    api = make_client()
    capture = ChunkCapture(api)
    stix2 = api.stix2
    gate_a_created = threading.Event()
    gate_b_done = threading.Event()
    seen_by_b = {}

    def window_a():
        with capture.capture() as buffer:
            echo = api.query(LABEL_MUTATION, {"input": {"value": "shared-label"}})
            label = echo["data"]["labelAdd"]
            stix2.set_in_cache("label--shared-label", label)
            # A still sees its own echo
            assert stix2.get_in_cache("label--shared-label")["id"] == label["id"]
            gate_a_created.set()
            gate_b_done.wait(5)
            assert buffer[0]["echo_id"] == label["id"]

    def window_b():
        gate_a_created.wait(5)
        with capture.capture() as buffer:
            seen_by_b["hit"] = stix2.get_in_cache("label--shared-label")
            # B re-creates: a producer of its own
            echo = api.query(LABEL_MUTATION, {"input": {"value": "shared-label"}})
            seen_by_b["own"] = echo["data"]["labelAdd"]["id"]
            assert buffer[0]["echo_id"] == seen_by_b["own"]
        gate_b_done.set()

    ta, tb = threading.Thread(target=window_a), threading.Thread(target=window_b)
    ta.start()
    tb.start()
    ta.join(10)
    tb.join(10)
    assert seen_by_b["hit"] is None
    assert seen_by_b["own"].startswith(ECHO_PREFIX)


def test_outside_any_window_echo_is_a_miss_and_real_values_pass():
    api = make_client()
    ChunkCapture(api)
    stix2 = api.stix2
    stix2.set_in_cache("label--x", {"id": f"{ECHO_PREFIX}dead"})
    stix2.set_in_cache("identity--real", {"id": "identity--real"})
    assert stix2.get_in_cache("label--x") is None
    assert stix2.get_in_cache("identity--real") == {"id": "identity--real"}


def test_build_chunks_reports_dangling_echoes():
    producer = {"query": LABEL_MUTATION, "variables": {"input": {"value": "l"}}, "object_id": None, "echo_id": f"{ECHO_PREFIX}own"}
    consumer_ok = {"query": INDICATOR_MUTATION, "variables": {"input": {"stix_id": "indicator--1", "objectLabel": [f"{ECHO_PREFIX}own"]}}, "object_id": "indicator--1"}
    consumer_leak = {"query": INDICATOR_MUTATION, "variables": {"input": {"stix_id": "indicator--2", "objectLabel": [f"{ECHO_PREFIX}foreign"]}}, "object_id": "indicator--2"}
    dangling = set()
    chunks = build_chunks([producer, consumer_ok, consumer_leak], 16, dangling)
    assert dangling == {f"{ECHO_PREFIX}foreign"}
    assert chunks[0][0]["echo_id"] == f"{ECHO_PREFIX}own"
    assert [op["object_id"] for op in chunks[0][1:]] == ["indicator--1", "indicator--2"]
    # the default call stays compatible
    assert len(build_chunks([producer, consumer_ok], 16)) == 1


def test_purge_visits_only_this_windows_echo_keys_and_keeps_foreign_entries():
    api = make_client()
    capture = ChunkCapture(api)
    stix2 = api.stix2
    # a large cache of real entries must survive a window close untouched
    for i in range(1000):
        stix2.set_in_cache(f"identity--{i}", {"id": f"identity--{i}"})
    foreign = {"id": f"{ECHO_PREFIX}foreign"}
    stix2.mapping_cache["label--foreign"] = foreign  # another window's echo, bypassing the wrapper
    with capture.capture():
        echo = api.query(LABEL_MUTATION, {"input": {"value": "mine"}})["data"]["labelAdd"]
        stix2.set_in_cache("label--mine", echo)
        stix2.set_in_cache("identity--mine", {"id": "identity--mine"})
        assert capture._local.echo_keys == {"label--mine"}
    assert "label--mine" not in stix2.mapping_cache
    assert stix2.mapping_cache["label--foreign"] is foreign
    assert stix2.mapping_cache["identity--mine"] == {"id": "identity--mine"}
    assert len(stix2.mapping_cache) == 1002
