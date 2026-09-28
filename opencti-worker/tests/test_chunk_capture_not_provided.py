"""pycti's NOT_PROVIDED marker never reaches a chunk message.

pycti >= 7.260921 puts a bare object() (NOT_PROVIDED) in mutation variables for values its
caller never supplied (createdBy of an object without author) and drops those entries in its
HTTP path. The capture transport receives the raw variables: it must drop them too, or the
chunk message cannot be serialized.
"""

import json
from unittest.mock import MagicMock

from chunk_transport import NOT_PROVIDED, ChunkCapture, drop_not_provided

INDICATOR_MUTATION = "mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }"


def test_drop_not_provided_is_recursive_and_keeps_explicit_nulls():
    value = {"a": NOT_PROVIDED, "b": None, "c": {"d": NOT_PROVIDED, "e": 1}, "f": [{"g": NOT_PROVIDED, "h": "x"}]}
    assert drop_not_provided(value) == {"b": None, "c": {"e": 1}, "f": [{"h": "x"}]}


def test_captured_operation_is_serializable():
    api = MagicMock()
    api.query = MagicMock(return_value={"data": {}})
    capture = ChunkCapture(api)
    with capture.capture() as buffer:
        api.query(INDICATOR_MUTATION, {"input": {"stix_id": "indicator--1", "name": "i", "createdBy": NOT_PROVIDED}})
    assert "createdBy" not in buffer[0]["variables"]["input"]
    json.dumps(buffer)
