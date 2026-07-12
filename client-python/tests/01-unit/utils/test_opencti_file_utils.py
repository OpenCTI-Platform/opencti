import base64
import os

from pycti.utils.opencti_file_utils import (
    BASE64_FILE_MEMORY_THRESHOLD,
    decode_base64_file_data,
)


def test_decode_base64_file_data_keeps_small_payloads_in_memory():
    encoded_data = base64.b64encode(b"payload").decode("ascii")

    with decode_base64_file_data(encoded_data) as data:
        assert data == b"payload"


def test_decode_base64_file_data_streams_large_canonical_payloads():
    payload = b"x" * (BASE64_FILE_MEMORY_THRESHOLD + 1)
    encoded_data = base64.b64encode(payload).decode("ascii")

    with decode_base64_file_data(encoded_data) as data:
        assert hasattr(data, "read")
        assert not data.closed
        assert data.tell() == 0
        assert data.seek(0, os.SEEK_END) == len(payload)
        assert data.tell() == len(payload)
        assert data.seek(0) == 0
        assert data.read() == payload

    assert data.closed


def test_decode_base64_file_data_preserves_noncanonical_decode_behavior():
    payload = b"x" * (BASE64_FILE_MEMORY_THRESHOLD + 1)
    encoded_data = base64.b64encode(payload).decode("ascii")
    encoded_data = encoded_data[:100] + "\n" + encoded_data[100:]

    with decode_base64_file_data(encoded_data) as data:
        assert data == payload
