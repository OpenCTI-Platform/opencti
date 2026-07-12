import base64
import os
import re
from contextlib import contextmanager

BASE64_FILE_MEMORY_THRESHOLD = 1024 * 1024
BASE64_DECODE_CHUNK_SIZE = 4 * 1024 * 1024
_MIN_STREAMABLE_ENCODED_LENGTH = ((BASE64_FILE_MEMORY_THRESHOLD + 1 + 2) // 3) * 4
_CANONICAL_BASE64_TEXT = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def _canonical_base64_decoded_length(data):
    if (
        not isinstance(data, str)
        or len(data) % 4 != 0
        or _CANONICAL_BASE64_TEXT.fullmatch(data) is None
    ):
        return None
    padding = 2 if data.endswith("==") else 1 if data.endswith("=") else 0
    return (len(data) // 4) * 3 - padding


def _base64_decoded_length_upper_bound(data):
    if not isinstance(data, str) or len(data) % 4 != 0:
        return None
    padding = 2 if data.endswith("==") else 1 if data.endswith("=") else 0
    return (len(data) // 4) * 3 - padding


class _Base64DecodedStream:
    def __init__(self, encoded_data, decoded_length):
        self._encoded_data = encoded_data
        self._decoded_length = decoded_length
        self._decoded_position = 0
        self._encoded_position = 0
        self._pending_decoded = b""
        self.closed = False

    def _ensure_open(self):
        if self.closed:
            raise ValueError("I/O operation on closed file.")

    def _reset(self):
        self._decoded_position = 0
        self._encoded_position = 0
        self._pending_decoded = b""

    def read(self, size=-1):
        self._ensure_open()
        remaining = self._decoded_length - self._decoded_position
        if size is None or size < 0 or size > remaining:
            size = remaining
        if size == 0:
            return b""

        chunks = []
        bytes_needed = size
        while bytes_needed > 0:
            if not self._pending_decoded:
                encoded_chunk = self._encoded_data[
                    self._encoded_position : self._encoded_position
                    + BASE64_DECODE_CHUNK_SIZE
                ]
                if not encoded_chunk:
                    break
                self._encoded_position += len(encoded_chunk)
                self._pending_decoded = base64.b64decode(encoded_chunk)

            take = min(bytes_needed, len(self._pending_decoded))
            chunks.append(self._pending_decoded[:take])
            self._pending_decoded = self._pending_decoded[take:]
            self._decoded_position += take
            bytes_needed -= take

        if len(chunks) == 1:
            return chunks[0]
        return b"".join(chunks)

    def seek(self, offset, whence=os.SEEK_SET):
        self._ensure_open()
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self._decoded_position + offset
        elif whence == os.SEEK_END:
            target = self._decoded_length + offset
        else:
            raise ValueError(f"Unsupported whence value: {whence}")

        if target < 0 or target > self._decoded_length:
            raise ValueError("Invalid seek position")
        if target == self._decoded_position:
            return target
        if target == self._decoded_length:
            self._decoded_position = target
            self._encoded_position = len(self._encoded_data)
            self._pending_decoded = b""
            return target
        if target < self._decoded_position:
            self._reset()
        while self._decoded_position < target:
            self.read(min(BASE64_DECODE_CHUNK_SIZE, target - self._decoded_position))
        return target

    def tell(self):
        self._ensure_open()
        return self._decoded_position

    def close(self):
        self.closed = True
        self._encoded_data = ""
        self._pending_decoded = b""


@contextmanager
def decode_base64_file_data(data):
    """Decode large canonical base64 file data lazily for multipart upload.

    Small or non-canonical inputs keep the existing one-shot decode behavior.
    The latter preserves permissive ``base64.b64decode`` handling for unusual
    whitespace or non-alphabet input while keeping exported STIX file payloads
    on the bounded-memory path.
    """

    if not isinstance(data, str) or len(data) < _MIN_STREAMABLE_ENCODED_LENGTH:
        yield base64.b64decode(data)
        return

    decoded_length_upper_bound = _base64_decoded_length_upper_bound(data)
    if (
        decoded_length_upper_bound is None
        or decoded_length_upper_bound <= BASE64_FILE_MEMORY_THRESHOLD
    ):
        yield base64.b64decode(data)
        return

    decoded_length = _canonical_base64_decoded_length(data)
    if decoded_length is None:
        yield base64.b64decode(data)
        return

    decoded_stream = _Base64DecodedStream(data, decoded_length)
    try:
        yield decoded_stream
    finally:
        decoded_stream.close()
