"""Microbenchmark for base64-serializing downloaded file content.

The benchmark isolates OpenCTIApiClient.fetch_opencti_file(..., binary=True,
serialize=True) with a synthetic response body. It captures the peak-memory
cost of returning a base64 string for a large download while also reporting
whether the request asked requests to stream the response body.
"""

from __future__ import annotations

import argparse
import gc
import json
import math
import statistics
import time
import tracemalloc

from pycti.api.opencti_api_client import OpenCTIApiClient


class _NullLogger:
    def warning(self, *args, **kwargs):
        del args, kwargs


class _SyntheticResponse:
    ok = True
    status_code = 200

    def __init__(self, size_bytes: int):
        self.size_bytes = size_bytes
        self._content = None

    @property
    def content(self):
        if self._content is None:
            self._content = b"x" * self.size_bytes
        return self._content

    def iter_content(self, chunk_size: int):
        remaining = self.size_bytes
        while remaining > 0:
            current_size = min(chunk_size, remaining)
            yield b"x" * current_size
            remaining -= current_size

    def close(self):
        pass


class _SyntheticSession:
    def __init__(self, size_bytes: int):
        self.size_bytes = size_bytes
        self.stream_values = []

    def get(self, *args, **kwargs):
        del args
        self.stream_values.append(kwargs.get("stream", False))
        return _SyntheticResponse(self.size_bytes)


def _build_client(size_bytes: int) -> tuple[OpenCTIApiClient, _SyntheticSession]:
    client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    session = _SyntheticSession(size_bytes)
    client.session = session
    client.request_headers = {}
    client.ssl_verify = False
    client.cert = None
    client.proxies = None
    client.session_requests_timeout = 300
    client.app_logger = _NullLogger()
    return client, session


def _run_once(size_bytes: int) -> tuple[float, int, bool]:
    client, session = _build_client(size_bytes)
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    result = client.fetch_opencti_file(
        "http://benchmark.invalid/storage/get/file",
        binary=True,
        serialize=True,
    )
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    expected_length = 4 * math.ceil(size_bytes / 3)
    if len(result) != expected_length:
        raise AssertionError("fetch_opencti_file() returned the wrong base64 length")
    return elapsed_seconds, peak_bytes, session.stream_values[-1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mib", type=int, default=16)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    size_bytes = args.size_mib * 1024 * 1024
    _run_once(min(size_bytes, 1024 * 1024))
    samples = [_run_once(size_bytes) for _ in range(args.repeat)]
    elapsed_samples = [sample[0] for sample in samples]
    peak_samples = [sample[1] for sample in samples]
    stream_samples = [sample[2] for sample in samples]

    result = {
        "size_mib": args.size_mib,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
        "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
        "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
        "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        "stream_requested": all(stream_samples),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
