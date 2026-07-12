"""Benchmark multipart upload memory for non-seekable file-like inputs.

The benchmark wraps a real temporary file in a read-only object that rejects
tell()/seek(). That isolates the extra buffering performed by
_MultipartStream._normalize_data() for streams whose length is not known
upfront while still sending the body through a local HTTP server.
"""

from __future__ import annotations

import argparse
import gc
import io
import json
import os
import statistics
import tempfile
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pycti.api.opencti_api_client import File, OpenCTIApiClient


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        remaining = int(self.headers["Content-Length"])
        while remaining > 0:
            chunk = self.rfile.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        body = b'{"data":{"ok":true}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        del format, args


class _NonSeekableReader:
    def __init__(self, file_handle):
        self.file_handle = file_handle

    def read(self, *args, **kwargs):
        return self.file_handle.read(*args, **kwargs)

    def tell(self):
        raise io.UnsupportedOperation("stream is not seekable")

    def seek(self, *args, **kwargs):
        del args, kwargs
        raise io.UnsupportedOperation("stream is not seekable")


def _build_client(api_url: str) -> OpenCTIApiClient:
    client = OpenCTIApiClient.__new__(OpenCTIApiClient)
    client.api_url = api_url
    client.request_headers = {}
    client.ssl_verify = False
    client.cert = None
    client.proxies = None
    client.session_requests_timeout = 300
    client.session = __import__("requests").session()
    return client


def _run_once(client: OpenCTIApiClient, file_name: str) -> tuple[float, int]:
    gc.collect()
    tracemalloc.start()
    started_at = time.perf_counter()
    with open(file_name, "rb") as file_handle:
        client.query(
            "mutation Benchmark($file: Upload!) { uploadImport(file: $file) { id } }",
            {
                "file": File(
                    os.path.basename(file_name),
                    _NonSeekableReader(file_handle),
                    "application/octet-stream",
                )
            },
        )
    elapsed_seconds = time.perf_counter() - started_at
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed_seconds, peak_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mib", type=int, default=16)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        with tempfile.NamedTemporaryFile(delete=False) as upload_file:
            upload_file.write(b"x" * args.size_mib * 1024 * 1024)
            file_name = upload_file.name

        client = _build_client(f"http://127.0.0.1:{server.server_port}/graphql")
        _run_once(client, file_name)
        samples = [_run_once(client, file_name) for _ in range(args.repeat)]
        elapsed_samples = [sample[0] for sample in samples]
        peak_samples = [sample[1] for sample in samples]
        result = {
            "size_mib": args.size_mib,
            "repeat": args.repeat,
            "median_runtime_ms": round(statistics.median(elapsed_samples) * 1000, 3),
            "min_runtime_ms": round(min(elapsed_samples) * 1000, 3),
            "max_runtime_ms": round(max(elapsed_samples) * 1000, 3),
            "median_peak_kib": round(statistics.median(peak_samples) / 1024, 3),
        }
        print(json.dumps(result, sort_keys=True))
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()
        if "file_name" in locals() and os.path.exists(file_name):
            os.unlink(file_name)


if __name__ == "__main__":
    main()
