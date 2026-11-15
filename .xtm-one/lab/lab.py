"""The toolchain and process helpers of the OpenCTI lab (``opencti_lab.py``). Standard library only.

Node and yarn are downloaded from the npm registry (a host the XTM One sandbox lets a lab reach), each pinned by
version and digest: a download whose digest differs stops the lab. Everything lives under /tmp/lab and dies with it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path("/tmp/lab")
CACHE = ROOT / "cache"
#: The repository root: this file is .xtm-one/lab/lab.py.
CHECKOUT = Path(__file__).resolve().parents[2]
T0 = time.monotonic()

# (url, algorithm, digest). Node satisfies the root package.json engines (>= 22.18.0).
NODE = (
    "https://registry.npmjs.org/node-linux-x64/-/node-linux-x64-24.22.2.tgz",
    "sha512",
    "R5qxeQXhLZLFRzZ0Nh+Ux/dVgIVVbhwCine7eXN2CUaehslzemv24CgzfNb0U+NGOlSOVvlSpabGkiu8lg3oNg==",
)
#: The yarn release the root package.json pins (packageManager yarn@4.18.1).
YARN = (
    "https://registry.npmjs.org/@yarnpkg/cli-dist/-/cli-dist-4.18.1.tgz",
    "sha512",
    "EH+A4TxAtBWXKE0DGQxW9Bo9crXHLJ73mfxjTQJuv8XonNWWTpei8BQ5JjczHJNU9GROTycwMFn8iOvRIZXUcA==",
)

CHILDREN: list[subprocess.Popen] = []


def log(message: str) -> None:
    print(f"[lab {time.monotonic() - T0:6.1f}s] {message}", flush=True)


def fetch(spec: tuple[str, str, str]) -> bytes:
    """The bytes at *spec*'s URL, checked against its digest."""
    url, algorithm, expected = spec
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=300) as response:
        data = response.read()
    digest = hashlib.new(algorithm, data)
    actual = base64.b64encode(digest.digest()).decode() if algorithm == "sha512" else digest.hexdigest()
    if actual != expected:
        raise SystemExit(f"lab: {url} has {algorithm} {actual}, expected {expected}")
    log(f"fetched {url.rsplit('/', 1)[-1]} ({len(data) // 1_000_000} MB, {time.monotonic() - started:.1f}s)")
    return data


def pump(name: str, stream) -> None:
    for line in iter(stream.readline, b""):
        sys.stdout.write(f"[{name}] {line.decode('utf-8', 'replace')}")
        sys.stdout.flush()


def spawn(
    name: str, argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, daemon: bool = True
) -> subprocess.Popen:
    """Start *argv* with its output prefixed by *name*; a daemon is watched: the lab stops when it exits."""
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env={**os.environ, **(env or {})},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    threading.Thread(target=pump, args=(name, process.stdout), daemon=True).start()
    if daemon:
        CHILDREN.append(process)
    log(f"started {name} (pid {process.pid})")
    return process


def run(name: str, argv: list[str], **kwargs) -> None:
    process = spawn(name, argv, daemon=False, **kwargs)
    if process.wait() != 0:
        raise SystemExit(f"lab: {name} exited with {process.returncode}")


def startup_failure(body: bytes) -> str:
    """The ``startup_error`` a 503 answer names, empty while the process is only starting."""
    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return ""
    error = payload.get("startup_error") if isinstance(payload, dict) else None
    return str(error).strip() if error else ""


def wait_http(url: str, timeout: float, what: str) -> None:
    """Wait until *url* answers below 500; stop the lab when a watched process exits or *timeout* passes."""
    deadline = time.monotonic() + timeout
    reported = 0.0
    while time.monotonic() < deadline:
        answer = "no answer"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status < 500:
                    log(f"{what} ready")
                    return
        except urllib.error.HTTPError as exc:
            body = exc.read()[:2000]
            failure = startup_failure(body)
            if failure:
                raise SystemExit(f"lab: {what} startup failed: {failure[:500]}") from None
            answer = f"{exc.code} {body[:300].decode('utf-8', 'replace')}"
        except Exception as exc:  # noqa: BLE001 - not up yet
            answer = type(exc).__name__
        if time.monotonic() - reported >= 15:
            reported = time.monotonic()
            log(f"waiting for {what}: {answer}")
        for child in CHILDREN:
            if child.poll() is not None:
                raise SystemExit(f"lab: a process exited ({child.args[0]}, code {child.returncode}) while waiting for {what}")
        time.sleep(1)
    raise SystemExit(f"lab: {what} not ready within {timeout:.0f}s")
