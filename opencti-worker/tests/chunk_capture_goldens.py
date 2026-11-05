"""Write (or check) the goldens of the chunk capture: the chunks the worker publishes for each
import conformance fixture (POC chunk-queue direct intake, opencti-worker/src/chunk_transport.py).

The platform's worker-less intake builds the same chunks in TypeScript; its test compares them
with these goldens. The goldens run the worker's own path (push_handler.publish_bundle_chunks):
split the bundle, mark the in-bundle refs with ||M||, import each mini-bundle with pycti's
mutations captured, then group the operations into chunks. Reads are answered from the
conformance world (client-python tests/import_conformance/recorder.py), as for the import goldens.

    cd opencti-worker
    python tests/chunk_capture_goldens.py          # rewrite the goldens
    python tests/chunk_capture_goldens.py --check  # fail if one is stale
"""

import json
import sys
import types
import uuid
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

WORKER_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = WORKER_DIR.parent
sys.path.insert(0, str(WORKER_DIR / "src"))
sys.path.insert(0, str(REPO_DIR / "client-python"))

from pycti import OpenCTIApiClient, OpenCTIStix2Splitter  # noqa: E402
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils  # noqa: E402

# pylint: disable=wrong-import-position
from chunk_transport import ChunkCapture, build_chunks  # noqa: E402
from push_handler import PushHandler  # noqa: E402
from tests.import_conformance.recorder import (  # noqa: E402
    FIXTURES_DIR,
    RecordingSession,
    World,
    fixture_dirs,
    load_call,
    silenced_logging,
    utc_timezone,
)

GOLDENS_DIR = WORKER_DIR / "tests" / "data" / "chunk-capture"
# Multi-object bundles: the conformance fixtures carry one object each (or refs outside the
# bundle), so neither the ||M|| marks nor the producers repeated across chunks show there
CHUNK_FIXTURES_DIR = WORKER_DIR / "tests" / "data" / "chunk-capture-fixtures"
CHUNK_FIXTURES_PREFIX = "chunk-capture/"
EXCLUDED_FILE = GOLDENS_DIR / "excluded.json"
# A small size makes the producers repeat across chunks, 24 is the bench's chunk size
CHUNK_SIZES = (3, 24)
ECHO_PREFIX = "echo--"


class NotChunked(Exception):
    """The worker does not publish this message as chunks (the reason is the message)."""


def member_marker():
    """push_handler's ||M|| marking, without a handler (it only needs the mark)."""
    marker = types.SimpleNamespace(MEMBER_REF_MARK=PushHandler.MEMBER_REF_MARK)
    marker.mark_member_refs = types.MethodType(PushHandler.mark_member_refs, marker)
    return marker


def exclusion(call: Dict, raw: Dict) -> str:
    """Why the worker does not send this message as chunks, or '' when it does."""
    if call["message_type"] != "bundle":
        return "stream event: the worker imports it over HTTP"
    if any(PushHandler.carries_files(obj) for obj in raw.get("objects", [])):
        return "files: the worker imports the bundle over HTTP"
    return ""


def normalize_echoes(value: Any, names: Dict[str, str]) -> Any:
    """Echo ids are random: name them by order of first appearance."""
    if isinstance(value, str) and value.startswith(ECHO_PREFIX):
        if value not in names:
            names[value] = "{}{}".format(ECHO_PREFIX, len(names) + 1)
        return names[value]
    if isinstance(value, dict):
        return {key: normalize_echoes(item, names) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_echoes(item, names) for item in value]
    return value


def canonical_producers(chunk_operations: List[Dict]) -> List[Dict]:
    """build_chunks adds the producers an operation references from a set: their order follows
    the string hash, which changes with each process. It does not matter (the manager executes
    the producers first): each run of consecutive producers is sorted by echo id."""
    result: List[Dict] = []
    run: List[Dict] = []
    for operation in chunk_operations:
        if operation.get("echo_id"):
            run.append(operation)
            continue
        result.extend(sorted(run, key=lambda producer: producer["echo_id"]))
        run = []
        result.append(operation)
    result.extend(sorted(run, key=lambda producer: producer["echo_id"]))
    return result


def chunk_messages(operations: List[Dict], size: int) -> List[Dict]:
    """The chunk messages of publish_bundle_chunks, without the envelope (ids, work)."""
    dangling: set = set()
    messages = []
    accounted: set = set()
    for chunk_operations in build_chunks(operations, size, dangling):
        chunk_objects = {
            op.get("object_id")
            for op in chunk_operations
            if op.get("object_id") and not op.get("echo_id")
        } - accounted
        accounted |= chunk_objects
        messages.append(
            {
                "operations": canonical_producers(chunk_operations),
                "work_objects": len(chunk_objects),
            }
        )
    if dangling:
        raise AssertionError("echo without producer: {}".format(sorted(dangling)))
    return messages


def capture(fixture_dir: Path, call: Dict, raw: Dict) -> Dict:
    now = datetime.fromisoformat(call["now"])
    guess_past_date = OpenCTIStix2Utils.guess_past_date
    with ExitStack() as stack:
        stack.enter_context(utc_timezone())
        stack.enter_context(silenced_logging())
        stack.enter_context(patch("time.sleep"))
        stack.enter_context(patch.object(OpenCTIApiClient, "_setup_proxy_certificates"))
        # The splitter's bundle ids as in the import goldens (nil uuid), on the splitter's own
        # reference: patching uuid.uuid4 itself would give every echo id the same value
        stack.enter_context(
            patch(
                "pycti.utils.opencti_stix2_splitter.uuid",
                types.SimpleNamespace(
                    **{
                        **{
                            name: getattr(uuid, name)
                            for name in dir(uuid)
                            if not name.startswith("__")
                        },
                        "uuid4": lambda: uuid.UUID(int=0),
                    }
                ),
            )
        )
        stack.enter_context(
            patch.object(
                OpenCTIStix2Utils,
                "guess_past_date",
                staticmethod(lambda text, now_=None: guess_past_date(text, now=now)),
            )
        )
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="conformance",
            log_level="error",
            perform_health_check=False,
        )
        client.session = RecordingSession(World.load(fixture_dir))
        chunk_capture = ChunkCapture(client)
        # publish_bundle_chunks: split, mark, capture each mini-bundle's import
        content = json.loads(json.dumps(raw))
        try:
            (
                _,
                incompatible,
                bundles,
            ) = OpenCTIStix2Splitter().split_bundle_with_expectations(
                content, False, content.get("x_opencti_event_version")
            )
        except Exception as error:  # pylint: disable=broad-except
            raise NotChunked(
                "split error {}: the message fails".format(type(error).__name__)
            ) from error
        member_ids = {obj["id"] for obj in content.get("objects", []) if "id" in obj}
        marker = member_marker()
        for mini_bundle in bundles:
            for obj in mini_bundle.get("objects", []):
                marker.mark_member_refs(obj, member_ids)
        with chunk_capture.capture() as captured:
            for mini_bundle in bundles:
                client.stix2.import_bundle_from_json(
                    json.dumps(mini_bundle), call["update"], call["types"], None, 0
                )
        # Serialized after the window, as the worker publishes them
        try:
            serialized = json.dumps(captured)
        except TypeError as error:
            raise NotChunked(
                "not serializable (a file in the variables): the worker imports it over HTTP"
            ) from error
        operations = normalize_echoes(json.loads(serialized), {})
    return {
        "operations": len(operations),
        "incompatible": [item["id"] for item in incompatible],
        "chunks": {str(size): chunk_messages(operations, size) for size in CHUNK_SIZES},
    }


def serialize(golden) -> str:
    return json.dumps(golden, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(check: bool) -> int:
    stale: List[str] = []
    excluded: Dict[str, str] = {}
    expected_files = set()
    chunk_fixture_dirs = sorted(
        path.parent for path in CHUNK_FIXTURES_DIR.rglob("input.json")
    )
    for fixture_dir in fixture_dirs() + chunk_fixture_dirs:
        if fixture_dir.is_relative_to(CHUNK_FIXTURES_DIR):
            name = (
                CHUNK_FIXTURES_PREFIX
                + fixture_dir.relative_to(CHUNK_FIXTURES_DIR).as_posix()
            )
        else:
            name = fixture_dir.relative_to(FIXTURES_DIR).as_posix()
        call = load_call(fixture_dir)
        raw = json.loads((fixture_dir / "input.json").read_text(encoding="utf-8"))
        reason = exclusion(call, raw)
        if reason:
            excluded[name] = reason
            continue
        golden_file = GOLDENS_DIR / (name + ".json")
        expected_files.add(golden_file)
        try:
            golden = serialize(capture(fixture_dir, call, raw))
        except NotChunked as reason_not_chunked:
            excluded[name] = str(reason_not_chunked)
            expected_files.discard(golden_file)
            continue
        current = (
            golden_file.read_text(encoding="utf-8") if golden_file.exists() else None
        )
        if current != golden:
            if check:
                stale.append(name)
            else:
                golden_file.parent.mkdir(parents=True, exist_ok=True)
                golden_file.write_text(golden, encoding="utf-8")
    orphans = sorted(
        path.relative_to(GOLDENS_DIR).as_posix()
        for path in GOLDENS_DIR.rglob("*.json")
        if path != EXCLUDED_FILE and path not in expected_files
    )
    excluded_golden = serialize(excluded)
    current_excluded = (
        EXCLUDED_FILE.read_text(encoding="utf-8") if EXCLUDED_FILE.exists() else None
    )
    if check:
        if current_excluded != excluded_golden:
            stale.append("excluded.json")
        stale.extend("orphan " + orphan for orphan in orphans)
    else:
        GOLDENS_DIR.mkdir(parents=True, exist_ok=True)
        EXCLUDED_FILE.write_text(excluded_golden, encoding="utf-8")
        for orphan in orphans:
            (GOLDENS_DIR / orphan).unlink()
    if stale:
        print("stale goldens:", ", ".join(stale))
        return 1
    print(
        "{} fixtures captured, {} excluded".format(len(expected_files), len(excluded))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv[1:]))
