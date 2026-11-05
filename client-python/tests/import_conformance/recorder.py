"""Record the GraphQL calls pycti's STIX transformation sends for one conformance fixture.

Scope: the transformation only, from STIX to GraphQL mutations and variables. pycti's splitter
then ``import_item`` run for real on each object; only the HTTP session is replaced. Every call
is captured as it leaves the wire (after pycti's own variable cleaning) and answered from a
declared world, so the recorded calls depend on the fixture only. What surrounds the
transformation in the worker (retries, work expectations, too large objects, envelope headers)
is out of scope: the platform redesigns it instead of reproducing it.
"""

import copy
import hashlib
import json
import logging
import os
import re
import time
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from unittest.mock import patch

from pycti import OpenCTIApiClient, OpenCTIStix2Splitter
from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "import-conformance"
FIXTURES_DIR = DATA_DIR / "fixtures"
WORLD_DIR = DATA_DIR / "world"
EXPECTED_FILE = "expected.json"
# pycti defects the platform does not reproduce (fixture -> reason, pycti's and the port's result)
ACCEPTED_DIFFERENCES_FILE = DATA_DIR / "accepted-differences.json"
DATES_DIR = DATA_DIR / "dates"
DATES_TEXTS_FILE = "texts.json"

# Namespace of the deterministic ids answered to mutations, shared with the TypeScript side.
RESPONSE_ID_NAMESPACE = uuid.UUID("4a8a4c2e-6a53-4c1b-9e43-0f2f1c8a6b10")
# dateutil's two-digit-year pivot uses the clock year, not this: such dates go stale ~2060
FIXED_NOW = "2026-01-01T00:00:00+00:00"
DEFAULT_CALL = {
    "update": False,
    "types": None,
    "now": FIXED_NOW,
    # Objects pycti cannot transform (an error) must be declared by the fixture
    "expect_errors": False,
    # "bundle": input.json is a STIX bundle; "event": input.json is a stream event (sync)
    "message_type": "bundle",
}
EMPTY_CONNECTION = {
    "edges": [],
    "pageInfo": {
        "startCursor": None,
        "endCursor": None,
        "hasNextPage": False,
        "hasPreviousPage": False,
        "globalCount": 0,
    },
}
OPERATION_PATTERN = re.compile(
    r"^\s*(query|mutation)\s*(\w+)?[^{]*\{\s*(\w+)\s*(?:\([^)]*\))?\s*(\{\s*(\w+)\s*(\()?)?"
)


def _js_number(value: float) -> str:
    """A float as ECMAScript's Number::toString writes it (RFC 8785 number form)."""
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity have no JSON form")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr gives the shortest round-trip digits, as ECMAScript does
    _, digit_tuple, exponent = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(map(str, digit_tuple))
    k = len(digits)
    n = exponent + k  # position of the decimal point
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        text = mantissa + "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
    return sign + text


def canonical_json(value: Any) -> str:
    """RFC 8785 canonical JSON, the form the TypeScript side gets from `canonicalize`."""
    if isinstance(value, dict):
        # Keys sorted by UTF-16 code units, as RFC 8785 requires
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + canonical_json(value[key])
                for key in keys
            )
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, float):
        return _js_number(value)
    return json.dumps(value, ensure_ascii=False)


def response_id(root: str, variables: Dict) -> str:
    """Same input, same id, as the platform's upsert would answer."""
    return str(
        uuid.uuid5(RESPONSE_ID_NAMESPACE, root + ":" + canonical_json(variables))
    )


@contextmanager
def utc_timezone() -> Iterator[None]:
    """dateutil reads the host's zone names as local time: record as the platform runs, in UTC."""
    previous = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    try:
        yield
    finally:
        if previous is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = previous
        time.tzset()


@contextmanager
def silenced_logging() -> Iterator[None]:
    """pycti logs the errors it recovers from: record() tracks them, the output stays readable."""
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(previous)


def parse_operation(query: str) -> Dict[str, Any]:
    """The operation, root field and nested operation of a document, read by a regex.

    The regex reads the first root field and its first nested field only: a document whose
    shape it cannot read (comment, alias, fragment where it reads a field) is refused rather
    than misread, the TypeScript side parses the documents with graphql-js.
    """
    if "#" in query:
        raise ValueError("Unsupported GraphQL comment: " + query[:200])
    match = OPERATION_PATTERN.match(query)
    if match is None:
        raise ValueError("Unrecognized GraphQL operation: " + query[:200])
    kind, name, root, selection, nested, has_args = match.groups()
    rest = query[match.end() :].lstrip()
    # An alias puts a ':' right after the field the regex took for the root or nested field
    if rest.startswith(":"):
        raise ValueError("Unsupported GraphQL alias: " + query[:200])
    # No nested field read although a selection set follows: a fragment or another form
    if selection is None and rest.startswith("{"):
        raise ValueError("Unsupported GraphQL selection: " + query[:200])
    # A nested field is the operation itself under an *Edit root (stixCoreObjectEdit { delete })
    # or when it takes arguments; otherwise it is only the first field read back
    is_operation = nested is not None and (has_args or root.endswith("Edit"))
    return {
        "op": kind,
        "name": name,
        "root": root,
        "sub": nested if is_operation else None,
        # A root field without selection set (deletes, async rules, mails answer an id or a flag)
        "scalar": selection is None,
    }


def _entity_type(root: str, variables: Dict) -> str:
    input_value = variables.get("input") if isinstance(variables, dict) else None
    if root == "stixCyberObservableAdd" and variables.get("type"):
        return variables["type"]
    if isinstance(input_value, dict) and isinstance(
        input_value.get("relationship_type"), str
    ):
        return input_value["relationship_type"]
    name = root[:-3] if root.endswith("Add") else root
    return name[:1].upper() + name[1:]


# Inputs holding a reference: the platform answers them as objects, never echoes the id
REFERENCE_INPUTS = {"createdBy"}


def _echo_input(variables: Dict) -> Dict:
    # Scalar input fields are echoed back: some callers read them from the response (vocabulary name)
    input_value = variables.get("input") if isinstance(variables, dict) else None
    if not isinstance(input_value, dict):
        return {}
    return {
        key: value
        for key, value in input_value.items()
        if key not in REFERENCE_INPUTS
        and (value is None or isinstance(value, (str, int, float, bool)))
    }


class World:
    """What the platform answers to reads: the part of a fixture that is not STIX."""

    def __init__(self, reads: Dict[str, Any], errors: Dict[str, Dict]):
        self.reads = reads
        # Root fields the platform refuses: every call to them answers this GraphQL error
        self.errors = errors

    @staticmethod
    def load(fixture_dir: Path) -> "World":
        with open(WORLD_DIR / "vocabulary-categories.json", encoding="utf-8") as f:
            reads = {"vocabularyCategories": json.load(f)}
        world_file = fixture_dir / "world.json"
        if world_file.exists():
            with open(world_file, encoding="utf-8") as f:
                world = json.load(f)
            reads.update(world.get("reads", {}))
            return World(reads, world.get("errors", {}))
        return World(reads, {})

    def answer(self, operation: Dict, variables: Dict) -> Any:
        root, sub = operation["root"], operation["sub"]
        if operation["op"] == "query":
            # Copies: the caller may change what it reads, the next read must not see it
            if root in self.reads:
                return copy.deepcopy(self.reads[root])
            return copy.deepcopy(EMPTY_CONNECTION) if root.endswith("s") else None
        identifier = response_id(root + ("." + sub if sub else ""), variables)
        if operation["scalar"]:
            return identifier
        input_value = variables.get("input") if isinstance(variables, dict) else None
        stix_id = input_value.get("stix_id") if isinstance(input_value, dict) else None
        entity = {
            **_echo_input(variables),
            "id": identifier,
            "standard_id": stix_id or identifier,
            "entity_type": _entity_type(root, variables),
            "parent_types": [],
        }
        return {sub: entity} if sub else entity


class FakeResponse:
    def __init__(self, payload: Dict):
        self.status_code = 200
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self) -> Dict:
        return self._payload


class RecordingSession:
    """Stands for requests.Session: records each POST and answers it from the world."""

    def __init__(self, world: World):
        self.world = world
        self.calls: List[Dict] = []

    @staticmethod
    def _files(data: Dict, files: List) -> List[Dict]:
        file_map = json.loads(data["map"])
        recorded = []
        for index, (name, content, mime) in files:
            raw = content.getvalue() if hasattr(content, "getvalue") else content
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            recorded.append(
                {
                    "path": file_map[index][0].removeprefix("variables."),
                    "name": name,
                    "mime": mime,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        return recorded

    def post(self, url, **kwargs):
        if kwargs.get("json") is not None:
            # What requests sends (json.dumps without NaN): a tuple becomes a list, a non-str key
            # a str, recorded and hashed as the platform receives them
            payload = json.loads(json.dumps(kwargs["json"], allow_nan=False))
            sent_files = []
        else:
            payload = json.loads(kwargs["data"]["operations"])
            sent_files = self._files(kwargs["data"], kwargs["files"])
        query, variables = payload["query"], payload["variables"]
        operation = parse_operation(query)
        self.calls.append(
            {
                "seq": len(self.calls) + 1,
                "op": operation["op"],
                "name": operation["name"],
                "root": operation["root"],
                "sub": operation["sub"],
                "variables": variables,
                "files": sent_files,
            }
        )
        error = self.world.errors.get(operation["root"])
        if error is not None:
            return FakeResponse(
                {
                    "errors": [
                        {
                            "message": error["message"],
                            "name": error["name"],
                            "extensions": {"code": error["name"]},
                        }
                    ]
                }
            )
        answer = self.world.answer(operation, variables)
        return FakeResponse({"data": {operation["root"]: answer}})

    def get(self, *args, **kwargs):
        raise AssertionError("The import path must not download files")


def event_bundle(event: Dict) -> Dict:
    """The bundle the worker builds from a stream event (opencti-worker push_handler.py).

    The worker, not pycti, turns an event into a bundle: the platform's intake must do the same,
    so the harness mirrors it here.
    """
    data = event["data"]
    if event["type"] == "merge":
        data["opencti_operation"] = event["type"]
        data["merge_target_id"] = data["id"]
        data["merge_source_ids"] = [
            source["id"] for source in event["context"]["sources"]
        ]
    elif event["type"] not in ("create", "update"):
        data["opencti_operation"] = event["type"]
    return {"type": "bundle", "objects": [data]}


def load_call(fixture_dir: Path) -> Dict:
    call = dict(DEFAULT_CALL)
    call_file = fixture_dir / "call.json"
    if call_file.exists():
        with open(call_file, encoding="utf-8") as f:
            declared = json.load(f)
        unknown = set(declared) - set(DEFAULT_CALL)
        if unknown:
            raise ValueError("{}: unknown call keys {}".format(fixture_dir, unknown))
        call.update(declared)
    return call


class UnexpectedImportError(AssertionError):
    pass


def transform(client: OpenCTIApiClient, bundle: Dict, update: bool, types) -> Dict:
    """pycti's transformation of a bundle, as import_bundle runs it, without what surrounds it."""
    splitter = OpenCTIStix2Splitter()
    _, incompatible, bundles = splitter.split_bundle_with_expectations(
        bundle, False, bundle.get("x_opencti_event_version")
    )
    items = []
    for split_bundle in bundles:
        for item in split_bundle["objects"]:
            item_id = item["id"]
            try:
                client.stix2.import_item(item, update, types, None, split_bundle["id"])
                outcome = "transformed"
            except Exception as error:
                outcome = type(error).__name__
            items.append({"id": item_id, "outcome": outcome})
    return {"items": items, "incompatible": [item["id"] for item in incompatible]}


def record(fixture_dir: Path) -> Dict:
    """Run pycti's transformation on one fixture and return the ordered calls it sent.

    The golden also holds the outcome of each object (transformed, or the error that stopped
    it), the objects the splitter set aside, and the objects pycti drops with an error log.
    """
    call = load_call(fixture_dir)
    raw = json.loads((fixture_dir / "input.json").read_text(encoding="utf-8"))
    now = datetime.fromisoformat(call["now"])
    guess_past_date = OpenCTIStix2Utils.guess_past_date
    with ExitStack() as stack:
        stack.enter_context(utc_timezone())
        stack.enter_context(silenced_logging())
        stack.enter_context(patch.object(OpenCTIApiClient, "_setup_proxy_certificates"))
        stack.enter_context(
            patch(
                "pycti.utils.opencti_stix2_splitter.uuid.uuid4",
                return_value=uuid.UUID(int=0),
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
        session = RecordingSession(World.load(fixture_dir))
        client.session = session
        # pycti drops some objects with an error log only (unknown type): part of the contract
        logged_errors: List[str] = []
        log_error = client.app_logger.error

        def tracked_log_error(message, *args, **kwargs):
            logged_errors.append(message)
            return log_error(message, *args, **kwargs)

        client.app_logger.error = tracked_log_error
        try:
            if call["message_type"] == "event":
                # The worker transforms an event with update forced
                result = transform(client, event_bundle(raw), True, call["types"])
            else:
                result = transform(client, raw, call["update"], call["types"])
            bundle_error = None
        except Exception as error:
            # The whole message cannot be transformed (the splitter fails)
            result = {"items": [], "incompatible": []}
            bundle_error = type(error).__name__
    errors = [item for item in result["items"] if item["outcome"] != "transformed"]
    if (errors or bundle_error) and not call["expect_errors"]:
        raise UnexpectedImportError(
            "{}: the transformation failed, fix the world or declare expect_errors: {} {}".format(
                fixture_dir.name, errors, bundle_error
            )
        )
    return {
        "calls": session.calls,
        **result,
        "bundle_error": bundle_error,
        "logged_errors": logged_errors,
    }


def record_dates() -> List[Dict[str, Optional[str]]]:
    """pycti's guess_past_date on the texts of dates/texts.json, as the importer runs it.

    The platform's port of datefinder and dateutil is checked against this table.
    """
    texts = json.loads((DATES_DIR / DATES_TEXTS_FILE).read_text(encoding="utf-8"))
    now = datetime.fromisoformat(FIXED_NOW)
    with utc_timezone():
        return [
            {
                "label": entry["label"],
                "text": entry["text"],
                "expected": OpenCTIStix2Utils.guess_past_date(entry["text"], now=now),
            }
            for entry in texts
        ]


def fixture_dirs() -> List[Path]:
    return sorted(path.parent for path in FIXTURES_DIR.rglob("input.json"))


def first_difference(expected: Dict, actual: Dict) -> Optional[str]:
    """Describe the first difference, or None when both records are equal."""
    for key in ("items", "incompatible", "bundle_error", "logged_errors"):
        if expected.get(key) != actual.get(key):
            return "{}: expected {}, actual {}".format(
                key, expected.get(key), actual.get(key)
            )
    expected_calls, actual_calls = expected["calls"], actual["calls"]
    for index in range(max(len(expected_calls), len(actual_calls))):
        left = expected_calls[index] if index < len(expected_calls) else None
        right = actual_calls[index] if index < len(actual_calls) else None
        if left != right:
            return "call {}:\n expected {}\n actual   {}".format(
                index + 1,
                json.dumps(left, sort_keys=True),
                json.dumps(right, sort_keys=True),
            )
    return None
