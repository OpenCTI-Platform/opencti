"""pycti's STIX importer against its committed goldens (tests/data/import-conformance).

The goldens are the calls another importer (the platform's) must reproduce. A failure here
means pycti's import behaviour changed: regenerate them with
``python -m tests.import_conformance.generate`` and review the diff.
"""

import inspect
import json
import re

import pytest

from pycti import OpenCTIStix2
from pycti.utils.opencti_stix2_utils import (
    STIX_CORE_OBJECTS,
    STIX_CYBER_OBSERVABLE_MAPPING,
    STIX_META_OBJECTS,
)
from tests.import_conformance.generate import serialize
from tests.import_conformance.recorder import (
    ACCEPTED_DIFFERENCES_FILE,
    DATES_DIR,
    EXPECTED_FILE,
    FIXTURES_DIR,
    first_difference,
    fixture_dirs,
    record,
    record_dates,
)


@pytest.mark.parametrize(
    "fixture_dir",
    fixture_dirs(),
    ids=lambda path: path.relative_to(FIXTURES_DIR).as_posix(),
)
def test_import_matches_golden(fixture_dir):
    # The text, as generate --check compares it: Python == would take 1 for 1.0 or True
    expected = (fixture_dir / EXPECTED_FILE).read_text(encoding="utf-8")
    actual = serialize(record(fixture_dir))
    assert actual == expected, first_difference(
        json.loads(expected), json.loads(actual)
    )


def test_dates_match_golden():
    expected = (DATES_DIR / EXPECTED_FILE).read_text(encoding="utf-8")
    assert serialize(record_dates()) == expected


# Types the platform and OpenAEV only send in the 2.1 form (new-sdo extension, no 2.0
# converter): they have no legacy fixture
EXTENSION_ONLY_TYPES = {
    "language",
    "security-coverage",
    "security-coverage-result",
    "vocabulary",
}


def _canonical_type(stix_type):
    return stix_type.removeprefix("x-opencti-").removeprefix("x-mitre-")


def _carries_operation(stix_object):
    extensions = stix_object.get("extensions") or {}
    return "opencti_operation" in stix_object or any(
        isinstance(extension, dict) and "opencti_operation" in extension
        for extension in extensions.values()
    )


# pycti's task create sends no stix_id: its creation is told by its root
CREATION_ROOTS_WITHOUT_STIX_ID = {"task": "taskAdd"}


def _is_created(stix_object, calls):
    """Whether pycti sent a creation mutation for the object (a log or a scope filter is not)."""
    for call in calls:
        if call["op"] != "mutation" or not call["root"].endswith("Add"):
            continue
        variables = call["variables"] if isinstance(call["variables"], dict) else {}
        inputs = (
            variables.get("input") if isinstance(variables.get("input"), dict) else {}
        )
        if stix_object["id"] in (variables.get("stix_id"), inputs.get("stix_id")):
            return True
        if call["root"] == CREATION_ROOTS_WITHOUT_STIX_ID.get(
            _canonical_type(stix_object["type"])
        ):
            return True
    return False


def _imported_objects(fixture_dir):
    """The objects pycti imported without error, None when the fixture does not count.

    A fixture counts when pycti transformed every object of it, failed on none and is not an
    accepted difference; an object counts when it was not set aside, is not an operation applied
    to an existing element, and pycti sent a creation mutation for it.
    """
    golden = json.loads((fixture_dir / EXPECTED_FILE).read_text(encoding="utf-8"))
    if golden["bundle_error"] is not None or any(
        item["outcome"] != "transformed" for item in golden["items"]
    ):
        return None
    message = json.loads((fixture_dir / "input.json").read_text(encoding="utf-8"))
    # A bundle, or a stream event carrying one object
    objects = message["objects"] if "objects" in message else [message["data"]]
    transformed = {item["id"] for item in golden["items"]}
    return [
        stix_object
        for stix_object in objects
        if stix_object["id"] in transformed
        and not _carries_operation(stix_object)
        and _is_created(stix_object, golden["calls"])
    ]


def test_every_imported_type_has_fixtures_in_both_forms():
    imported_types = {
        _canonical_type(stix_type)
        for stix_type in STIX_META_OBJECTS
        + STIX_CORE_OBJECTS
        + list(STIX_CYBER_OBSERVABLE_MAPPING)
        + ["relationship", "sighting"]
    }
    accepted = json.loads(ACCEPTED_DIFFERENCES_FILE.read_text(encoding="utf-8"))
    covered = set()
    for fixture_dir in fixture_dirs():
        if fixture_dir.relative_to(FIXTURES_DIR).as_posix() in accepted:
            continue
        objects = _imported_objects(fixture_dir)
        form = fixture_dir.name.rsplit(".", 1)[1]
        for stix_object in objects or []:
            covered.add((_canonical_type(stix_object["type"]), form))
    missing = sorted(
        "{}.{}".format(stix_type, form)
        for stix_type in imported_types
        for form in ("ext", "legacy")
        if (stix_type, form) not in covered
        and not (form == "legacy" and stix_type in EXTENSION_ONLY_TYPES)
    )
    assert missing == [], "types without fixture: {}".format(", ".join(missing))


# Stream event types a sync sends to the worker (opencti-worker push_handler.py)
SYNC_EVENT_TYPES = {"create", "update", "merge", "delete"}


def test_every_operation_has_fixtures():
    # The operations pycti dispatches, read from its source so that a new one fails this test
    source = inspect.getsource(OpenCTIStix2.apply_opencti_operation)
    operations = set(re.findall(r'operation == "(\w+)"', source))
    covered = set()
    for fixture_dir in fixture_dirs():
        parts = fixture_dir.relative_to(FIXTURES_DIR).parts
        if parts[0] == "ops":
            covered.add((parts[1], parts[2].rsplit(".", 1)[1]))
    missing = sorted(
        ["{}.ext".format(op) for op in operations if (op, "ext") not in covered]
        + ["{}.top".format(op) for op in SYNC_EVENT_TYPES if (op, "top") not in covered]
    )
    assert len(operations) >= 22
    assert missing == [], "operations without fixture: {}".format(", ".join(missing))
