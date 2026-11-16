"""Offline tests of the procedure prototype scripts (scale generator, example bundle)."""

import importlib.util
import json
import re
from pathlib import Path

from pycti.utils.opencti_procedure_utils import normalize_procedure_bundle
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

PROTOTYPE_DIR = Path(__file__).resolve().parents[3] / "prototype" / "procedures"
EXAMPLE_BUNDLE = PROTOTYPE_DIR / "data" / "example-procedures.json"
NAME_PATTERN = re.compile(r"^\w[\w ./-]* via \w[\w ./-]*$")


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, PROTOTYPE_DIR / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load_script("generate_scale_bundle")
build_scale_bundle = generator.build_scale_bundle


def _load_example():
    with open(EXAMPLE_BUNDLE, encoding="utf-8") as file:
        return json.load(file)


def test_scale_bundle_shape():
    b = build_scale_bundle(["attack-pattern--a"], count_per_pattern=300, seed=1)
    procs = [o for o in b["objects"] if o["type"] == "x-procedure"]
    assert len(procs) == 300
    assert len({p["id"] for p in procs}) == 300
    assert all(p["x_technique_refs"] == ["attack-pattern--a"] for p in procs)
    assert (
        build_scale_bundle(["attack-pattern--a"], 300, 1) == b
    )  # seeded, reproducible


def test_scale_bundle_is_a_stix_bundle_with_one_batch_per_pattern():
    b = build_scale_bundle(["attack-pattern--a", "attack-pattern--b"], 5, 7)
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--")
    procs = [o for o in b["objects"] if o["type"] == "x-procedure"]
    assert len(procs) == 10
    refs = [p["x_technique_refs"][0] for p in procs]
    assert refs.count("attack-pattern--a") == 5
    assert refs.count("attack-pattern--b") == 5
    assert all(p["id"].startswith("x-procedure--") for p in procs)


def test_scale_bundle_differs_with_seed():
    first = build_scale_bundle(["attack-pattern--a"], 20, 1)
    second = build_scale_bundle(["attack-pattern--a"], 20, 2)
    assert first != second


def _procedure_ids(bundle, attack_pattern_id=None):
    return [
        o["id"]
        for o in bundle["objects"]
        if o["type"] == "x-procedure"
        and attack_pattern_id in (None, o["x_technique_refs"][0])
    ]


def test_scale_bundle_ids_differ_per_attack_pattern_with_the_same_seed():
    # Two runs with the same seed and another MITRE id must not upsert the
    # same procedures
    first = build_scale_bundle(["attack-pattern--a"], 20, 1)
    second = build_scale_bundle(["attack-pattern--b"], 20, 1)
    assert set(_procedure_ids(first)).isdisjoint(_procedure_ids(second))
    assert first["id"] != second["id"]
    # Each pattern's procedures stay reproducible, alone or with other patterns
    both = build_scale_bundle(["attack-pattern--a", "attack-pattern--b"], 20, 1)
    assert _procedure_ids(both, "attack-pattern--a") == _procedure_ids(first)
    assert _procedure_ids(both, "attack-pattern--b") == _procedure_ids(second)


def test_scale_bundle_names_follow_verb_object_via_method():
    b = build_scale_bundle(["attack-pattern--a"], 50, 3)
    for proc in (o for o in b["objects"] if o["type"] == "x-procedure"):
        assert NAME_PATTERN.match(proc["name"]), proc["name"]
        assert proc["platforms"]


def test_scale_bundle_normalizes_without_warnings():
    b = build_scale_bundle(["attack-pattern--a"], 30, 1)
    normalized, warnings = normalize_procedure_bundle(b)
    assert warnings == []
    assert "x-procedure--" not in json.dumps(normalized)
    relationships = [o for o in normalized["objects"] if o["type"] == "relationship"]
    assert len(relationships) == 30
    assert all(r["relationship_type"] == "implements-technique" for r in relationships)
    assert all(r["target_ref"] == "attack-pattern--a" for r in relationships)


def test_example_bundle_normalizes_cleanly():
    bundle = _load_example()
    assert bundle["type"] == "bundle"
    normalized, warnings = normalize_procedure_bundle(bundle)
    assert warnings == []
    assert "x-procedure--" not in json.dumps(normalized)
    types = {o["type"] for o in normalized["objects"]}
    assert "x-procedure" not in types
    assert "x-opencti-procedure" in types
    procedures = [
        o for o in normalized["objects"] if o["type"] == "x-opencti-procedure"
    ]
    assert len(procedures) == 2
    for proc in procedures:
        assert "x_technique_refs" not in proc
        assert "x_vulnerability_refs" not in proc
        assert "tactics" not in proc
        assert proc["x_fingerprint"]


def test_example_bundle_keeps_every_reference_resolvable():
    """Objects the bundle must carry itself, as opposed to the MITRE attack patterns."""
    normalized, _ = normalize_procedure_bundle(_load_example())
    ids = {o["id"] for o in normalized["objects"]}
    for obj in normalized["objects"]:
        for key, value in obj.items():
            refs = []
            if key.endswith("_ref") and isinstance(value, str):
                refs = [value]
            elif key.endswith("_refs") and isinstance(value, list):
                refs = value
            for ref in refs:
                if ref.startswith("attack-pattern--"):
                    continue  # resolved by the platform MITRE dataset
                assert ref in ids, obj["id"] + " -> " + ref


def test_example_bundle_has_no_customer_data():
    text = EXAMPLE_BUNDLE.read_text(encoding="utf-8").lower()
    assert "customer" not in text


def test_split_keeps_relationships_to_attack_patterns_not_in_the_bundle():
    """import_bundle splits with cleanup_inconsistent_bundle=False (its default)."""
    splitter = OpenCTIStix2Splitter()
    _, incompatible, bundles = splitter.split_bundle_with_expectations(
        _load_example(), False, None
    )
    assert incompatible == []
    kept = set()
    for split in bundles:
        for obj in split["objects"]:
            if (
                obj["type"] == "relationship"
                and obj["relationship_type"] == "implements-technique"
            ):
                kept.add(obj["target_ref"])
    assert kept == {
        "attack-pattern--e94e1030-0b72-4b37-ab03-00e1a81a665e",
        "attack-pattern--4c209832-0086-42bf-b4ac-84cdc2434a72",
        "attack-pattern--ed0f9d93-0ae4-4feb-bec9-7f02016a6189",
        "attack-pattern--be2dcee9-a7a7-4e38-afd6-21b31ecc3d63",
    }


def test_split_with_cleanup_would_drop_those_relationships():
    """Why the seed script must not turn cleanup_inconsistent_bundle on."""
    splitter = OpenCTIStix2Splitter()
    _, _, bundles = splitter.split_bundle_with_expectations(
        _load_example(), False, None, cleanup_inconsistent_bundle=True
    )
    targets = {
        obj["target_ref"]
        for split in bundles
        for obj in split["objects"]
        if obj["type"] == "relationship"
        and obj["relationship_type"] == "implements-technique"
    }
    assert targets == set()


def test_seed_script_imports_each_file_and_prints_counts_and_warnings(tmp_path):
    from unittest.mock import MagicMock

    seed = _load_script("seed_procedures")
    bundle = _load_example()
    # a report source that is not in the bundle makes the normalizer warn
    bundle["objects"][-1]["x_source_refs"].append(
        "report--00000000-0000-4000-8000-000000000000"
    )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    client = MagicMock()
    client.stix2.import_bundle_from_file.return_value = (
        [{"id": "a", "type": "x-opencti-procedure"}],
        [],
    )
    lines = []
    failed = seed.seed_file(client, str(path), out=lines.append)
    assert failed == 0
    client.stix2.import_bundle_from_file.assert_called_once_with(str(path), update=True)
    text = "\n".join(lines)
    assert "2 procedure(s) in the file" in text
    assert "x-opencti-procedure: 1" in text
    assert "warning: Procedure x-opencti-procedure--" in text
