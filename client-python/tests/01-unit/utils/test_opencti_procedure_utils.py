"""Offline tests of the procedure bundle normalizer and fingerprint."""

import copy
import json
from unittest.mock import MagicMock

from pycti.entities.opencti_procedure import Procedure
from pycti.utils.opencti_procedure_utils import (
    compute_procedure_fingerprint,
    normalize_procedure_bundle,
)
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

PROC_UUID = "3f6c2a1e-6d1f-4b8a-9b55-0c2f1e6e2d11"
X_PROC = "x-procedure--" + PROC_UUID
OCTI_PROC = "x-opencti-procedure--" + PROC_UUID
AP1 = "attack-pattern--e94e1030-0b72-4b37-ab03-00e1a81a665e"
AP2 = "attack-pattern--4c209832-0086-42bf-b4ac-84cdc2434a72"
VULN = "vulnerability--0f5f2c9b-3c0e-4d0f-8e64-0a5f7d4c1b2a"
IDENTITY = "identity--7b1e9a52-1f5a-4bfb-8b1e-3f8c2a9d6e01"
REPORT = "report--5d3b8c1a-9e2f-4a6b-8c7d-1e0f2a3b4c5d"
INTRUSION_SET = "intrusion-set--1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
NOTE = "note--9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
MARKING = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def _procedure_object(**overrides):
    proc = {
        "type": "x-procedure",
        "spec_version": "2.1",
        "id": X_PROC,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Run encoded PowerShell via scheduled task",
    }
    proc.update(overrides)
    return proc


def _bundle(*objects):
    return {
        "type": "bundle",
        "id": "bundle--0e3c1f7a-2b4d-4e6f-8a9b-1c2d3e4f5a6b",
        "objects": list(objects),
    }


def _report(object_refs):
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": REPORT,
        "name": "Sample report",
        "published": "2026-01-01T00:00:00.000Z",
        "object_refs": list(object_refs),
    }


def bundle_with(
    tactics=None,
    platforms=None,
    source_refs=None,
    include_report=False,
    fingerprint=None,
):
    overrides = {}
    if tactics is not None:
        overrides["tactics"] = tactics
    if platforms is not None:
        overrides["platforms"] = platforms
    if source_refs is not None:
        overrides["x_source_refs"] = source_refs
    if fingerprint is not None:
        overrides["x_fingerprint"] = fingerprint
    objects = [_procedure_object(**overrides)]
    if include_report:
        objects.append(_report([IDENTITY]))
    return _bundle(*objects)


def bundle_with_refs(techniques=(), vulnerabilities=(), existing_rel_to=None):
    proc = _procedure_object(
        x_technique_refs=list(techniques),
        x_vulnerability_refs=list(vulnerabilities),
        object_marking_refs=[MARKING],
        created_by_ref=IDENTITY,
    )
    objects = [proc]
    if existing_rel_to is not None:
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d",
                "relationship_type": "implements-technique",
                "source_ref": X_PROC,
                "target_ref": existing_rel_to,
            }
        )
    return _bundle(*objects)


def bundle_with_x_procedure_and_refs():
    return _bundle(
        _procedure_object(x_technique_refs=[AP1], x_source_refs=[REPORT]),
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--7e6d5c4b-3a2f-4e1d-8c0b-9a8f7e6d5c4b",
            "relationship_type": "uses",
            "source_ref": INTRUSION_SET,
            "target_ref": X_PROC,
        },
        _report([X_PROC]),
        {
            "type": "note",
            "spec_version": "2.1",
            "id": NOTE,
            "content": "Seen in the wild",
            "object_refs": [X_PROC],
            "extensions": {
                "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                    "extension_type": "property-extension",
                    "related_ref": X_PROC,
                }
            },
        },
    )


def sample_bundle():
    return _bundle(
        _procedure_object(
            x_procedure_type="execution",
            platforms=["Windows", "Linux", "windows"],
            tactics=["execution", "persistence"],
            kill_chain_phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                {"kill_chain_name": "lockheed-martin", "phase_name": "installation"},
            ],
            x_technique_refs=[AP1, AP2],
            x_vulnerability_refs=[VULN],
            x_source_refs=[IDENTITY, REPORT],
        ),
        _report([]),
    )


def procedure(bundle):
    procs = [o for o in bundle["objects"] if o["type"] == "x-opencti-procedure"]
    assert len(procs) == 1
    return procs[0]


def relationships(bundle):
    return [o for o in bundle["objects"] if o["type"] == "relationship"]


def report(bundle):
    return next(o for o in bundle["objects"] if o["type"] == "report")


def test_fingerprint_matches_shared_vector():
    # Review Focus 1: same vectors as the TypeScript procedure-fingerprint test
    assert (
        compute_procedure_fingerprint(
            [AP1, AP2],
            ["windows"],
            ["execution", "defense-evasion"],
        )
        == "a85ef1be299c2196e535393a59df5021"
    )
    assert (
        compute_procedure_fingerprint([], [], []) == "d00d9be38948fb145335e663ae2d01c0"
    )


def test_renames_type_and_every_reference():  # Review Focus 5
    out, _ = normalize_procedure_bundle(bundle_with_x_procedure_and_refs())
    assert "x-procedure--" not in json.dumps(out)
    assert procedure(out)["type"] == "x-opencti-procedure"
    assert procedure(out)["id"] == OCTI_PROC
    uses = next(r for r in relationships(out) if r["relationship_type"] == "uses")
    assert uses["target_ref"] == OCTI_PROC
    assert report(out)["object_refs"] == [OCTI_PROC]
    note = next(o for o in out["objects"] if o["type"] == "note")
    assert note["object_refs"] == [OCTI_PROC]


def test_does_not_mutate_input():
    bundle = sample_bundle()
    original = copy.deepcopy(bundle)
    normalize_procedure_bundle(bundle)
    assert bundle == original


def test_technique_and_vulnerability_refs_become_relationships():
    out, _ = normalize_procedure_bundle(
        bundle_with_refs(techniques=[AP1, AP2], vulnerabilities=[VULN])
    )
    rels = relationships(out)
    assert {(r["relationship_type"], r["target_ref"]) for r in rels} == {
        ("implements-technique", AP1),
        ("implements-technique", AP2),
        ("exploits", VULN),
    }
    assert all(r["source_ref"] == OCTI_PROC for r in rels)
    # The generated relationships keep the procedure's author and markings
    assert all(r["object_marking_refs"] == [MARKING] for r in rels)
    assert all(r["created_by_ref"] == IDENTITY for r in rels)
    assert "x_technique_refs" not in procedure(out)
    assert "x_vulnerability_refs" not in procedure(out)


def test_existing_relationship_not_duplicated():  # Review Focus 2
    # The existing relationship still points at the x-procedure id: it must be
    # matched after the rename, so no second implements-technique is generated.
    out, _ = normalize_procedure_bundle(
        bundle_with_refs(techniques=[AP1], existing_rel_to=AP1)
    )
    assert len([r for r in relationships(out) if r["target_ref"] == AP1]) == 1


def test_duplicate_refs_generate_one_relationship():  # Review Focus 2
    out, _ = normalize_procedure_bundle(bundle_with_refs(techniques=[AP1, AP1]))
    assert len(relationships(out)) == 1


def test_generated_relationship_ids_are_deterministic():  # Review Focus 2
    a, _ = normalize_procedure_bundle(bundle_with_refs(techniques=[AP1]))
    b, _ = normalize_procedure_bundle(bundle_with_refs(techniques=[AP1]))
    assert relationships(a)[0]["id"] == relationships(b)[0]["id"]
    assert relationships(a)[0]["id"].startswith("relationship--")
    # A different target gives a different id
    c, _ = normalize_procedure_bundle(bundle_with_refs(techniques=[AP2]))
    assert relationships(c)[0]["id"] != relationships(a)[0]["id"]


def test_tactics_become_mitre_kill_chain_phases():
    p = procedure(
        normalize_procedure_bundle(
            bundle_with(tactics=["execution", "defense-evasion"])
        )[0]
    )
    assert {"kill_chain_name": "mitre-attack", "phase_name": "execution"} in p[
        "kill_chain_phases"
    ]
    assert {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"} in p[
        "kill_chain_phases"
    ]
    assert "tactics" not in p


def test_tactics_merge_with_existing_kill_chain_phases():
    p = procedure(normalize_procedure_bundle(sample_bundle())[0])
    assert p["kill_chain_phases"] == [
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
        {"kill_chain_name": "lockheed-martin", "phase_name": "installation"},
        {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
    ]


def test_platforms_lowercased():  # Review Focus 3
    # "Windows" must land on the existing lowercase "windows" vocabulary entry
    assert procedure(
        normalize_procedure_bundle(bundle_with(platforms=["Windows", "Office Suite"]))[
            0
        ]
    )["platforms"] == ["windows", "office suite"]


def test_report_source_becomes_containment():
    out, warnings = normalize_procedure_bundle(
        bundle_with(source_refs=[IDENTITY, REPORT], include_report=True)
    )
    assert procedure(out)["x_source_refs"] == [IDENTITY]
    assert procedure(out)["id"] in report(out)["object_refs"]
    assert warnings == []


def test_report_source_not_in_bundle_is_dropped_with_warning():  # Review Focus 4
    out, warnings = normalize_procedure_bundle(
        bundle_with(source_refs=[REPORT], include_report=False)
    )
    assert procedure(out)["x_source_refs"] == [] and len(warnings) == 1
    assert REPORT in warnings[0] and OCTI_PROC in warnings[0]


def test_fingerprint_kept_or_computed():
    assert (
        procedure(normalize_procedure_bundle(bundle_with(fingerprint="keep-me"))[0])[
            "x_fingerprint"
        ]
        == "keep-me"
    )
    assert (
        len(
            procedure(normalize_procedure_bundle(bundle_with(fingerprint=None))[0])[
                "x_fingerprint"
            ]
        )
        == 32
    )


def test_computed_fingerprint_uses_refs_lowercased_platforms_and_mitre_phases():
    p = procedure(normalize_procedure_bundle(sample_bundle())[0])
    # techniques as written in the bundle, lowercased platforms, and only the
    # mitre-attack phases (lockheed-martin ignored)
    assert p["x_fingerprint"] == compute_procedure_fingerprint(
        [AP1, AP2], ["windows", "linux"], ["execution", "persistence"]
    )


def test_idempotent():
    once, _ = normalize_procedure_bundle(sample_bundle())
    twice, _ = normalize_procedure_bundle(once)
    assert once == twice


def test_bundle_without_procedure_is_unchanged():
    bundle = _bundle(_report([IDENTITY]))
    out, warnings = normalize_procedure_bundle(bundle)
    assert out == bundle and warnings == []


def test_splitter_normalizes_and_logs_warnings():
    logger = MagicMock()
    splitter = OpenCTIStix2Splitter(logger=logger)
    _, incompatible, bundles = splitter.split_bundle_with_expectations(
        _bundle(_procedure_object(x_technique_refs=[AP1], x_source_refs=[REPORT])),
        use_json=False,
    )
    objects = [o for b in bundles for o in b["objects"]]
    assert {o["type"] for o in objects} == {"x-opencti-procedure", "relationship"}
    assert logger.warning.call_count == 1
    assert REPORT in logger.warning.call_args[0][0]
    assert splitter.warnings == [logger.warning.call_args[0][0]]
    # Warnings never go to the incompatible items, which callers read as dicts
    assert incompatible == []


def test_splitter_without_logger_keeps_warnings_out_of_incompatible_items():
    splitter = OpenCTIStix2Splitter()
    _, incompatible, _ = splitter.split_bundle_with_expectations(
        bundle_with(source_refs=[REPORT]), use_json=False
    )
    assert incompatible == []
    assert len(splitter.warnings) == 1 and REPORT in splitter.warnings[0]


def test_import_from_stix2_maps_procedure_fields():
    opencti = MagicMock()
    opencti.query.return_value = {"data": {"procedureAdd": {"id": "internal-id"}}}
    opencti.process_multiple_fields.side_effect = lambda data: data
    opencti.stix2.convert_markdown.side_effect = lambda text: text
    opencti.get_attribute_in_extension.return_value = None
    stix_object, _ = normalize_procedure_bundle(sample_bundle())
    proc = procedure(stix_object)
    proc["x_observable_refs"] = ["process--1"]
    proc["x_command_ref"] = "process--2"
    proc["description"] = "Runs a payload"

    result = Procedure(opencti).import_from_stix2(
        stixObject=proc,
        extras={
            "kill_chain_phases_ids": ["kcp-1"],
            "created_by_id": "author-id",
            "object_marking_ids": ["marking-id"],
        },
        update=True,
    )

    assert result == {"id": "internal-id"}
    variables = opencti.query.call_args[0][1]["input"]
    assert variables["stix_id"] == OCTI_PROC
    assert variables["name"] == proc["name"]
    assert variables["description"] == "Runs a payload"
    assert variables["x_procedure_type"] == "execution"
    assert variables["x_mitre_platforms"] == ["windows", "linux"]
    assert variables["x_fingerprint"] == proc["x_fingerprint"]
    assert variables["procedureObservables"] == ["process--1"]
    assert variables["procedureCommand"] == "process--2"
    assert variables["procedureSources"] == [IDENTITY]
    assert variables["killChainPhases"] == ["kcp-1"]
    assert variables["createdBy"] == "author-id"
    assert variables["objectMarking"] == ["marking-id"]
    assert variables["update"] is True
    assert "techniques" not in variables


def test_generate_id_from_data_returns_the_given_id():
    assert Procedure.generate_id_from_data({"id": OCTI_PROC}) == OCTI_PROC


def test_tactics_are_normalised_to_mitre_phase_names():
    p = procedure(
        normalize_procedure_bundle(
            bundle_with(tactics=["Defense Evasion", " Command_and_Control "])
        )[0]
    )
    assert [phase["phase_name"] for phase in p["kill_chain_phases"]] == [
        "defense-evasion",
        "command-and-control",
    ]


def test_fingerprint_of_title_case_tactic_equals_the_phase_name_one():
    title_case = procedure(
        normalize_procedure_bundle(bundle_with(tactics=["Defense Evasion"]))[0]
    )
    phase_name = procedure(
        normalize_procedure_bundle(bundle_with(tactics=["defense-evasion"]))[0]
    )
    assert title_case["x_fingerprint"] == phase_name["x_fingerprint"]
    assert title_case["x_fingerprint"] == compute_procedure_fingerprint(
        [], [], ["defense-evasion"]
    )


def test_scalar_list_values_are_wrapped_in_a_list():
    out, warnings = normalize_procedure_bundle(
        _bundle(
            _procedure_object(
                platforms="Windows",
                tactics="Execution",
                x_technique_refs=AP1,
                x_vulnerability_refs=VULN,
                x_source_refs=IDENTITY,
                x_observable_refs="process--1",
            )
        )
    )
    p = procedure(out)
    assert warnings == []
    assert p["platforms"] == ["windows"]
    assert p["kill_chain_phases"] == [
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
    ]
    assert {(r["relationship_type"], r["target_ref"]) for r in relationships(out)} == {
        ("implements-technique", AP1),
        ("exploits", VULN),
    }
    assert p["x_source_refs"] == [IDENTITY]
    assert p["x_observable_refs"] == ["process--1"]


def bundle_with_bad_values():
    return _bundle(
        _procedure_object(
            platforms=["Windows", 3],
            tactics=["execution", None],
            kill_chain_phases=[
                {"kill_chain_name": "mitre-attack"},
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                "persistence",
            ],
            x_technique_refs=[AP1, {"id": AP2}],
            x_vulnerability_refs=[7],
            x_source_refs=[IDENTITY, None],
            x_observable_refs=["process--1", 1],
        )
    )


def test_bad_values_are_skipped_with_a_warning():
    out, warnings = normalize_procedure_bundle(bundle_with_bad_values())
    p = procedure(out)
    assert p["platforms"] == ["windows"]
    assert p["kill_chain_phases"] == [
        {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
    ]
    assert [(r["relationship_type"], r["target_ref"]) for r in relationships(out)] == [
        ("implements-technique", AP1)
    ]
    assert p["x_source_refs"] == [IDENTITY]
    assert p["x_observable_refs"] == ["process--1"]
    assert p["x_fingerprint"] == compute_procedure_fingerprint(
        [AP1], ["windows"], ["persistence", "execution"]
    )
    # platforms, tactics, 2 kill chain phases, techniques, vulnerabilities,
    # sources, observables
    assert len(warnings) == 8
    assert all(OCTI_PROC in warning for warning in warnings)


def test_splitter_does_not_reject_a_bundle_with_bad_values():
    logger = MagicMock()
    splitter = OpenCTIStix2Splitter(logger=logger)
    _, incompatible, bundles = splitter.split_bundle_with_expectations(
        bundle_with_bad_values(), use_json=False
    )
    objects = [o for b in bundles for o in b["objects"]]
    assert "x-opencti-procedure" in {o["type"] for o in objects}
    assert incompatible == []
    assert logger.warning.call_count == 8
