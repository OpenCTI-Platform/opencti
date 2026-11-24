"""Procedure helpers: fingerprint and ``x-procedure`` bundle normalizer.

A third-party ``x-procedure`` object carries its links as properties
(``x_technique_refs``, ``x_vulnerability_refs``, ``tactics``, report entries in
``x_source_refs``). OpenCTI stores them once, as relationships, kill chain
phases and report containment, so the normalizer rewrites the bundle before
it is split and imported.
"""

import copy
import hashlib
import re
from typing import Any, Dict, List, Tuple

from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship

PROCEDURE_STIX_TYPE = "x-opencti-procedure"
THIRD_PARTY_PROCEDURE_STIX_TYPE = "x-procedure"
PROCEDURE_STIX_TYPES = (PROCEDURE_STIX_TYPE, THIRD_PARTY_PROCEDURE_STIX_TYPE)
_THIRD_PARTY_ID_PREFIX = THIRD_PARTY_PROCEDURE_STIX_TYPE + "--"
_ID_PREFIX = PROCEDURE_STIX_TYPE + "--"
MITRE_ATTACK_KILL_CHAIN = "mitre-attack"
FINGERPRINT_LENGTH = 32

# Procedure property -> relationship type created from it
_REFS_TO_RELATIONSHIPS = (
    ("x_technique_refs", "implements-technique"),
    ("x_vulnerability_refs", "exploits"),
)
# List properties of a procedure whose items must be strings
_STRING_LIST_PROPERTIES = (
    "platforms",
    "tactics",
    "x_technique_refs",
    "x_vulnerability_refs",
    "x_source_refs",
    "x_observable_refs",
)


def _sorted_unique(values: List[str]) -> str:
    return "|".join(sorted(set(values)))


def compute_procedure_fingerprint(
    technique_ids: List[str], platforms: List[str], phase_names: List[str]
) -> str:
    """Compute the fingerprint of a procedure.

    sha256 hex (utf-8) of "technique ids :: platforms :: mitre-attack phase
    names", each part deduplicated, sorted and joined by "|", cut to 32
    characters. Must match the backend ``computeProcedureFingerprint`` byte
    for byte.

    :param technique_ids: attack pattern ids the procedure implements
    :type technique_ids: list[str]
    :param platforms: platforms of the procedure (lowercase vocabulary values)
    :type platforms: list[str]
    :param phase_names: phase names of the procedure ``mitre-attack`` kill chain phases
    :type phase_names: list[str]
    :return: the 32 characters fingerprint
    :rtype: str
    """
    material = "::".join(
        _sorted_unique(part) for part in (technique_ids, platforms, phase_names)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]


def _mentions_procedure(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith(_THIRD_PARTY_ID_PREFIX)
    if isinstance(value, dict):
        if value.get("type") in PROCEDURE_STIX_TYPES:
            return True
        return any(_mentions_procedure(item) for item in value.values())
    if isinstance(value, list):
        return any(_mentions_procedure(item) for item in value)
    return False


def _rename_third_party_ids(value: Any) -> Any:
    """Rewrite every ``x-procedure--`` id and type, in place, at any depth."""
    if isinstance(value, dict):
        if value.get("type") == THIRD_PARTY_PROCEDURE_STIX_TYPE:
            value["type"] = PROCEDURE_STIX_TYPE
        for key, item in value.items():
            value[key] = _rename_third_party_ids(item)
        return value
    if isinstance(value, list):
        return [_rename_third_party_ids(item) for item in value]
    if isinstance(value, str) and value.startswith(_THIRD_PARTY_ID_PREFIX):
        return _ID_PREFIX + value[len(_THIRD_PARTY_ID_PREFIX) :]
    return value


def _unique(values: List[Any]) -> List[Any]:
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _warn(proc: Dict, message: str, warnings: List[str]) -> None:
    warnings.append("Procedure " + str(proc.get("id")) + ": " + message)


def _clean_string_lists(proc: Dict, warnings: List[str]) -> None:
    """Make every list property a list of strings.

    A scalar value is wrapped in a list (``"platforms": "Windows"``); a value
    that is not a string is dropped with a warning instead of failing the
    whole bundle.
    """
    for key in _STRING_LIST_PROPERTIES:
        if proc.get(key) is None:
            continue
        values = proc[key]
        if not isinstance(values, (list, tuple)):
            values = [values]
        kept = []
        for value in values:
            if isinstance(value, str):
                kept.append(value)
            else:
                _warn(
                    proc,
                    key + " value " + repr(value) + " is not a string, it is dropped",
                    warnings,
                )
        proc[key] = kept


def _clean_kill_chain_phases(proc: Dict, warnings: List[str]) -> None:
    """Drop, with a warning, the kill chain phases without a phase name."""
    if proc.get("kill_chain_phases") is None:
        return
    phases = proc["kill_chain_phases"]
    if not isinstance(phases, (list, tuple)):
        phases = [phases]
    kept = []
    for phase in phases:
        if isinstance(phase, dict) and isinstance(phase.get("phase_name"), str):
            kept.append(phase)
        else:
            _warn(
                proc,
                "kill chain phase " + repr(phase) + " has no phase name, it is dropped",
                warnings,
            )
    proc["kill_chain_phases"] = kept


def lowercase_platforms(platforms: Any) -> List[str]:
    """Lowercase platforms, as the platforms vocabulary values are.

    A scalar is wrapped in a list; values that are not strings are dropped;
    duplicates are removed, order kept.

    :param platforms: platforms as written in a STIX object
    :type platforms: list[str] or str
    :return: the lowercased platforms
    :rtype: list[str]
    """
    if not isinstance(platforms, (list, tuple)):
        platforms = [platforms]
    return _unique([p.strip().lower() for p in platforms if isinstance(p, str)])


def _lowercase_platforms(proc: Dict) -> None:
    if proc.get("platforms") is not None:
        proc["platforms"] = lowercase_platforms(proc["platforms"])


def describe_unnormalized_procedure(stix_object: Dict) -> List[str]:
    """List what a procedure object still carries that the normalizer converts.

    An empty list means the object is normalized. Otherwise, each entry names
    a property the import alone does not convert, and what happens to it.

    :param stix_object: STIX procedure object
    :type stix_object: dict
    :return: the unconverted properties, as readable descriptions
    :rtype: list[str]
    """
    found = []
    if stix_object.get("type") == THIRD_PARTY_PROCEDURE_STIX_TYPE:
        found.append("type x-procedure (references to its id are not renamed)")
    for key in ("x_technique_refs", "x_vulnerability_refs", "tactics"):
        if stix_object.get(key):
            found.append(key + " (lost)")
    source_refs = stix_object.get("x_source_refs") or []
    if not isinstance(source_refs, (list, tuple)):
        source_refs = [source_refs]
    if any(isinstance(ref, str) and ref.startswith("report--") for ref in source_refs):
        found.append("report entries of x_source_refs (no report containment)")
    platforms = stix_object.get("platforms") or []
    if not isinstance(platforms, (list, tuple)):
        platforms = [platforms]
    if any(isinstance(p, str) and p != p.lower() for p in platforms):
        found.append("uppercase platforms (lowercased here)")
    return found


def _tactic_to_phase_name(tactic: str) -> str:
    """``"Defense Evasion"`` or ``"defense_evasion"`` -> ``"defense-evasion"``."""
    return re.sub(r"[\s_]+", "-", tactic.strip().lower())


def _tactics_to_kill_chain_phases(proc: Dict) -> None:
    if "tactics" not in proc:
        return
    tactics = proc.pop("tactics") or []
    phases = list(proc.get("kill_chain_phases") or []) + [
        {
            "kill_chain_name": MITRE_ATTACK_KILL_CHAIN,
            "phase_name": _tactic_to_phase_name(tactic),
        }
        for tactic in tactics
    ]
    deduplicated = []
    seen = set()
    for phase in phases:
        key = (phase.get("kill_chain_name"), phase.get("phase_name"))
        if key not in seen:
            seen.add(key)
            deduplicated.append(phase)
    proc["kill_chain_phases"] = deduplicated


def _fill_fingerprint(proc: Dict) -> None:
    if proc.get("x_fingerprint"):
        return
    phase_names = [
        phase["phase_name"]
        for phase in proc.get("kill_chain_phases") or []
        if phase.get("kill_chain_name") == MITRE_ATTACK_KILL_CHAIN
    ]
    proc["x_fingerprint"] = compute_procedure_fingerprint(
        proc.get("x_technique_refs") or [],
        proc.get("platforms") or [],
        phase_names,
    )


def _refs_to_relationships(proc: Dict, existing: set) -> List[Dict]:
    relationships = []
    for refs_key, relationship_type in _REFS_TO_RELATIONSHIPS:
        for target_ref in proc.pop(refs_key, None) or []:
            key = (proc["id"], relationship_type, target_ref)
            if key in existing:
                continue
            existing.add(key)
            relationship = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": StixCoreRelationship.generate_id(
                    relationship_type, proc["id"], target_ref
                ),
                "relationship_type": relationship_type,
                "source_ref": proc["id"],
                "target_ref": target_ref,
            }
            if proc.get("created_by_ref") is not None:
                relationship["created_by_ref"] = proc["created_by_ref"]
            if proc.get("object_marking_refs"):
                relationship["object_marking_refs"] = list(proc["object_marking_refs"])
            relationships.append(relationship)
    return relationships


def _report_sources_to_containment(
    proc: Dict, reports: Dict[str, Dict], warnings: List[str]
) -> None:
    if proc.get("x_source_refs") is None:
        return
    kept = []
    for source_ref in proc["x_source_refs"]:
        if not source_ref.startswith("report--"):
            kept.append(source_ref)
            continue
        container = reports.get(source_ref)
        if container is None:
            warnings.append(
                "Procedure "
                + proc["id"]
                + ": source "
                + source_ref
                + " is a report that is not in the bundle, the reference is dropped"
            )
            continue
        object_refs = container.setdefault("object_refs", [])
        if proc["id"] not in object_refs:
            object_refs.append(proc["id"])
    proc["x_source_refs"] = kept


def normalize_procedure_bundle(bundle: Dict) -> Tuple[Dict, List[str]]:
    """Convert the procedures of a STIX bundle to the OpenCTI representation.

    In order: ``x-procedure`` type and ids are renamed to
    ``x-opencti-procedure`` everywhere in the bundle; scalar list properties
    are wrapped in a list, and values that are not strings, or kill chain
    phases without a phase name, are dropped with a warning; ``platforms`` are
    lowercased; ``tactics`` become ``mitre-attack`` kill chain phases, their
    name lowercased with spaces and underscores turned to hyphens; a
    missing ``x_fingerprint`` is computed; ``x_technique_refs`` and
    ``x_vulnerability_refs`` become ``implements-technique`` and ``exploits``
    relationships with deterministic ids, skipping the ones already in the
    bundle; report ids in ``x_source_refs`` become the report containment,
    or are dropped with a warning when the report is not in the bundle.

    The input bundle is not modified. The function is idempotent. A bundle
    without any procedure is returned as is.

    :param bundle: STIX 2.1 bundle
    :type bundle: dict
    :return: the rewritten bundle and the list of warnings
    :rtype: tuple[dict, list[str]]
    """
    if not _mentions_procedure(bundle.get("objects") or []):
        return bundle, []
    bundle = _rename_third_party_ids(copy.deepcopy(bundle))
    objects = bundle["objects"]
    procedures = [o for o in objects if o.get("type") == PROCEDURE_STIX_TYPE]
    reports = {o["id"]: o for o in objects if o.get("type") == "report"}
    existing_relationships = {
        (o.get("source_ref"), o.get("relationship_type"), o.get("target_ref"))
        for o in objects
        if o.get("type") == "relationship"
    }
    warnings = []
    new_relationships = []
    for proc in procedures:
        _clean_string_lists(proc, warnings)
        _clean_kill_chain_phases(proc, warnings)
        _lowercase_platforms(proc)
        _tactics_to_kill_chain_phases(proc)
        _fill_fingerprint(proc)
        new_relationships += _refs_to_relationships(proc, existing_relationships)
        _report_sources_to_containment(proc, reports, warnings)
    objects.extend(new_relationships)
    return bundle, warnings
