"""Procedure helpers: fingerprint and ``x-procedure`` bundle normalizer.

A third-party ``x-procedure`` object carries its links as properties
(``x_technique_refs``, ``x_vulnerability_refs``, ``tactics``, report entries in
``x_source_refs``). OpenCTI stores them once, as relationships, kill chain
phases and report containment, so the normalizer rewrites the bundle before
it is split and imported.
"""

import copy
import hashlib
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


def _lowercase_platforms(proc: Dict) -> None:
    if proc.get("platforms") is not None:
        proc["platforms"] = _unique([p.lower() for p in proc["platforms"]])


def _tactics_to_kill_chain_phases(proc: Dict) -> None:
    if "tactics" not in proc:
        return
    tactics = proc.pop("tactics") or []
    phases = list(proc.get("kill_chain_phases") or []) + [
        {"kill_chain_name": MITRE_ATTACK_KILL_CHAIN, "phase_name": tactic}
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
    ``x-opencti-procedure`` everywhere in the bundle; ``platforms`` are
    lowercased; ``tactics`` become ``mitre-attack`` kill chain phases; a
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
        _lowercase_platforms(proc)
        _tactics_to_kill_chain_phases(proc)
        _fill_fingerprint(proc)
        new_relationships += _refs_to_relationships(proc, existing_relationships)
        _report_sources_to_containment(proc, reports, warnings)
    objects.extend(new_relationships)
    return bundle, warnings
