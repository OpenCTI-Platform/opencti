"""Parity between the legacy STIX export and the backend STIX 2.0 export.

The backend STIX 2.0 converter must produce the same bundle as the legacy
client-side converter (brainstorm decision of 2024-12-06), except for the
differences validated in the decision log and listed below.

The sweep exports one entity of every type covered by `EntityTestCases`, with
the backend path forced inside the test only, so that each migration chunk
can check its types before adding them to `_STIX_2_0_BACKEND_ENTITY_TYPES`.
"""

import json

import pytest
from stix2 import TLP_GREEN

from pycti.utils import opencti_stix2
from pycti.utils.opencti_stix2 import STIX_VERSION_2_0
from tests.cases.entities import (
    EntityTestCases,
    StixCoreRelationshipTest,
    StixSightingRelationshipTest,
)
from tests.utils import case_id, cases_of

# Differences validated in the decision log of issue #8832.
# 2026-11-05: spec_version is "2.0" (the legacy "2.1" was a bug).
# 2026-11-09: samples is only leaked by the legacy export (raw GraphQL key,
#   not STIX, ignored on import). The sample is exported as `sample_refs` by
#   both converters, and the legacy output is left unchanged.
ACCEPTED_DIFFERENCES = {"spec_version", "samples"}

# Known differences still to validate in the decision log. They are ignored
# so that the comparison of every other key stays enforced meanwhile.
# TODO(stix-2-0-migration): move each one to ACCEPTED_DIFFERENCES once
# validated, or fix the converter and remove it.
# - x_opencti_modified_at: only exported by the backend; the legacy readers do
#   not select it, although `import_from_stix2` reads it back.
PENDING_DIFFERENCES = {"x_opencti_modified_at"}

# Same as PENDING_DIFFERENCES, for one STIX object type only.
PENDING_DIFFERENCES_BY_STIX_TYPE = {
    # The legacy export leaks the raw GraphQL key `number_seen`.
    "observed-data": {"number_seen"},
    # SCOs: legacy outputs `external_references`, the backend outputs
    # `x_opencti_external_references` (to decide with chunk 2-4).
    "autonomous-system": {"x_opencti_external_references"},
    "domain-name": {"x_opencti_external_references"},
    "ipv4-addr": {"x_opencti_external_references"},
}

# Keys the legacy export leaves out of a partially read object. They are only
# ignored when the legacy object does not have them, so they stay enforced on
# a fully read object.
# - identity: the embedded author is read with a partial GraphQL fragment,
#   without `confidence` and `revoked`.
PARTIAL_LEGACY_KEYS_BY_STIX_TYPE = {"identity": {"confidence", "revoked"}}

# Not STIX core objects: they are not exported on their own.
NOT_EXPORTED_CASES = {
    "external_reference",
    "group",
    "kill_chain_phase",
    "label",
    "marking_definition",
    "role",
    "settings",
    "user",
}

# Known failures of the backend path, tracked in issue #19645.
# TODO(stix-2-0-migration): remove each entry with the chunk that fixes it.
_SRO_ROUTING = (
    "chunk 2-5: relationships and sightings are routed on `entity_type` "
    "(the relationship type), and `stixCoreObject` does not return them"
)
_CONTAINED_RELATIONSHIPS = (
    "chunk 2-3b: the full bundle loses the contained relationships"
)
KNOWN_FAILURES = {
    ("relationship", "simple"): _SRO_ROUTING,
    ("relationship", "full"): _SRO_ROUTING,
    ("stix_sighting_relationship", "simple"): _SRO_ROUTING,
    ("stix_sighting_relationship", "full"): _SRO_ROUTING,
    **{
        (container, "full"): _CONTAINED_RELATIONSHIPS
        for container in (
            "case_incident",
            "case_rfi",
            "case_rft",
            "feedback",
            "note",
            "opinion",
            "report",
        )
    },
}


def _export_entity_type(entity_case, entity):
    if isinstance(entity_case, StixCoreRelationshipTest):
        return "stix-core-relationship"
    if isinstance(entity_case, StixSightingRelationshipTest):
        return "stix-sighting-relationship"
    return entity["entity_type"]


def _normalized(value):
    """Compare values regardless of list order, and of null versus absent."""
    if isinstance(value, dict):
        return {
            key: _normalized(item) for key, item in value.items() if item is not None
        }
    if isinstance(value, list):
        return sorted(
            (_normalized(item) for item in value),
            key=lambda item: json.dumps(item, sort_keys=True, default=str),
        )
    return value


def _differences(legacy_bundle, stix_2_0_bundle):
    """List the keys that differ, per STIX id, outside the ignored keys."""
    legacy_objects = {item["id"]: item for item in legacy_bundle["objects"]}
    stix_2_0_objects = {item["id"]: item for item in stix_2_0_bundle["objects"]}
    differences = {}
    for object_id in legacy_objects.keys() ^ stix_2_0_objects.keys():
        differences[object_id] = (
            "missing" if object_id in legacy_objects else "only in STIX 2.0"
        )
    for object_id in legacy_objects.keys() & stix_2_0_objects.keys():
        legacy_object = _normalized(legacy_objects[object_id])
        stix_2_0_object = _normalized(stix_2_0_objects[object_id])
        stix_type = object_id.split("--")[0]
        partial_legacy_keys = PARTIAL_LEGACY_KEYS_BY_STIX_TYPE.get(stix_type, set())
        ignored = (
            ACCEPTED_DIFFERENCES
            | PENDING_DIFFERENCES
            | PENDING_DIFFERENCES_BY_STIX_TYPE.get(stix_type, set())
            | (partial_legacy_keys - legacy_object.keys())
        )
        keys = {
            key
            for key in legacy_object.keys() | stix_2_0_object.keys()
            if key not in ignored and legacy_object.get(key) != stix_2_0_object.get(key)
        }
        if keys:
            differences[object_id] = {
                key: {
                    "legacy": legacy_object.get(key),
                    "stix_2_0": stix_2_0_object.get(key),
                }
                for key in sorted(keys)
            }
    return differences


def _export_both(api_stix, entity_type, entity_id, mode):
    legacy_bundle = api_stix.get_stix_bundle_or_object_from_entity_id(
        entity_type=entity_type, entity_id=entity_id, mode=mode
    )
    stix_2_0_bundle = api_stix.get_stix_bundle_or_object_from_entity_id(
        entity_type=entity_type,
        entity_id=entity_id,
        mode=mode,
        stix_version=STIX_VERSION_2_0,
    )
    return legacy_bundle, stix_2_0_bundle


@pytest.fixture(scope="module")
def related_objects(api_client):
    """Author, marking, label, external reference and contained objects."""
    author = api_client.identity.create(
        type="Organization",
        name="STIX 2.0 parity sweep author",
        description="Author of the STIX 2.0 parity sweep entities",
    )
    marking = api_client.marking_definition.read(id=TLP_GREEN["id"])
    label = api_client.label.create(value="stix-2-0-parity-sweep")
    external_reference = api_client.external_reference.create(
        source_name="stix-2-0-parity-sweep",
        url="https://example.com/stix-2-0-parity-sweep",
    )
    intrusion_set = api_client.intrusion_set.create(
        name="STIX 2.0 parity sweep intrusion set",
        description="Contained in the STIX 2.0 parity sweep containers",
    )
    tool = api_client.tool.create(
        name="STIX 2.0 parity sweep tool",
        description="Contained in the STIX 2.0 parity sweep containers",
    )
    relationship = api_client.stix_core_relationship.create(
        fromId=intrusion_set["id"],
        toId=tool["id"],
        relationship_type="uses",
        description="Contained in the STIX 2.0 parity sweep containers",
    )
    # Keys that the create methods of other entity types ignore.
    yield {
        "createdBy": author["id"],
        "objectMarking": [marking["id"]],
        "objectLabel": [label["id"]],
        "externalReferences": [external_reference["id"]],
        "objects": [intrusion_set["id"], tool["id"], relationship["id"]],
    }
    api_client.stix_core_relationship.delete(id=relationship["id"])
    api_client.stix_domain_object.delete(id=tool["id"])
    api_client.stix_domain_object.delete(id=intrusion_set["id"])
    api_client.external_reference.delete(id=external_reference["id"])
    api_client.label.delete(id=label["id"])
    api_client.stix_domain_object.delete(id=author["id"])


@pytest.fixture(
    params=[
        case
        for case in cases_of(EntityTestCases)
        if case_id(case) not in NOT_EXPORTED_CASES
    ],
    ids=case_id,
)
def exported_entity(request, api_client, related_objects):
    """Create one entity of the case type, with its related objects."""
    entity_case = request.param(api_client)
    entity_case.setup()
    entity = entity_case.own_class().create(**{**related_objects, **entity_case.data()})
    yield case_id(request.param), _export_entity_type(entity_case, entity), entity
    entity_case.base_class().delete(id=entity["id"])
    entity_case.teardown()


@pytest.mark.parametrize("mode", ["simple", "full"])
def test_stix_2_0_export_matches_legacy_export(
    request, api_stix, monkeypatch, exported_entity, mode
):
    name, entity_type, entity = exported_entity
    if (name, mode) in KNOWN_FAILURES:
        request.applymarker(
            pytest.mark.xfail(reason=KNOWN_FAILURES[(name, mode)], strict=True)
        )
    # Force the backend path for this type, in this test only.
    monkeypatch.setattr(
        opencti_stix2,
        "_STIX_2_0_BACKEND_ENTITY_TYPES",
        frozenset({entity["entity_type"]}),
    )

    legacy_bundle, stix_2_0_bundle = _export_both(
        api_stix, entity_type, entity["id"], mode
    )

    assert legacy_bundle["objects"], "the legacy export is empty"
    exported = [
        item
        for item in stix_2_0_bundle["objects"]
        if item.get("x_opencti_id") == entity["id"]
    ]
    assert [item["spec_version"] for item in exported] == ["2.0"]
    assert _differences(legacy_bundle, stix_2_0_bundle) == {}


@pytest.fixture
def rich_malware(api_client):
    """A Malware carrying every attribute and ref handled by the export."""
    marking = api_client.marking_definition.read(id=TLP_GREEN["id"])
    author = api_client.identity.create(
        type="Organization",
        name="STIX 2.0 parity author",
        description="Author of the STIX 2.0 parity malware",
    )
    label = api_client.label.create(value="stix-2-0-parity")
    kill_chain_phase = api_client.kill_chain_phase.create(
        kill_chain_name="stix-2-0-parity", phase_name="execution", x_opencti_order=1
    )
    external_reference = api_client.external_reference.create(
        source_name="stix-2-0-parity",
        url="https://example.com/stix-2-0-parity",
        external_id="PARITY-1",
        description="External reference of the parity malware",
    )
    api_client.external_reference.add_file(
        id=external_reference["id"],
        file_name="stix-2-0-parity-report.txt",
        data="External reference attachment of the parity malware",
        no_trigger_import=True,
    )
    sample = api_client.stix_cyber_observable.create(
        observableData={
            "type": "file",
            "name": "parity-sample.exe",
            "hashes": {"MD5": "5d41402abc4b2a76b9719d911017c592"},
        }
    )
    malware = api_client.malware.create(
        name="STIX 2.0 parity malware",
        description="Malware used to compare the legacy and 2.0 exports",
        aliases=["parity-alias"],
        malware_types=["ransomware"],
        is_family=False,
        first_seen="2024-01-01T00:00:00.000Z",
        last_seen="2024-06-01T00:00:00.000Z",
        architecture_execution_envs=["x86"],
        implementation_languages=["c"],
        capabilities=["evades-av"],
        confidence=80,
        x_opencti_score=70,
        x_opencti_modified_at="2024-06-15T00:00:00.000Z",
        createdBy=author["id"],
        objectMarking=[marking["id"]],
        objectLabel=[label["id"]],
        killChainPhases=[kill_chain_phase["id"]],
        externalReferences=[external_reference["id"]],
        samples=[sample["id"]],
    )
    yield malware
    api_client.stix_domain_object.delete(id=malware["id"])
    api_client.stix_cyber_observable.delete(id=sample["id"])
    api_client.external_reference.delete(id=external_reference["id"])
    api_client.kill_chain_phase.delete(id=kill_chain_phase["id"])
    api_client.label.delete(id=label["id"])
    api_client.stix_domain_object.delete(id=author["id"])


@pytest.mark.parametrize("mode", ["simple", "full"])
def test_malware_stix_2_0_export_matches_legacy_export(api_stix, rich_malware, mode):
    legacy_bundle, stix_2_0_bundle = _export_both(
        api_stix, "Malware", rich_malware["id"], mode
    )

    malware = {item["id"]: item for item in stix_2_0_bundle["objects"]}[
        rich_malware["standard_id"]
    ]
    assert malware["spec_version"] == "2.0"
    # Files are only read, and embedded, in full mode.
    if mode == "full":
        attached_files = malware["external_references"][0]["x_opencti_files"]
        assert attached_files[0]["name"] == "stix-2-0-parity-report.txt"
    assert _differences(legacy_bundle, stix_2_0_bundle) == {}
