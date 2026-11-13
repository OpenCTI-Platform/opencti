"""Parity between the legacy STIX export and the backend STIX 2.0 export.

The backend STIX 2.0 converter must produce the same bundle as the legacy
client-side converter (brainstorm decision of 2024-12-06), except for the
differences validated in the decision log and listed below.

The sweep exports one entity of every type covered by `EntityTestCases` and
`ExtraEntityTestCases`. The migrated types use `_STIX_2_0_BACKEND_ENTITY_TYPES`
as in production; the other types are added to it inside the test only, so
that each migration chunk can check its types before migrating them.
"""

import json
from datetime import datetime, timezone
from typing import Dict

import pytest
from stix2 import TLP_GREEN

from pycti.utils import opencti_stix2
from pycti.utils.opencti_stix2 import STIX_VERSION_2_0
from tests.cases.entities import (
    EntityTest,
    EntityTestCases,
    StixCoreRelationshipTest,
    StixSightingRelationshipTest,
    TaskTest,
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
    # The legacy export adds `data_source_ref` (without the `x-mitre-` prefix)
    # from the nested refs, next to `x_mitre_data_source_ref`. The import only
    # reads it on a `data-component`, not on an `x-mitre-data-component`.
    "x-mitre-data-component": {"data_source_ref"},
    # SCOs: legacy outputs `external_references`, the backend outputs
    # `x_opencti_external_references` (to decide with chunk 2-4).
    "autonomous-system": {"x_opencti_external_references"},
    "domain-name": {"x_opencti_external_references"},
    "ipv4-addr": {"x_opencti_external_references"},
}

# Keys the legacy export leaves out because its GraphQL reader does not select
# them, while the backend exports the stored value. They are only ignored when
# the legacy object does not have them, so a value the backend loses is still
# caught.
# TODO(stix-2-0-migration): validate them in the decision log, then move them
# to the accepted differences.
# - identity: the embedded author is read with a partial fragment, without
#   `confidence` and `revoked`; no identity reader selects `roles`.
# - infrastructure: the reader does not select `aliases`.
# - report: the reader used in full mode (with files) does not select
#   `content`.
# - x-mitre-data-source: the Data-Source embedded in a Data-Component is read
#   with a partial fragment, without `labels`.
PARTIAL_LEGACY_KEYS_BY_STIX_TYPE = {
    "identity": {"confidence", "revoked", "roles"},
    "infrastructure": {"aliases"},
    "report": {"content"},
    "x-mitre-data-source": {"labels"},
}

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
KNOWN_FAILURES = {
    ("relationship", "simple"): _SRO_ROUTING,
    ("relationship", "full"): _SRO_ROUTING,
    ("stix_sighting_relationship", "simple"): _SRO_ROUTING,
    ("stix_sighting_relationship", "full"): _SRO_ROUTING,
}


class _SimpleEntityTest(EntityTest):
    """Entity created from fixed data with the given API sub-client."""

    client_name = None
    entity_data = {}

    def data(self) -> Dict:
        return dict(self.entity_data)

    def own_class(self):
        return getattr(self.api_client, self.client_name)


class _NarrativeTest(_SimpleEntityTest):
    client_name = "narrative"
    entity_data = {
        "name": "STIX 2.0 parity narrative",
        "description": "Narrative of the STIX 2.0 parity sweep",
    }


class _ChannelTest(_SimpleEntityTest):
    client_name = "channel"
    entity_data = {
        "name": "STIX 2.0 parity channel",
        "description": "Channel of the STIX 2.0 parity sweep",
        "channel_types": ["website"],
    }


class _EventTest(_SimpleEntityTest):
    client_name = "event"
    entity_data = {
        "name": "STIX 2.0 parity event",
        "description": "Event of the STIX 2.0 parity sweep",
    }


class _AdministrativeAreaTest(_SimpleEntityTest):
    client_name = "location"
    entity_data = {
        "type": "Administrative-Area",
        "name": "STIX 2.0 parity administrative area",
        "description": "Administrative area of the STIX 2.0 parity sweep",
        "latitude": 48.85,
        "longitude": 2.35,
    }


class _SecurityPlatformTest(_SimpleEntityTest):
    client_name = "identity"
    entity_data = {
        "type": "SecurityPlatform",
        "name": "STIX 2.0 parity security platform",
        "description": "Security platform of the STIX 2.0 parity sweep",
        "security_platform_type": "SIEM",
    }


class _GroupingTest(_SimpleEntityTest):
    client_name = "grouping"
    entity_data = {
        "name": "STIX 2.0 parity grouping",
        "description": "Grouping of the STIX 2.0 parity sweep",
        "context": "suspicious-activity",
    }


class _DataComponentWithDataSourceTest(EntityTest):
    """The Data-Source is added to the bundle in simple and full mode."""

    def setup(self):
        # The legacy export embeds the Data-Source from a partial fragment:
        # give it the keys that fragment does not read.
        self.label = self.api_client.label.create(value="stix-2-0-parity-source")
        self.data_source = self.api_client.data_source.create(
            name="STIX 2.0 parity data source",
            description="Data source of the STIX 2.0 parity data component",
            objectLabel=[self.label["id"]],
            aliases=_ALIASES,
            platforms=["windows"],
        )

    def data(self) -> Dict:
        return {
            "name": "STIX 2.0 parity data component",
            "description": "Data component of the STIX 2.0 parity sweep",
            "dataSource": self.data_source["id"],
        }

    def own_class(self):
        return self.api_client.data_component

    def teardown(self):
        self.api_client.stix_domain_object.delete(id=self.data_source["id"])
        self.api_client.label.delete(id=self.label["id"])


class _MalwareAnalysisWithRefsTest(EntityTest):
    """Single and multiple nested refs to observables."""

    def setup(self):
        create = self.api_client.stix_cyber_observable.create
        self.observables = {
            "sample": create(
                observableData={
                    "type": "file",
                    "name": "stix-2-0-parity-analysis-sample.exe",
                    "hashes": {"MD5": "0cc175b9c0f1b6a831c399e269772661"},
                }
            ),
            "operatingSystem": create(
                observableData={"type": "software", "name": "stix-2-0-parity-os"}
            ),
            "hostVm": create(
                observableData={"type": "software", "name": "stix-2-0-parity-vm"}
            ),
            "installedSoftware": create(
                observableData={"type": "software", "name": "stix-2-0-parity-tool"}
            ),
            "analysisSco": create(
                observableData={"type": "ipv4-addr", "value": "198.51.100.77"}
            ),
        }

    def data(self) -> Dict:
        ids = {key: item["id"] for key, item in self.observables.items()}
        return {
            "result_name": "STIX 2.0 parity analysis",
            "product": "Cuckoo",
            "version": "1",
            "sample": ids["sample"],
            "operatingSystem": ids["operatingSystem"],
            "hostVm": ids["hostVm"],
            "installedSoftware": [ids["installedSoftware"]],
            "analysisSco": [ids["analysisSco"]],
        }

    def own_class(self):
        return self.api_client.malware_analysis

    def teardown(self):
        for observable in self.observables.values():
            self.api_client.stix_cyber_observable.delete(id=observable["id"])


class _ReportWithNoteTest(EntityTest):
    """The legacy export filters the Note out of the report `object_refs`."""

    def setup(self):
        self.note = self.api_client.note.create(
            content="Note contained in the STIX 2.0 parity report"
        )

    def data(self) -> Dict:
        return {
            "name": "STIX 2.0 parity report with a note",
            "description": "Report of the STIX 2.0 parity sweep",
            "published": "2024-01-01T00:00:00.000Z",
            "report_types": ["threat-report"],
            "objects": [self.note["id"]],
        }

    def own_class(self):
        return self.api_client.report

    def teardown(self):
        self.api_client.stix_domain_object.delete(id=self.note["id"])


class ExtraEntityTestCases:
    """Exported types and shapes that `EntityTestCases` does not cover."""

    @staticmethod
    def case_narrative(api_client):
        return _NarrativeTest(api_client)

    @staticmethod
    def case_channel(api_client):
        return _ChannelTest(api_client)

    @staticmethod
    def case_event(api_client):
        return _EventTest(api_client)

    @staticmethod
    def case_location_administrative_area(api_client):
        return _AdministrativeAreaTest(api_client)

    @staticmethod
    def case_identity_security_platform(api_client):
        return _SecurityPlatformTest(api_client)

    @staticmethod
    def case_grouping(api_client):
        return _GroupingTest(api_client)

    @staticmethod
    def case_task(api_client):
        return TaskTest(api_client)

    @staticmethod
    def case_data_component_with_data_source(api_client):
        return _DataComponentWithDataSourceTest(api_client)

    @staticmethod
    def case_malware_analysis_with_refs(api_client):
        return _MalwareAnalysisWithRefsTest(api_client)

    @staticmethod
    def case_report_with_note(api_client):
        return _ReportWithNoteTest(api_client)


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


_FIRST = "2024-01-01T00:00:00.000Z"
_LAST = "2024-06-01T00:00:00.000Z"
_ALIASES = ["stix-2-0-parity-alias"]
_THREAT_ACTOR = {
    "aliases": _ALIASES,
    "first_seen": _FIRST,
    "last_seen": _LAST,
    "goals": ["parity"],
    "personal_motivations": ["revenge"],
    "primary_motivation": "ideology",
    "resource_level": "government",
    "roles": ["agent"],
    "secondary_motivations": ["dominance"],
    "sophistication": "expert",
    "threat_actor_types": ["crime-syndicate"],
    "x_opencti_score": 60,
}
_IDENTITY = {
    "contact_information": "parity@example.com",
    "roles": ["analyst"],
    "x_opencti_aliases": _ALIASES,
    "x_opencti_reliability": "A - Completely reliable",
    "x_opencti_score": 60,
}
_LOCATION = {"precision": 10.0, "x_opencti_aliases": _ALIASES}
_CASE = {"content": "<p>Parity content</p>", "priority": "P2", "severity": "high"}

# Every attribute the create method of each type sets, on top of the case data,
# so that a key dropped or added by one export does not go unnoticed.
RICH_DATA = {
    "attack_pattern": {
        "aliases": _ALIASES,
        "x_mitre_detection": "Parity detection",
        "x_mitre_id": "T9999",
        "x_mitre_permissions_required": ["User"],
        "x_mitre_platforms": ["Windows"],
    },
    "campaign": {
        "aliases": _ALIASES,
        "first_seen": _FIRST,
        "last_seen": _LAST,
        "objective": "Parity",
    },
    "course_of_action": {"x_mitre_id": "M9999", "x_opencti_aliases": _ALIASES},
    "incident": {
        "incident_type": "phishing",
        "severity": "high",
        "source": "Parity source",
        "x_opencti_score": 60,
    },
    "infrastructure": {
        "aliases": _ALIASES,
        "first_seen": _FIRST,
        "last_seen": _LAST,
        "infrastructure_types": ["botnet"],
    },
    "indicator": {
        "indicator_types": ["malicious-activity"],
        "pattern_version": "2.1",
        "x_mitre_platforms": ["windows"],
    },
    "intrusion_set": {
        "aliases": _ALIASES,
        "first_seen": _FIRST,
        "last_seen": _LAST,
        "goals": ["parity"],
        "primary_motivation": "ideology",
        "resource_level": "government",
        "secondary_motivations": ["dominance"],
        "x_opencti_score": 60,
    },
    "malware": {
        "aliases": _ALIASES,
        "architecture_execution_envs": ["x86"],
        "capabilities": ["evades-av"],
        "implementation_languages": ["c"],
        "is_family": False,
        "first_seen": _FIRST,
        "last_seen": _LAST,
        "malware_types": ["ransomware"],
        "x_opencti_score": 60,
    },
    "malware_analysis": {
        "analysis_definition_version": "1",
        "analysis_engine_version": "2",
        "analysis_started": _FIRST,
        "analysis_ended": _LAST,
        "configuration_version": "3",
        "modules": ["parity-module"],
        "result": "malicious",
    },
    "narrative": {"aliases": _ALIASES, "narrative_types": ["parity"]},
    "channel": {"aliases": _ALIASES},
    "event": {
        "aliases": _ALIASES,
        "event_types": ["conference"],
        "start_time": _FIRST,
        "stop_time": _LAST,
        "x_opencti_score": 60,
    },
    "threat_actor_group": _THREAT_ACTOR,
    "threat_actor_individual": _THREAT_ACTOR,
    "tool": {
        "aliases": _ALIASES,
        "tool_types": ["remote-access"],
        "tool_version": "1.0",
    },
    "vulnerability": {
        "x_opencti_aliases": _ALIASES,
        "x_opencti_cisa_kev": True,
        "x_opencti_cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "x_opencti_cvss_attack_vector": "NETWORK",
        "x_opencti_cvss_base_score": 9.8,
        "x_opencti_cvss_base_severity": "CRITICAL",
        "x_opencti_cvss_scope": "UNCHANGED",
        "x_opencti_cvss_v2_base_score": 7.5,
        "x_opencti_cvss_v4_base_score": 9.3,
        "x_opencti_cwe": ["CWE-79"],
        "x_opencti_epss_score": 0.5,
        "x_opencti_epss_percentile": 0.9,
        "x_opencti_first_seen_active": _FIRST,
        "x_opencti_score": 60,
    },
    "data_component": {"aliases": _ALIASES},
    "data_component_with_data_source": {"aliases": _ALIASES},
    "data_source": {
        "aliases": _ALIASES,
        "collection_layers": ["host"],
        "platforms": ["windows"],
    },
    "identity_organization": {
        **_IDENTITY,
        "x_opencti_organization_type": "vendor",
    },
    "identity_individual": {
        **_IDENTITY,
        "x_opencti_firstname": "Jane",
        "x_opencti_lastname": "Parity",
    },
    "identity_sector": _IDENTITY,
    "identity_system": _IDENTITY,
    "identity_security_platform": _IDENTITY,
    "location_city": _LOCATION,
    "location_country": _LOCATION,
    "location_region": _LOCATION,
    "location_position": _LOCATION,
    "location_administrative_area": _LOCATION,
    "report": {"content": "<p>Parity content</p>", "x_opencti_reliability": "B"},
    "report_with_note": {"content": "<p>Parity content</p>"},
    "note": {"content": "Parity content"},
    "opinion": {"authors": ["parity"], "explanation": "Parity explanation"},
    "grouping": {"content": "<p>Parity content</p>", "x_opencti_aliases": _ALIASES},
    "case_incident": {**_CASE, "response_types": ["data-leak"]},
    "case_rfi": {**_CASE, "information_types": ["parity"]},
    "case_rft": {**_CASE, "takedown_types": ["parity"]},
    "feedback": {"rating": 4},
    "task": {"due_date": _LAST},
}


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
    kill_chain_phase = api_client.kill_chain_phase.create(
        kill_chain_name="stix-2-0-parity-sweep",
        phase_name="execution",
        x_opencti_order=1,
    )
    me = api_client.query("query { me { id } }")["data"]["me"]
    # Keys that the create methods of other entity types ignore.
    yield {
        "createdBy": author["id"],
        "objectMarking": [marking["id"]],
        "objectLabel": [label["id"]],
        "externalReferences": [external_reference["id"]],
        "objects": [intrusion_set["id"], tool["id"], relationship["id"]],
        "killChainPhases": [kill_chain_phase["id"]],
        "objectAssignee": [me["id"]],
        "objectParticipant": [me["id"]],
        "lang": "fr",
        "confidence": 70,
        "x_opencti_modified_at": "2024-06-15T00:00:00.000Z",
    }
    api_client.kill_chain_phase.delete(id=kill_chain_phase["id"])
    api_client.stix_core_relationship.delete(id=relationship["id"])
    api_client.stix_domain_object.delete(id=tool["id"])
    api_client.stix_domain_object.delete(id=intrusion_set["id"])
    api_client.external_reference.delete(id=external_reference["id"])
    api_client.label.delete(id=label["id"])
    api_client.stix_domain_object.delete(id=author["id"])


@pytest.fixture(
    params=[
        case
        for case in cases_of(EntityTestCases) + cases_of(ExtraEntityTestCases)
        if case_id(case) not in NOT_EXPORTED_CASES
    ],
    ids=case_id,
)
def exported_entity(request, api_client, related_objects):
    """Create one entity of the case type, with its related objects."""
    name = case_id(request.param)
    entity_case = request.param(api_client)
    entity_case.setup()
    entity = entity_case.own_class().create(
        **{**related_objects, **entity_case.data(), **RICH_DATA.get(name, {})}
    )
    yield name, _export_entity_type(entity_case, entity), entity
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
    # Force the backend path for this type, in this test only. The migrated
    # types keep it, as in production (e.g. for the embedded author).
    monkeypatch.setattr(
        opencti_stix2,
        "_STIX_2_0_BACKEND_ENTITY_TYPES",
        opencti_stix2._STIX_2_0_BACKEND_ENTITY_TYPES | {entity["entity_type"]},
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
    differences = _differences(legacy_bundle, stix_2_0_bundle)
    assert differences == {}, json.dumps(differences, indent=1, default=str)


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


@pytest.fixture
def indicator_with_equal_validity_dates(api_client):
    """An Indicator whose `valid_until` was updated to its `valid_from`."""
    indicator = api_client.indicator.create(
        name="STIX 2.0 parity indicator with equal validity dates",
        pattern_type="stix",
        pattern="[ipv4-addr:value = '198.51.100.91']",
        x_opencti_main_observable_type="IPv4-Addr",
        valid_from=_FIRST,
        valid_until=_LAST,
    )
    # Equal dates are set with an update, after the creation.
    api_client.stix_domain_object.update_field(
        id=indicator["id"], input={"key": "valid_until", "value": _FIRST}
    )
    yield indicator
    api_client.stix_domain_object.delete(id=indicator["id"])


def test_indicator_equal_validity_dates_match_legacy_export(
    api_stix, indicator_with_equal_validity_dates
):
    """Both exports move `valid_until` one second after `valid_from`.

    The STIX specification requires `valid_until` to be after `valid_from`.
    The legacy export formats the new date with microseconds, so the two
    dates are compared as timestamps.
    """
    indicator_id = indicator_with_equal_validity_dates["id"]
    legacy_bundle, stix_2_0_bundle = _export_both(
        api_stix, "Indicator", indicator_id, "simple"
    )

    def valid_until(bundle):
        indicator = next(
            item
            for item in bundle["objects"]
            if item.get("x_opencti_id") == indicator_id
        )
        # Python 3.10 does not parse the `Z` suffix.
        return datetime.fromisoformat(indicator["valid_until"].replace("Z", "+00:00"))

    expected = datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    assert valid_until(legacy_bundle) == valid_until(stix_2_0_bundle) == expected
    differences = _differences(legacy_bundle, stix_2_0_bundle)
    assert [set(keys) for keys in differences.values()] == [{"valid_until"}]


@pytest.fixture
def position_at_zero_coordinates(api_client):
    """A Position on the equator and the prime meridian."""
    position = api_client.location.create(
        type="Position",
        name="STIX 2.0 parity position at zero coordinates",
        latitude=0.0,
        longitude=0.0,
    )
    yield position
    api_client.stix_domain_object.delete(id=position["id"])


@pytest.mark.parametrize("mode", ["simple", "full"])
def test_position_zero_coordinates_match_legacy_export(
    api_stix, position_at_zero_coordinates, mode
):
    """Both exports keep a latitude and a longitude of 0."""
    position_id = position_at_zero_coordinates["id"]
    legacy_bundle, stix_2_0_bundle = _export_both(
        api_stix, "Position", position_id, mode
    )
    for bundle in (legacy_bundle, stix_2_0_bundle):
        position = next(
            item
            for item in bundle["objects"]
            if item.get("x_opencti_id") == position_id
        )
        assert (position["latitude"], position["longitude"]) == (0, 0)
    assert _differences(legacy_bundle, stix_2_0_bundle) == {}
