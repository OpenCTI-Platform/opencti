from typing import Dict, List, Union

from stix2 import TLP_GREEN, TLP_WHITE, AttackPattern

from pycti.entities.opencti_settings import Settings
from pycti.utils.constants import ContainerTypes, IdentityTypes, LocationTypes
from tests.utils import get_incident_end_date, get_incident_start_date


class EntityTestCases:
    @staticmethod
    def case_attack_pattern(api_client):
        return AttackPatternTest(api_client)

    @staticmethod
    def case_campaign(api_client):
        return CampaignTest(api_client)

    @staticmethod
    def case_course_of_action(api_client):
        return CourseOfActionTest(api_client)

    @staticmethod
    def case_external_reference(api_client):
        return ExternalReferenceTest(api_client)

    @staticmethod
    def case_identity_organization(api_client):
        return IdentityOrganizationTest(api_client)

    @staticmethod
    def case_identity_individual(api_client):
        return IdentityIndividualTest(api_client)

    @staticmethod
    def case_identity_sector(api_client):
        return IdentitySectorTest(api_client)

    @staticmethod
    def case_identity_system(api_client):
        return IdentitySystemTest(api_client)

    @staticmethod
    def case_incident(api_client):
        return IncidentTest(api_client)

    @staticmethod
    def case_infrastructure(api_client):
        return InfrastructureTest(api_client)

    @staticmethod
    def case_indicator(api_client):
        return IndicatorTest(api_client)

    @staticmethod
    def case_intrusion_set(api_client):
        return IntrusionSetTest(api_client)

    @staticmethod
    def case_kill_chain_phase(api_client):
        return KillChainPhaseTest(api_client)

    @staticmethod
    def case_label(api_client):
        return LabelTest(api_client)

    @staticmethod
    def case_location_city(api_client):
        return LocationCityTest(api_client)

    @staticmethod
    def case_location_country(api_client):
        return LocationCountryTest(api_client)

    @staticmethod
    def case_location_region(api_client):
        return LocationRegionTest(api_client)

    @staticmethod
    def case_location_position(api_client):
        return LocationPositionTest(api_client)

    @staticmethod
    def case_malware(api_client):
        return MalwareTest(api_client)

    @staticmethod
    def case_malware_analysis(api_client):
        return MalwareAnalysisTest(api_client)

    @staticmethod
    def case_marking_definition(api_client):
        return MarkingDefinitionTest(api_client)

    @staticmethod
    def case_note(api_client):
        return NoteTest(api_client)

    @staticmethod
    def case_observed_data(api_client):
        return ObservedDataTest(api_client)

    @staticmethod
    def case_opinion(api_client):
        return OpinionTest(api_client)

    @staticmethod
    def case_report(api_client):
        return ReportTest(api_client)

    @staticmethod
    def case_relationship(api_client):
        return StixCoreRelationshipTest(api_client)

    @staticmethod
    def case_stix_cyber_observable_ipv4(api_client):
        return StixCyberObservableIPv4Test(api_client)

    @staticmethod
    def case_stix_cyber_observable_domain(api_client):
        return StixCyberObservableDomainTest(api_client)

    @staticmethod
    def case_stix_cyber_observable_as(api_client):
        return StixCyberObservableASTest(api_client)

    @staticmethod
    def case_stix_sighting_relationship(api_client):
        return StixSightingRelationshipTest(api_client)

    @staticmethod
    def case_threat_actor_group(api_client):
        return ThreatActorGroupTest(api_client)

    @staticmethod
    def case_threat_actor_individual(api_client):
        return ThreatActorIndividualTest(api_client)

    @staticmethod
    def case_tool(api_client):
        return ToolTest(api_client)

    @staticmethod
    def case_vulnerability(api_client):
        return VulnerabilityTest(api_client)

    @staticmethod
    def case_data_component(api_client):
        return DataComponentTest(api_client)

    @staticmethod
    def case_data_source(api_client):
        return DataSourceTest(api_client)

    @staticmethod
    def case_feedback(api_client):
        return FeedbackTest(api_client)

    @staticmethod
    def case_case_incident(api_client):
        return CaseIncidentTest(api_client)

    @staticmethod
    def case_case_rfi(api_client):
        return CaseRfiTest(api_client)

    @staticmethod
    def case_case_rft(api_client):
        return CaseRftTest(api_client)

    @staticmethod
    def task(api_client):
        return TaskTest(api_client)

    @staticmethod
    def case_role(api_client):
        return RoleTest(api_client)

    @staticmethod
    def case_group(api_client):
        return GroupTest(api_client)

    @staticmethod
    def case_user(api_client):
        return UserTest(api_client)

    @staticmethod
    def case_settings(api_client):
        return SettingsTest(api_client)


class EntityTest:
    def __init__(self, api_client):
        self.api_client = api_client

    def setup(self):
        pass

    def teardown(self):
        pass

    def data(self) -> Dict:
        pass

    def own_class(self):
        pass

    def relation_test(self):
        return False

    def base_class(self):
        return self.api_client.stix_domain_object

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {"description": "Test"}

    def get_compare_exception_keys(self) -> List[str]:
        return ["type", "update", "createdBy", "modified"]

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "name",
                    "values": self.data()["name"],
                }
            ],
            "filterGroups": [],
        }

    def get_search(self) -> str:
        return None

    def stix_class(self):
        pass


class IdentityTest(EntityTest):
    def own_class(self):
        return self.api_client.identity


class IdentityOrganizationTest(IdentityTest):
    def data(self) -> Dict:
        return {
            "type": IdentityTypes.ORGANIZATION.value,
            "name": "Testing Inc.",
            "description": "OpenCTI Test Org",
        }


class IdentityIndividualTest(IdentityTest):
    def data(self) -> Dict:
        return {
            "type": IdentityTypes.INDIVIDUAL.value,
            "name": "Jane Smith",
            "description": "Mrs awesome",
        }


class IdentitySectorTest(IdentityTest):
    def data(self) -> Dict:
        return {
            "type": IdentityTypes.SECTOR.value,
            "name": "Energetic",
            "description": "The energetic sector",
        }


class IdentitySystemTest(IdentityTest):
    def data(self) -> Dict:
        return {
            "type": IdentityTypes.SYSTEM.value,
            "name": "System A",
            "description": "The system A",
        }


class IndicatorTest(EntityTest):
    def setup(self):
        self.marking_definition_green = self.api_client.marking_definition.read(
            id=TLP_GREEN["id"]
        )
        self.marking_definition_white = self.api_client.marking_definition.read(
            id=TLP_WHITE["id"]
        )
        # Create the organization
        self.organization = self.api_client.identity.create(
            **IdentityOrganizationTest(self.api_client).data()
        )

    def data(self) -> Dict:
        return {
            "type": "indicator",
            "name": "C2 server of the new campaign",
            "description": "This is the C2 server of the campaign",
            "pattern_type": "stix",
            "pattern": "[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']",
            "x_opencti_main_observable_type": "IPv4-Addr",
            "confidence": 60,
            "x_opencti_score": 80,
            "x_opencti_detection": True,
            "valid_from": get_incident_start_date(),
            "valid_until": get_incident_end_date(),
            "created": get_incident_start_date(),
            "modified": get_incident_start_date(),
            "createdBy": self.organization["id"],
            "objectMarking": [
                self.marking_definition_green["id"],
                self.marking_definition_white["id"],
            ],
            "update": True,
            # TODO killchain phase
        }

    def get_compare_exception_keys(self) -> List[str]:
        # indicator objects include extracted creators field
        return ["type", "update", "createdBy", "modified", "creators"]

    def teardown(self):
        self.api_client.stix_domain_object.delete(id=self.organization["id"])

    def own_class(self):
        return self.api_client.indicator


class AttackPatternTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "attack-pattern",
            "name": "Evil Pattern!",
            # "x_mitre_id": "T1999",
            "description": "Test Attack Pattern!",
        }

    def own_class(self):
        return self.api_client.attack_pattern

    def stix_class(self):
        return AttackPattern


class CourseOfActionTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "CourseOfAction",
            "name": "Evil Pattern",
            "description": "Test Attack Pattern",
        }

    def own_class(self):
        return self.api_client.course_of_action


class ExternalReferenceTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "ExternalReference",
            "source_name": "veris",
            "description": "Evil veris link",
            "external_id": "001AA7F-C601-424A-B2B8-BE6C9F5164E7",
            "url": "https://github.com/vz-risk/VCDB/blob/125307638178efddd3ecfe2c267ea434667a4eea/data/json/validated/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
        }

    def own_class(self):
        return self.api_client.external_reference

    def base_class(self):
        return self.api_client.external_reference

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "external_id",
                    "values": self.data()["external_id"],
                }
            ],
            "filterGroups": [],
        }


class CampaignTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Campagin",
            "name": "Green Group Attacks Against Finance",
            "description": "Campaign by Green Group against a series of targets in the financial services sector.",
            "aliases": ["GREENEVIL", "GREVIL"],
            "confidence": 60,
            "first_seen": get_incident_start_date(),
            "last_seen": get_incident_end_date(),
            "objective": "World dominance",
        }

    def own_class(self):
        return self.api_client.campaign


class IncidentTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Incident",
            "name": "Green Group Attacks Against Finance",
            "description": "Incident by Green Group against a targets in the financial services sector.",
            "aliases": ["GREENEVIL", "GREVIL"],
            "confidence": 60,
            "created": get_incident_start_date(),
            "first_seen": get_incident_start_date(),
            "last_seen": get_incident_end_date(),
            "objective": "World dominance",
        }

    def own_class(self):
        return self.api_client.incident


class InfrastructureTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Infrastructure",
            "name": "Poison Ivy C2",
            "description": "Poison Ivy C2 turning into C3",
            "first_seen": get_incident_start_date(),
            "last_seen": get_incident_end_date(),
            "infrastructure_types": ["command-and-control"],
        }

    def own_class(self):
        return self.api_client.infrastructure


class IntrusionSetTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "IntrusionSet",
            "name": "Bobcat Breakin",
            "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.",
            "aliases": ["Zookeeper"],
            "goals": ["acquisition-theft", "harassment", "damage"],
        }

    def own_class(self):
        return self.api_client.intrusion_set


class KillChainPhaseTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "KillChainPhase",
            "kill_chain_name": "foo",
            "phase_name": "pre-attack",
        }

    def own_class(self):
        return self.api_client.kill_chain_phase

    def base_class(self):
        return self.api_client.kill_chain_phase

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {"kill_chain_name": "test"}

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "kill_chain_name",
                    "values": self.data()["kill_chain_name"],
                }
            ],
            "filterGroups": [],
        }


class LabelTest(EntityTest):
    def data(self) -> Dict:
        return {"type": "Label", "value": "fooaaa", "color": "#c3ff1a"}

    def own_class(self):
        return self.api_client.label

    def base_class(self):
        return self.api_client.label

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {"color": "#c3ffbb"}

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "value",
                    "values": self.data()["value"],
                }
            ],
            "filterGroups": [],
        }


class LocationTest(EntityTest):
    def own_class(self):
        return self.api_client.location

    def get_compare_exception_keys(self) -> List[str]:
        return ["type", "update", "createdBy", "region"]


class LocationCityTest(LocationTest):
    def data(self) -> Dict:
        return {
            "type": LocationTypes.CITY.value,
            "name": "Mars",
            "description": "A city",
            "latitude": 48.8566,
            "longitude": 2.3522,
            # "country": "KR",
        }


class LocationCountryTest(LocationTest):
    def data(self) -> Dict:
        return {
            "type": LocationTypes.COUNTRY.value,
            "name": "Mars",
            "description": "A country",
            "latitude": 48.8566,
            "longitude": 2.3522,
            "region": "northern-america",
            "x_opencti_aliases": ["MRS"],
        }


class LocationRegionTest(LocationTest):
    def data(self) -> Dict:
        return {
            "type": LocationTypes.REGION.value,
            "name": "Mars",
            "description": "A Region",
            "latitude": 48.8566,
            "longitude": 2.3522,
        }


class LocationPositionTest(LocationTest):
    def data(self) -> Dict:
        return {
            "type": LocationTypes.POSITION.value,
            "name": "CEO",
            "description": "The janitor of everything",
        }


class MalwareTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Malware",
            "name": "Cryptolocker_test",
            "description": "A variant of the cryptolocker family",
            "malware_types": ["ransomware"],
            "is_family": False,
        }

    def own_class(self):
        return self.api_client.malware


class MalwareAnalysisTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "MalwareAnalysis",
            "result_name": "Analysis of Cryptolocker_test",
            "product": "Wireshark",
            "submitted": "2023-01-20T17:00:00.000Z",
            "version": "0",
        }

    def own_class(self):
        return self.api_client.malware_analysis

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "result_name",
                    "values": self.data()["result_name"],
                }
            ],
            "filterGroups": [],
        }

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {"version": "1.2.3"}


class MarkingDefinitionTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "MarkingDefinition",
            "definition_type": "statement",
            # TODO definition should be an array
            "definition": "Copyright 2019, Example Corp",
        }

    def own_class(self):
        return self.api_client.marking_definition

    def base_class(self):
        return self.api_client.marking_definition

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {"definition": "Test"}

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "definition",
                    "values": self.data()["definition"],
                }
            ],
            "filterGroups": [],
        }


class NoteTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": ContainerTypes.NOTE.value,
            "abstract": "A very short note",
            "content": "You would like to know that",
            "confidence": 50,
            "authors": ["you"],
            "note_types": ["internal"],
            "likelihood": 75,
            #    "lang": "en",
        }

    def own_class(self):
        return self.api_client.note

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {}

    def get_compare_exception_keys(self) -> List[str]:
        # changes between pycti and opencti naming
        # abstract = attribute_abstract
        return ["type", "update", "createdBy", "modified", "abstract"]

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "attribute_abstract",
                    "values": self.data()["abstract"],
                }
            ],
            "filterGroups": [],
        }


class ObservedDataTest(EntityTest):
    def setup(self):
        self.ipv4 = self.api_client.stix_cyber_observable.create(
            simple_observable_key="IPv4-Addr.value",
            simple_observable_value="198.51.100.3",
        )
        self.domain = self.api_client.stix_cyber_observable.create(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="example.com",
        )

    def data(self) -> Dict:
        return {
            "type": ContainerTypes.OBSERVED_DATA.value,
            "first_observed": get_incident_start_date(),
            "last_observed": get_incident_end_date(),
            "number_observed": 50,
            "objects": [self.ipv4["id"], self.domain["id"]],
        }

    def teardown(self):
        self.api_client.stix_cyber_observable.delete(id=self.ipv4["id"])
        self.api_client.stix_cyber_observable.delete(id=self.domain["id"])

    def own_class(self):
        return self.api_client.observed_data

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {"number_observed": 30}

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [],
            "filterGroups": [],
        }


class OpinionTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": ContainerTypes.OPINION.value,
            "opinion": "strongly-disagree",
            "explanation": "This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew.",
            "confidence": 50,
            "authors": ["you"],
            # "lang": "en",
        }

    def own_class(self):
        return self.api_client.opinion

    def update_data(self) -> Dict[str, Union[str, int]]:
        # return {"explanation": "Test"}
        return {}

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "explanation",
                    "values": self.data()["explanation"],
                }
            ],
            "filterGroups": [],
        }


class ReportTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": ContainerTypes.REPORT.value,
            "name": "The Black Vine Cyberespionage Group",
            "description": "A simple report with an indicator and campaign",
            "published": "2016-01-20T17:00:00.000Z",
            "report_types": ["threat-report"],
            # "lang": "en",
            # "object_refs": [self.ipv4["id"], self.domain["id"]],
        }

    def own_class(self):
        return self.api_client.report


class StixCoreRelationshipTest(EntityTest):
    def setup(self):
        self.incident = self.api_client.incident.create(
            name="My new incident",
            created=get_incident_start_date(),
            description="We have been compromised",
            objective="Espionage",
        )

        self.ttp1 = self.api_client.attack_pattern.create(
            name="Password Filter DLL Mitigation",
            description="Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (<code>C:\\Windows\\System32\\</code> by default) of a domain controller and/or local computer with a corresponding entry in <code>HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages</code>. (Citation: Microsoft Install Password Filter n.d)",
            x_mitre_id="T1174",
        )

    def data(self) -> Dict:
        return {
            "type": "StixCoreRelationship",
            "fromId": self.incident["id"],
            "toId": self.ttp1["id"],
            "relationship_type": "uses",
            "description": "We saw the attacker use Spearphishing Attachment.",
            "start_date": get_incident_start_date(),
            "stop_date": get_incident_end_date(),
            # "lang": "en",
        }

    def own_class(self):
        return self.api_client.stix_core_relationship

    def base_class(self):
        return self.api_client.stix_core_relationship

    def teardown(self):
        self.api_client.stix_domain_object.delete(id=self.incident["id"])

    def get_compare_exception_keys(self) -> List[str]:
        # changes between pycti and opencti naming
        # fromId = from
        # toId = to
        # start_date = start_time
        # stop_date = stop_time
        return [
            "type",
            "update",
            "createdBy",
            "modified",
            "fromId",
            "toId",
            "start_date",
            "stop_date",
        ]

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [],
            "filterGroups": [],
        }


class StixNestedRefRelationshipTest(EntityTest):
    def setup(self):
        self.ipv4 = self.api_client.stix_cyber_observable.create(
            simple_observable_key="IPv4-Addr.value",
            simple_observable_value="198.51.100.3",
        )
        self.domain = self.api_client.stix_cyber_observable.create(
            simple_observable_key="Domain-Name.value",
            simple_observable_value="example.com",
        )

    def data(self) -> Dict:
        return {
            "fromId": self.domain["id"],
            "toId": self.ipv4["id"],
            "relationship_type": "related-to",
            "description": "We saw the attacker use Spearphishing Attachment.",
            "start_date": get_incident_start_date(),
            "stop_date": get_incident_end_date(),
            # "lang": "en",
            # "object_refs": [self.ipv4["id"], self.domain["id"]],
        }

    def own_class(self):
        return self.api_client.stix_nested_ref_relationship

    def base_class(self):
        return self.api_client.stix_nested_ref_relationship

    def teardown(self):
        self.api_client.stix_domain_object.delete(id=self.domain["id"])
        self.api_client.stix_domain_object.delete(id=self.ipv4["id"])

    def get_compare_exception_keys(self) -> List[str]:
        # changes between pycti and opencti naming
        # fromId = from
        # toId = to
        # start_date = start_time
        # stop_date = stop_time
        return [
            "type",
            "update",
            "createdBy",
            "modified",
            "fromId",
            "toId",
            "start_date",
            "stop_date",
        ]

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [],
            "filterGroups": [],
        }


class StixSightingRelationshipTest(EntityTest):
    def setup(self):
        self.ttp1 = self.api_client.attack_pattern.create(
            name="Password Filter DLL Mitigation",
            description="Ensure only valid password filters are registered. Filter DLLs must be present in Windows installation directory (<code>C:\\Windows\\System32\\</code> by default) of a domain controller and/or local computer with a corresponding entry in <code>HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages</code>. (Citation: Microsoft Install Password Filter n.d)",
            x_mitre_id="T1174",
        )

        self.location = self.api_client.location.create(
            **{
                "type": LocationTypes.COUNTRY.value,
                "name": "Mars",
                "description": "A city",
                "latitude": 48.8566,
                "longitude": 2.3522,
                "region": "northern-america",
                "country": "th",
                "administrative_area": "Tak",
                "postal_code": "63170",
            },
        )

    def data(self) -> Dict:
        return {
            "fromId": self.ttp1["id"],
            "toId": self.location["id"],
            "description": "We saw the attacker use Spearphishing Attachment.",
            "start_date": get_incident_start_date(),
            "stop_date": get_incident_end_date(),
            "count": 3,
            # "lang": "en",
        }

    def own_class(self):
        return self.api_client.stix_sighting_relationship

    def base_class(self):
        return self.api_client.stix_sighting_relationship

    def teardown(self):
        self.api_client.stix_domain_object.delete(id=self.location["id"])

    def get_compare_exception_keys(self) -> List[str]:
        # changes between pycti and opencti naming
        # fromId = from
        # toId = to
        # start_date = start_time
        # stop_date = stop_time
        # count = attribute_count
        return [
            "type",
            "update",
            "createdBy",
            "modified",
            "fromId",
            "toId",
            "start_date",
            "stop_date",
            "count",
        ]

    def get_filter(self) -> Dict[str, str]:
        return {
            # TODO figure out why this test fails
            # "key": "description",
            # "values": self.data()["description"],
        }


class StixCyberObservableTest(EntityTest):
    def own_class(self):
        return self.api_client.stix_cyber_observable

    def base_class(self):
        return self.api_client.stix_cyber_observable

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {"x_opencti_score": 50}

    def get_compare_exception_keys(self) -> List[str]:
        # changes between pycti and opencti naming
        # fromId = from
        # toId = to
        # simple_observable_key = entity_type
        # simple_observable_value = observable_value & value
        # includes extracted creators field
        return [
            "type",
            "update",
            "creators",
            "createdBy",
            "modified",
            "simple_observable_key",
            "simple_observable_value",
        ]

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": "value",
                    "values": self.data()["simple_observable_value"],
                }
            ],
            "filterGroups": [],
        }


class StixCyberObservableIPv4Test(StixCyberObservableTest):
    def data(self) -> Dict:
        return {
            "simple_observable_key": "IPv4-Addr.value",
            "simple_observable_value": "198.51.100.3",
            "x_opencti_score": 30,
        }


class StixCyberObservableDomainTest(StixCyberObservableTest):
    def data(self) -> Dict:
        return {
            "simple_observable_key": "Domain-Name.value",
            "simple_observable_value": "example.com",
            "x_opencti_score": 30,
        }


class StixCyberObservableASTest(StixCyberObservableTest):
    def data(self) -> Dict:
        return {
            "simple_observable_key": "Autonomous-System.number",
            "simple_observable_value": 1234,
            "x_opencti_score": 30,
        }

    def get_filter(self) -> Dict[str, str]:
        return {
            "mode": "and",
            "filters": [],
            "filterGroups": [],
        }


class ToolTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Tool",
            "description": "The Evil Org threat actor group",
            "name": "VNC",
        }

    def own_class(self):
        return self.api_client.tool


class VulnerabilityTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Vulnerability",
            "name": "CVE-2016-1234",
            "description": "evil evil evil",
            # "external_references": [
            #     {
            #         "source_name": "cve",
            #         "external_id": "CVE-2016-1234"
            #     }
            # ]
        }

    def own_class(self):
        return self.api_client.vulnerability


class DataComponentTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "DataComponent",
            "name": "Command Execution",
            "description": "A command Execution",
        }

    def own_class(self):
        return self.api_client.data_component


class DataSourceTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "DataSource",
            "name": "Command",
            "description": "A command",
        }

    def own_class(self):
        return self.api_client.data_source


class FeedbackTest(EntityTest):
    def relation_test(self):
        return {
            "type": "Feedback",
            "name": "Feedback 2",
            "description": "Feedback Test 2",
        }

    def data(self) -> Dict:
        return {
            "type": "Feedback",
            "name": "Feedback 1",
            "description": "Feedback Test",
        }

    def update_data(self) -> Dict[str, Union[str, int]]:
        return {
            "name": "Feedback 1",
            "description": "Test",
        }

    def own_class(self):
        return self.api_client.feedback


class CaseIncidentTest(EntityTest):
    def relation_test(self):
        return {
            "type": "Case-Incident",
            "name": "Case Incident 2",
            "description": "Case Incident Desc 2",
            "created": "2023-03-30T08:01:50.924Z",
        }

    def data(self) -> Dict:
        return {
            "type": "Case-Incident",
            "name": "Case Incident",
            "description": "Case Incident Desc",
            "created": "2023-03-29T08:01:50.924Z",
        }

    def own_class(self):
        return self.api_client.case_incident


class CaseRfiTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Case-Rfi",
            "name": "Case Rfi",
            "description": "Case Rfi Desc",
            "created": "2023-03-28T08:01:50.924Z",
        }

    def own_class(self):
        return self.api_client.case_rfi


class CaseRftTest(EntityTest):
    def data(self) -> Dict:
        return {
            "type": "Case-Rft",
            "name": "Case Rft",
            "description": "Case Rft Desc",
            "created": "2023-03-29T08:01:50.924Z",
        }

    def own_class(self):
        return self.api_client.case_rft


class TaskTest(EntityTest):
    def data(self) -> Dict:
        return {
            "name": "Case Task",
            "description": "Test",
            "created": "2023-04-19T08:01:50.924Z",
        }

    def own_class(self):
        return self.api_client.task


class ThreatActorGroupTest(EntityTest):
    def data(self) -> Dict:
        return {
            "name": "Threat Actor Group",
            "description": "Test",
        }

    def own_class(self):
        return self.api_client.threat_actor_group


class ThreatActorIndividualTest(EntityTest):
    def data(self) -> Dict:
        return {
            "name": "Threat Actor Individual",
            "description": "Test",
        }

    def own_class(self):
        return self.api_client.threat_actor_individual


class RoleTest(EntityTest):
    def data(self) -> Dict:
        return {
            "name": "TestRole",
            "description": "This is a role for testing",
        }

    def own_class(self):
        return self.api_client.role

    def base_class(self):
        return self.own_class()

    def update_data(self) -> Dict[str, bool]:
        return {"can_manage_sensitive_config": True}

    def get_filter(self) -> Dict[str, str]:
        return {}

    def get_search(self) -> str:
        return "TestRole"


class GroupTest(EntityTest):
    def data(self) -> Dict:
        return {
            "name": "TestGroup",
            "group_confidence_level": {"max_confidence": 80, "overrides": []},
        }

    def own_class(self):
        return self.api_client.group

    def base_class(self):
        return self.own_class()

    def update_data(self) -> Dict:
        return {
            "description": "This is a test group",
            "no_creators": True,
            "group_confidence_level": {
                "max_confidence": 90,
                "overrides": [{"entity_type": "Indicator", "max_confidence": 80}],
            },
        }

    def get_search(self) -> str:
        return "TestGroup"


class UserTest(EntityTest):
    def data(self) -> Dict:
        return {
            "name": "Test User",
            "user_email": "test@localhost.local",
        }

    def own_class(self):
        return self.api_client.user

    def base_class(self):
        return self.own_class()

    def update_data(self) -> Dict:
        return {
            "description": "This is a test user",
            "firstname": "Test",
            "lastname": "User",
            "user_confidence_level": {
                "max_confidence": 70,
                "overrides": [{"entity_type": "Indicator", "max_confidence": 80}],
            },
            "account_status": "Locked",
            "submenu_show_icons": True,
        }

    def get_search(self):
        return '"Test User"'


class SettingsTest(EntityTest):

    class SettingsWrapper(Settings):
        def __init__(self, opencti):
            self._deleted = False
            super().__init__(opencti)

        def create(self, **kwargs) -> Dict:
            """Stub function for tests

            :return: Settings as defined by self.read()
            :rtype: Dict
            """
            self.opencti.admin_logger.info(
                "Settings.create called with arguments", kwargs
            )
            self._deleted = False
            return self.read()

        def delete(self, **kwargs):
            """Stub function for tests"""
            self.opencti.admin_logger.info(
                "Settings.delete called with arguments", kwargs
            )
            self._deleted = True

        def read(self, **kwargs):
            """Stub function for tests"""
            if self._deleted:
                return None
            return super().read(**kwargs)

    def setup(self):
        self._ownclass = self.SettingsWrapper(self.api_client)
        # Save current platform information
        custom_attributes = self.own_class().editable_properties
        self.own_class().create()
        self._saved_settings = self.own_class().read(customAttributes=custom_attributes)
        if self._saved_settings["platform_organization"] is not None:
            self._saved_settings["platform_organization"] = self._saved_settings[
                "platform_organization"
            ]["id"]
        return

    def teardown(self):
        # Restore platform information
        id = self._saved_settings.pop("id")
        input = [
            {"key": key, "value": value}
            for key, value in self._saved_settings.items()
            if value is not None
        ]
        self.own_class().update_field(id=id, input=input)
        return

    def data(self) -> Dict:
        return {}

    def own_class(self):
        return self._ownclass

    def base_class(self):
        return self.own_class()

    def update_data(self):
        return {"platform_title": "This is a test platform", "platform_theme": "light"}

    def get_filter(self):
        return None
