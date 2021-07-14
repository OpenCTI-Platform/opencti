import pytest

from pycti import OpenCTIApiClient
from tests.modules.modules import (
    ThreatActorTest,
    ToolTest,
    VulnerabilityTest,
    StixSightingRelationshipTest,
    AttackPatternTest,
    CampaignTest,
    CourseOfActionTest,
    ExternalReferenceTest,
    IdentityTest,
    IncidentTest,
    InfrastructureTest,
    IndicatorTest,
    IntrusionSetTest,
    KillChainPhaseTest,
    LabelTest,
    LocationTest,
    MalwareTest,
    MarkingDefinitionTest,
    NoteTest,
    ObservedDataTest,
    OpinionTest,
    ReportTest,
    StixCoreRelationshipTest,
    StixCyberObservableTest,
)


@pytest.fixture
def api_client(request):
    return OpenCTIApiClient(
        "https://demo.opencti.io",
        "681b01f9-542d-4c8c-be0c-b6c850b087c8",
        ssl_verify=True,
    )


@pytest.fixture
def fruit_bowl(api_client):
    return {
        "Attack-Pattern": AttackPatternTest(api_client),
        "Campaign": CampaignTest(api_client),
        "Course-Of-Action": CourseOfActionTest(api_client),
        "External-Reference": ExternalReferenceTest(api_client),
        "Identity": IdentityTest(api_client),
        "Incident": IncidentTest(api_client),
        "Infrastructure": InfrastructureTest(api_client),
        "Indicator": IndicatorTest(api_client),
        "IntrusionSet": IntrusionSetTest(api_client),
        "KillChainPhase": KillChainPhaseTest(api_client),
        "Label": LabelTest(api_client),
        "Location": LocationTest(api_client),
        "Malware": MalwareTest(api_client),
        "MarkingDefinition": MarkingDefinitionTest(api_client),
        "Note": NoteTest(api_client),
        "ObservedData": ObservedDataTest(api_client),
        "Opinion": OpinionTest(api_client),
        "Report": ReportTest(api_client),
        "Relationship": StixCoreRelationshipTest(api_client),
        "StixCyberObservable": StixCyberObservableTest(api_client),
        # "StixCyberObservableRelationship": StixCyberObservableRelationshipTest(api_client),
        # "StixDomainObject": TODO,
        # "StixObjectOrStixRelationship": TODO,
        "StixSightingRelationship": StixSightingRelationshipTest(api_client),
        "ThreatActor": ThreatActorTest(api_client),
        "Tool": ToolTest(api_client),
        "Vulnerability": VulnerabilityTest(api_client),
    }
