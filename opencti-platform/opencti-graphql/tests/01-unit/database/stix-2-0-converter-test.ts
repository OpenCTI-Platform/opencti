import { describe, it, expect } from 'vitest';
import '../../../src/modules/index';
import { EXPECTED_MALWARE, MALWARE_INSTANCE } from './instances-stix-2-0-converter/malware';
import { EXPECTED_REPORT, REPORT_INSTANCE } from './instances-stix-2-0-converter/containers/report';
import { EXPECTED_OBSERVED_DATA, OBSERVED_DATA_INSTANCE } from './instances-stix-2-0-converter/containers/observed-data';
import { EXPECTED_NOTE, NOTE_INSTANCE } from './instances-stix-2-0-converter/containers/note';
import { EXPECTED_OPINION, OPINION_INSTANCE } from './instances-stix-2-0-converter/containers/opinion';
import { EXPECTED_GROUPING, GROUPING_INSTANCE } from './instances-stix-2-0-converter/containers/grouping';
import { EXPECTED_FEEDBACK, FEEDBACK_INSTANCE } from './instances-stix-2-0-converter/containers/feedback';
import { EXPECTED_TASK, TASK_INSTANCE } from './instances-stix-2-0-converter/containers/task';
import { EXPECTED_IR, INCIDENT_RESPONSE_INSTANCE } from './instances-stix-2-0-converter/containers/incident_response';
import { EXPECTED_RFT, RFT_INSTANCE } from './instances-stix-2-0-converter/containers/case_rft';
import { EXPECTED_RFI, RFI_INSTANCE } from './instances-stix-2-0-converter/containers/case_rfi';
import { EXPECTED_TOOL, TOOL_INSTANCE } from './instances-stix-2-0-converter/tool';
import { EXPECTED_VULNERABILITY, INSTANCE_VULNERABILITY } from './instances-stix-2-0-converter/vulnerability';
import { CHANNEL_INSTANCE, EXPECTED_CHANNEL } from './instances-stix-2-0-converter/channel';
import { convertGroupingToStix_2_0 } from '../../../src/modules/grouping/grouping-converter';
import { convertFeedbackToStix_2_0 } from '../../../src/modules/case/feedback/feedback-converter';
import { convertTaskToStix_2_0 } from '../../../src/modules/task/task-converter';
import { convertCaseIncidentToStix_2_0 } from '../../../src/modules/case/case-incident/case-incident-converter';
import { convertCaseRftToStix_2_0 } from '../../../src/modules/case/case-rft/case-rft-converter';
import { convertCaseRfiToStix_2_0 } from '../../../src/modules/case/case-rfi/case-rfi-converter';
import { convertChannelToStix_2_0 } from '../../../src/modules/channel/channel-converter';
import { convertThreatActorIndividualToStix_2_0 } from '../../../src/modules/threatActorIndividual/threatActorIndividual-converter';
import { convertNarrativeToStix_2_0 } from '../../../src/modules/narrative/narrative-converter';
import { convertDataComponentToStix_2_0 } from '../../../src/modules/dataComponent/dataComponent-converter';
import { convertDataSourceToStix_2_0 } from '../../../src/modules/dataSource/dataSource-converter';
import { convertOrganizationToStix_2_0 } from '../../../src/modules/organization/organization-converter';
import { convertSecurityPlatformToStix_2_0 } from '../../../src/modules/securityPlatform/securityPlatform-converter';
import {
  convertAttackPatternToStix,
  convertCampaignToStix,
  convertCourseOfActionToStix,
  convertIntrusionSetToStix,
  convertToolToStix,
  convertThreatActorGroupToStix,
  convertVulnerabilityToStix,
  convertMalwareToStix,
  convertNoteToStix,
  convertObservedDataToStix,
  convertOpinionToStix,
  convertReportToStix,
  convertIncidentToStix,
  convertSightingToStix,
  convertIdentityToStix,
} from '../../../src/database/stix-2-0-converter';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_IDENTITY_SYSTEM } from '../../../src/schema/stixDomainObject';
import { CAMPAIGN_INSTANCE, EXPECTED_CAMPAIGN } from './instances-stix-2-0-converter/SDOs/campaign';
import { EXPECTED_INCIDENT, INCIDENT_INSTANCE } from './instances-stix-2-0-converter/SDOs/incident';
import { EXPECTED_INTRUSION_SET, INTRUSION_SET_INSTANCE } from './instances-stix-2-0-converter/SDOs/intrusion-set';
import { EXPECTED_THREAT_ACTOR_GROUP, THREAT_ACTOR_GROUP_INSTANCE } from './instances-stix-2-0-converter/SDOs/threat-actor-group';
import { EXPECTED_THREAT_ACTOR_INDIVIDUAL, THREAT_ACTOR_INDIVIDUAL_INSTANCE } from './instances-stix-2-0-converter/SDOs/threat-actor-individual';
import { EXPECTED_SIGHTING, SIGHTING_INSTANCE } from './instances-stix-2-0-converter/sightings';
import { ATTACK_PATTERN_INSTANCE, EXPECTED_ATTACK_PATTERN } from './instances-stix-2-0-converter/techniques/attack-pattern';
import { EXPECTED_NARRATIVE, NARRATIVE_INSTANCE } from './instances-stix-2-0-converter/techniques/narrative';
import { COURSE_OF_ACTION_INSTANCE, EXPECTED_COURSE_OF_ACTION } from './instances-stix-2-0-converter/techniques/course-of-action';
import { DATA_COMPONENT_INSTANCE, EXPECTED_DATA_COMPONENT } from './instances-stix-2-0-converter/techniques/data-component';
import { DATA_SOURCE_INSTANCE, EXPECTED_DATA_SOURCE } from './instances-stix-2-0-converter/techniques/data-source';
import { INDIVIDUAL_INSTANCE, EXPECTED_INDIVIDUAL } from './instances-stix-2-0-converter/identities/individual';
import { SECTOR_INSTANCE, EXPECTED_SECTOR } from './instances-stix-2-0-converter/identities/sector';
import { SYSTEM_INSTANCE, EXPECTED_SYSTEM } from './instances-stix-2-0-converter/identities/system';
import { ORGANIZATION_INSTANCE, EXPECTED_ORGANIZATION } from './instances-stix-2-0-converter/identities/organization';
import { SECURITY_PLATFORM_INSTANCE, EXPECTED_SECURITY_PLATFORM } from './instances-stix-2-0-converter/identities/security-platform';
import { EVENT_INSTANCE, EXPECTED_EVENT } from './instances-stix-2-0-converter/event';
import { convertEventToStix_2_0 } from '../../../src/modules/event/event-converter';

describe('Stix 2.0 opencti converter', () => {
  // SDOs
  it('should convert Malware', async () => {
    const result = convertMalwareToStix(MALWARE_INSTANCE);
    expect(result).toEqual(EXPECTED_MALWARE);
  });
  it('should convert Channel', async () => {
    const result = convertChannelToStix_2_0(CHANNEL_INSTANCE);
    expect(result).toEqual(EXPECTED_CHANNEL);
  });
  it('should convert Tool', async () => {
    const result = convertToolToStix(TOOL_INSTANCE);
    expect(result).toEqual(EXPECTED_TOOL);
  });
  it('should convert Vulnerability', async () => {
    const result = convertVulnerabilityToStix(INSTANCE_VULNERABILITY);
    expect(result).toEqual(EXPECTED_VULNERABILITY);
  });
  it('should convert Incident', async () => {
    const result = convertIncidentToStix(INCIDENT_INSTANCE);
    expect(result).toEqual(EXPECTED_INCIDENT);
  });
  it('should convert Campaign', async () => {
    const result = convertCampaignToStix(CAMPAIGN_INSTANCE);
    expect(result).toEqual(EXPECTED_CAMPAIGN);
  });
  it('should convert Intrusion Set', async () => {
    const result = convertIntrusionSetToStix(INTRUSION_SET_INSTANCE);
    expect(result).toEqual(EXPECTED_INTRUSION_SET);
  });
  it('should convert Threat Actor Group', async () => {
    const result = convertThreatActorGroupToStix(THREAT_ACTOR_GROUP_INSTANCE);
    expect(result).toEqual(EXPECTED_THREAT_ACTOR_GROUP);
  });
  it('should convert Threat Actor Individual', async () => {
    const result = convertThreatActorIndividualToStix_2_0(THREAT_ACTOR_INDIVIDUAL_INSTANCE);
    expect(result).toEqual(EXPECTED_THREAT_ACTOR_INDIVIDUAL);
  });
  // Techniques
  it('should convert Attack Pattern', async () => {
    const result = convertAttackPatternToStix(ATTACK_PATTERN_INSTANCE);
    expect(result).toEqual(EXPECTED_ATTACK_PATTERN);
  });
  it('should convert Narrative', async () => {
    const result = convertNarrativeToStix_2_0(NARRATIVE_INSTANCE);
    expect(result).toEqual(EXPECTED_NARRATIVE);
  });
  it('should convert Course of Action', async () => {
    const result = convertCourseOfActionToStix(COURSE_OF_ACTION_INSTANCE);
    expect(result).toEqual(EXPECTED_COURSE_OF_ACTION);
  });
  it('should convert Data Component', async () => {
    const result = convertDataComponentToStix_2_0(DATA_COMPONENT_INSTANCE);
    expect(result).toEqual(EXPECTED_DATA_COMPONENT);
  });
  it('should convert Data Source', async () => {
    const result = convertDataSourceToStix_2_0(DATA_SOURCE_INSTANCE);
    expect(result).toEqual(EXPECTED_DATA_SOURCE);
  });
  // Containers
  it('should convert Report', async () => {
    const result = convertReportToStix(REPORT_INSTANCE);
    expect(result).toEqual(EXPECTED_REPORT);
  });
  it('should convert Note', async () => {
    const result = convertNoteToStix(NOTE_INSTANCE);
    expect(result).toEqual(EXPECTED_NOTE);
  });
  it('should convert ObservedData', async () => {
    const result = convertObservedDataToStix(OBSERVED_DATA_INSTANCE);
    expect(result).toEqual(EXPECTED_OBSERVED_DATA);
  });
  it('should convert Opinion', async () => {
    const result = convertOpinionToStix(OPINION_INSTANCE);
    expect(result).toEqual(EXPECTED_OPINION);
  });
  it('should convert Grouping', async () => {
    const result = convertGroupingToStix_2_0(GROUPING_INSTANCE);
    expect(result).toEqual(EXPECTED_GROUPING);
  });
  it('should convert Feedback', async () => {
    const result = convertFeedbackToStix_2_0(FEEDBACK_INSTANCE);
    expect(result).toEqual(EXPECTED_FEEDBACK);
  });
  it('should convert Task', async () => {
    const result = convertTaskToStix_2_0(TASK_INSTANCE);
    expect(result).toEqual(EXPECTED_TASK);
  });
  it('should convert Incident Response', async () => {
    const result = convertCaseIncidentToStix_2_0(INCIDENT_RESPONSE_INSTANCE);
    expect(result).toEqual(EXPECTED_IR);
  });
  it('should convert Case RFI', async () => {
    const result = convertCaseRfiToStix_2_0(RFI_INSTANCE);
    expect(result).toEqual(EXPECTED_RFI);
  });
  it('should convert Case RFT', async () => {
    const result = convertCaseRftToStix_2_0(RFT_INSTANCE);
    expect(result).toEqual(EXPECTED_RFT);
  });
  // SROs
  it('should convert StixSightingRelationship', async () => {
    const result = convertSightingToStix(SIGHTING_INSTANCE);
    expect(result).toEqual(EXPECTED_SIGHTING);
  });
  // Identities
  it('should convert Individual', async () => {
    const result = convertIdentityToStix(INDIVIDUAL_INSTANCE, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
    expect(result).toEqual(EXPECTED_INDIVIDUAL);
  });
  it('should convert Sector', async () => {
    const result = convertIdentityToStix(SECTOR_INSTANCE, ENTITY_TYPE_IDENTITY_SECTOR);
    expect(result).toEqual(EXPECTED_SECTOR);
  });
  it('should convert System', async () => {
    const result = convertIdentityToStix(SYSTEM_INSTANCE, ENTITY_TYPE_IDENTITY_SYSTEM);
    expect(result).toEqual(EXPECTED_SYSTEM);
  });
  it('should convert Organization', async () => {
    const result = convertOrganizationToStix_2_0(ORGANIZATION_INSTANCE);
    expect(result).toEqual(EXPECTED_ORGANIZATION);
  });
  it('should convert SecurityPlatform', async () => {
    const result = convertSecurityPlatformToStix_2_0(SECURITY_PLATFORM_INSTANCE);
    expect(result).toEqual(EXPECTED_SECURITY_PLATFORM);
  });
  // Events
  it('should convert Event', async () => {
    const result = convertEventToStix_2_0(EVENT_INSTANCE);
    expect(result).toEqual(EXPECTED_EVENT);
  });
});
