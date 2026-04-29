import { describe, it, expect } from 'vitest';
import '../../../src/modules/index';
import { EXPECTED_MALWARE, MALWARE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/arsenal/malware';
import { EXPECTED_REPORT, REPORT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/report';
import { EXPECTED_OBSERVED_DATA, OBSERVED_DATA_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/observed-data';
import { EXPECTED_NOTE, NOTE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/note';
import { EXPECTED_OPINION, OPINION_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/opinion';
import { EXPECTED_GROUPING, GROUPING_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/grouping';
import { EXPECTED_FEEDBACK, FEEDBACK_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/feedback';
import { EXPECTED_TASK, TASK_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/task';
import { EXPECTED_IR, INCIDENT_RESPONSE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/incident_response';
import { EXPECTED_RFT, RFT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/case_rft';
import { EXPECTED_RFI, RFI_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/case_rfi';
import { EXPECTED_TOOL, TOOL_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/arsenal/tool';
import { EXPECTED_VULNERABILITY, INSTANCE_VULNERABILITY } from './stix-2-0-converter-fixtures/SDOs/arsenal/vulnerability';
import { CHANNEL_INSTANCE, EXPECTED_CHANNEL } from './stix-2-0-converter-fixtures/SDOs/arsenal/channel';
import { MALWARE_ANALYSIS_INSTANCE, EXPECTED_MALWARE_ANALYSIS } from './stix-2-0-converter-fixtures/SDOs/arsenal/malware-analysis';
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
  convertRelationToStix,
  convertInPirRelToStix,
  convertIdentityToStix,
  convertLocationToStix,
  convertStoreToStix_2_0,
  convertMarkingDefinitionToStix,
  convertLabelToStix,
  convertKillChainPhaseToStix,
  convertExternalReferenceToStix,
  convertInfrastructureToStix,
} from '../../../src/database/stix-2-0-converter';
import {
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_POSITION,
} from '../../../src/schema/stixDomainObject';
import { CAMPAIGN_INSTANCE, EXPECTED_CAMPAIGN } from './stix-2-0-converter-fixtures/SDOs/threats/campaign';
import { EXPECTED_INCIDENT, INCIDENT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/incident';
import { EXPECTED_INTRUSION_SET, INTRUSION_SET_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/intrusion-set';
import { EXPECTED_THREAT_ACTOR_GROUP, THREAT_ACTOR_GROUP_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/threat-actor-group';
import { EXPECTED_THREAT_ACTOR_INDIVIDUAL, THREAT_ACTOR_INDIVIDUAL_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/threat-actor-individual';
import { EXPECTED_SIGHTING, SIGHTING_INSTANCE } from './stix-2-0-converter-fixtures/SROs/sightings';
import { EXPECTED_RELATION, RELATION_INSTANCE } from './stix-2-0-converter-fixtures/SROs/relation';
import { EXPECTED_PIR_RELATION, PIR_RELATION_INSTANCE } from './stix-2-0-converter-fixtures/SROs/pir-relation';
import { ATTACK_PATTERN_INSTANCE, EXPECTED_ATTACK_PATTERN } from './stix-2-0-converter-fixtures/SDOs/techniques/attack-pattern';
import { EXPECTED_NARRATIVE, NARRATIVE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/techniques/narrative';
import { COURSE_OF_ACTION_INSTANCE, EXPECTED_COURSE_OF_ACTION } from './stix-2-0-converter-fixtures/SDOs/techniques/course-of-action';
import { DATA_COMPONENT_INSTANCE, EXPECTED_DATA_COMPONENT } from './stix-2-0-converter-fixtures/SDOs/techniques/data-component';
import { DATA_SOURCE_INSTANCE, EXPECTED_DATA_SOURCE } from './stix-2-0-converter-fixtures/SDOs/techniques/data-source';
import { INDIVIDUAL_INSTANCE, EXPECTED_INDIVIDUAL } from './stix-2-0-converter-fixtures/SDOs/entities/individual';
import { SECTOR_INSTANCE, EXPECTED_SECTOR } from './stix-2-0-converter-fixtures/SDOs/entities/sector';
import { SYSTEM_INSTANCE, EXPECTED_SYSTEM } from './stix-2-0-converter-fixtures/SDOs/entities/system';
import { ORGANIZATION_INSTANCE, EXPECTED_ORGANIZATION } from './stix-2-0-converter-fixtures/SDOs/entities/organization';
import { SECURITY_PLATFORM_INSTANCE, EXPECTED_SECURITY_PLATFORM } from './stix-2-0-converter-fixtures/SDOs/entities/security-platform';
import { EVENT_INSTANCE, EXPECTED_EVENT } from './stix-2-0-converter-fixtures/SDOs/entities/event';
import { convertEventToStix_2_0 } from '../../../src/modules/event/event-converter';
import { REGION_INSTANCE, EXPECTED_REGION } from './stix-2-0-converter-fixtures/SDOs/locations/region';
import { COUNTRY_INSTANCE, EXPECTED_COUNTRY } from './stix-2-0-converter-fixtures/SDOs/locations/country';
import { CITY_INSTANCE, EXPECTED_CITY } from './stix-2-0-converter-fixtures/SDOs/locations/city';
import { POSITION_INSTANCE, EXPECTED_POSITION } from './stix-2-0-converter-fixtures/SDOs/locations/position';
import { ADMINISTRATIVE_AREA_INSTANCE, EXPECTED_ADMINISTRATIVE_AREA } from './stix-2-0-converter-fixtures/SDOs/locations/administrative-area';
import { convertAdministrativeAreaToStix_2_0 } from '../../../src/modules/administrativeArea/administrativeArea-converter';
import { convertIndicatorToStix_2_0 } from '../../../src/modules/indicator/indicator-converter';
import { convertMalwareAnalysisToStix_2_0 } from '../../../src/modules/malwareAnalysis/malwareAnalysis-converter';
import { INDICATOR_INSTANCE, EXPECTED_INDICATOR } from './stix-2-0-converter-fixtures/SDOs/observations/indicator';
import { IPV4_INSTANCE, EXPECTED_IPV4 } from './stix-2-0-converter-fixtures/SCOs/ipv4-addr';
import { DOMAIN_NAME_INSTANCE, EXPECTED_DOMAIN_NAME } from './stix-2-0-converter-fixtures/SCOs/domain-name';
import { URL_INSTANCE, EXPECTED_URL } from './stix-2-0-converter-fixtures/SCOs/url';
import { EMAIL_ADDR_INSTANCE, EXPECTED_EMAIL_ADDR } from './stix-2-0-converter-fixtures/SCOs/email-addr';
import { FILE_INSTANCE, EXPECTED_FILE } from './stix-2-0-converter-fixtures/SCOs/file';
import { AUTONOMOUS_SYSTEM_INSTANCE, EXPECTED_AUTONOMOUS_SYSTEM } from './stix-2-0-converter-fixtures/SCOs/autonomous-system';
import {
  convertIPv4AddressToStix,
  convertDomainNameToStix,
  convertURLToStix,
  convertEmailAddressToStix,
  convertFileToStix,
  convertAutonomousSystemToStix,
  convertIPv6AddressToStix,
  convertMacAddressToStix,
  convertMutexToStix,
  convertDirectoryToStix,
  convertSoftwareToStix,
  convertUserAccountToStix,
  convertNetworkTrafficToStix,
  convertProcessToStix,
  convertArtifactToStix,
  convertX509CertificateToStix,
  convertHostnameToStix,
  convertCryptocurrencyWalletToStix,
  convertBankAccountToStix,
  convertPhoneNumberToStix,
  convertPersonaToStix,
  convertEmailMessageToStix,
  convertEmailMimePartToStix,
  convertWindowsRegistryKeyToStix,
  convertWindowsRegistryValueToStix,
  convertCredentialToStix,
  convertTextToStix,
  convertUserAgentToStix,
  convertTrackingNumberToStix,
  convertMediaContentToStix,
  convertSSHKeyToStix,
  convertCryptographicKeyToStix,
  convertPaymentCardToStix,
  convertAIPromptToStix,
  convertIMEIToStix,
  convertICCIDToStix,
  convertIMSIToStix,
} from '../../../src/database/stix-2-0-converter';
import { IPV6_INSTANCE, EXPECTED_IPV6 } from './stix-2-0-converter-fixtures/SCOs/ipv6-addr';
import { MAC_ADDR_INSTANCE, EXPECTED_MAC_ADDR } from './stix-2-0-converter-fixtures/SCOs/mac-addr';
import { MUTEX_INSTANCE, EXPECTED_MUTEX } from './stix-2-0-converter-fixtures/SCOs/mutex';
import { DIRECTORY_INSTANCE, EXPECTED_DIRECTORY } from './stix-2-0-converter-fixtures/SCOs/directory';
import { SOFTWARE_INSTANCE, EXPECTED_SOFTWARE } from './stix-2-0-converter-fixtures/SCOs/software';
import { USER_ACCOUNT_INSTANCE, EXPECTED_USER_ACCOUNT } from './stix-2-0-converter-fixtures/SCOs/user-account';
import { NETWORK_TRAFFIC_INSTANCE, EXPECTED_NETWORK_TRAFFIC } from './stix-2-0-converter-fixtures/SCOs/network-traffic';
import { PROCESS_INSTANCE, EXPECTED_PROCESS } from './stix-2-0-converter-fixtures/SCOs/process';
import { ARTIFACT_INSTANCE, EXPECTED_ARTIFACT } from './stix-2-0-converter-fixtures/SCOs/artifact';
import { X509_INSTANCE, EXPECTED_X509 } from './stix-2-0-converter-fixtures/SCOs/x509-certificate';
import {
  HOSTNAME_INSTANCE,
  EXPECTED_HOSTNAME,
  CRYPTOCURRENCY_WALLET_INSTANCE,
  EXPECTED_CRYPTOCURRENCY_WALLET,
  BANK_ACCOUNT_INSTANCE,
  EXPECTED_BANK_ACCOUNT,
  PHONE_NUMBER_INSTANCE,
  EXPECTED_PHONE_NUMBER,
  PERSONA_INSTANCE,
  EXPECTED_PERSONA,
} from './stix-2-0-converter-fixtures/SCOs/custom-observables';
import { EMAIL_MESSAGE_INSTANCE, EXPECTED_EMAIL_MESSAGE } from './stix-2-0-converter-fixtures/SCOs/email-message';
import { WINDOWS_REGISTRY_KEY_INSTANCE, EXPECTED_WINDOWS_REGISTRY_KEY } from './stix-2-0-converter-fixtures/SCOs/windows-registry-key';
import { WINDOWS_REGISTRY_VALUE_INSTANCE, EXPECTED_WINDOWS_REGISTRY_VALUE } from './stix-2-0-converter-fixtures/SCOs/windows-registry-value';
import { CREDENTIAL_INSTANCE, EXPECTED_CREDENTIAL } from './stix-2-0-converter-fixtures/SCOs/credential';
import { TEXT_INSTANCE, EXPECTED_TEXT } from './stix-2-0-converter-fixtures/SCOs/text';
import { USER_AGENT_INSTANCE, EXPECTED_USER_AGENT } from './stix-2-0-converter-fixtures/SCOs/user-agent';
import { TRACKING_NUMBER_INSTANCE, EXPECTED_TRACKING_NUMBER } from './stix-2-0-converter-fixtures/SCOs/tracking-number';
import { MEDIA_CONTENT_INSTANCE, EXPECTED_MEDIA_CONTENT } from './stix-2-0-converter-fixtures/SCOs/media-content';
import { SSH_KEY_INSTANCE, EXPECTED_SSH_KEY } from './stix-2-0-converter-fixtures/SCOs/ssh-key';
import { CRYPTOGRAPHIC_KEY_INSTANCE, EXPECTED_CRYPTOGRAPHIC_KEY } from './stix-2-0-converter-fixtures/SCOs/cryptographic-key';
import { IMEI_INSTANCE, EXPECTED_IMEI } from './stix-2-0-converter-fixtures/SCOs/imei';
import { PAYMENT_CARD_INSTANCE, EXPECTED_PAYMENT_CARD } from './stix-2-0-converter-fixtures/SCOs/payment-card';
import { AI_PROMPT_INSTANCE, EXPECTED_AI_PROMPT } from './stix-2-0-converter-fixtures/SCOs/ai-prompt';
import { ICCID_INSTANCE, EXPECTED_ICCID } from './stix-2-0-converter-fixtures/SCOs/iccid';
import { IMSI_INSTANCE, EXPECTED_IMSI } from './stix-2-0-converter-fixtures/SCOs/imsi';
import { EMAIL_MIME_PART_INSTANCE, EXPECTED_EMAIL_MIME_PART } from './stix-2-0-converter-fixtures/SCOs/email-mime-part';
import {
  MARKING_DEFINITION_INSTANCE,
  EXPECTED_MARKING_DEFINITION,
  PAP_MARKING_DEFINITION_INSTANCE,
  EXPECTED_PAP_MARKING_DEFINITION,
} from './stix-2-0-converter-fixtures/SMOs/marking-definition';
import { LABEL_INSTANCE, EXPECTED_LABEL } from './stix-2-0-converter-fixtures/SMOs/label';
import { KILL_CHAIN_PHASE_INSTANCE, EXPECTED_KILL_CHAIN_PHASE } from './stix-2-0-converter-fixtures/SMOs/kill-chain-phase';
import { EXTERNAL_REFERENCE_INSTANCE, EXPECTED_EXTERNAL_REFERENCE } from './stix-2-0-converter-fixtures/SMOs/external-reference';
import { EXPECTED_INFRASTRUCTURE, INFRASTRUCTURE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/observations/infrastructure';

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
  it('should convert Malware Analysis', async () => {
    const result = convertMalwareAnalysisToStix_2_0(MALWARE_ANALYSIS_INSTANCE as any);
    expect(result).toEqual(EXPECTED_MALWARE_ANALYSIS);
  });
  it('should convert Indicator', async () => {
    const result = convertIndicatorToStix_2_0(INDICATOR_INSTANCE);
    expect(result).toEqual(EXPECTED_INDICATOR);
  });
  it('should convert Infrastructure', async () => {
    const result = convertInfrastructureToStix(INFRASTRUCTURE_INSTANCE);
    expect(result).toEqual(EXPECTED_INFRASTRUCTURE);
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
  it('should convert StixCoreRelationship', async () => {
    const result = convertRelationToStix(RELATION_INSTANCE);
    expect(result).toEqual(EXPECTED_RELATION);
  });
  it('should convert InPirRelationship', async () => {
    const result = convertInPirRelToStix(PIR_RELATION_INSTANCE);
    expect(result).toEqual(EXPECTED_PIR_RELATION);
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
  // SCOs (Observables)
  it('should convert IPv4 Address', async () => {
    const result = convertIPv4AddressToStix(IPV4_INSTANCE);
    expect(result).toEqual(EXPECTED_IPV4);
  });
  it('should convert Domain Name', async () => {
    const result = convertDomainNameToStix(DOMAIN_NAME_INSTANCE);
    expect(result).toEqual(EXPECTED_DOMAIN_NAME);
  });
  it('should convert URL', async () => {
    const result = convertURLToStix(URL_INSTANCE);
    expect(result).toEqual(EXPECTED_URL);
  });
  it('should convert Email Address', async () => {
    const result = convertEmailAddressToStix(EMAIL_ADDR_INSTANCE);
    expect(result).toEqual(EXPECTED_EMAIL_ADDR);
  });
  it('should convert File', async () => {
    const result = convertFileToStix(FILE_INSTANCE);
    expect(result).toEqual(EXPECTED_FILE);
  });
  it('should convert Autonomous System', async () => {
    const result = convertAutonomousSystemToStix(AUTONOMOUS_SYSTEM_INSTANCE);
    expect(result).toEqual(EXPECTED_AUTONOMOUS_SYSTEM);
  });
  it('should convert IPv6 Address', async () => {
    const result = convertIPv6AddressToStix(IPV6_INSTANCE);
    expect(result).toEqual(EXPECTED_IPV6);
  });
  it('should convert Mac Address', async () => {
    const result = convertMacAddressToStix(MAC_ADDR_INSTANCE);
    expect(result).toEqual(EXPECTED_MAC_ADDR);
  });
  it('should convert Mutex', async () => {
    const result = convertMutexToStix(MUTEX_INSTANCE);
    expect(result).toEqual(EXPECTED_MUTEX);
  });
  it('should convert Directory', async () => {
    const result = convertDirectoryToStix(DIRECTORY_INSTANCE);
    expect(result).toEqual(EXPECTED_DIRECTORY);
  });
  it('should convert Software', async () => {
    const result = convertSoftwareToStix(SOFTWARE_INSTANCE);
    expect(result).toEqual(EXPECTED_SOFTWARE);
  });
  it('should convert User Account', async () => {
    const result = convertUserAccountToStix(USER_ACCOUNT_INSTANCE);
    expect(result).toEqual(EXPECTED_USER_ACCOUNT);
  });
  it('should convert Network Traffic', async () => {
    const result = convertNetworkTrafficToStix(NETWORK_TRAFFIC_INSTANCE);
    expect(result).toEqual(EXPECTED_NETWORK_TRAFFIC);
  });
  it('should convert Process', async () => {
    const result = convertProcessToStix(PROCESS_INSTANCE);
    expect(result).toEqual(EXPECTED_PROCESS);
  });
  it('should convert Artifact', async () => {
    const result = convertArtifactToStix(ARTIFACT_INSTANCE);
    expect(result).toEqual(EXPECTED_ARTIFACT);
  });
  it('should convert X509 Certificate', async () => {
    const result = convertX509CertificateToStix(X509_INSTANCE);
    expect(result).toEqual(EXPECTED_X509);
  });
  it('should convert Hostname', async () => {
    const result = convertHostnameToStix(HOSTNAME_INSTANCE);
    expect(result).toEqual(EXPECTED_HOSTNAME);
  });
  it('should convert Cryptocurrency Wallet', async () => {
    const result = convertCryptocurrencyWalletToStix(CRYPTOCURRENCY_WALLET_INSTANCE);
    expect(result).toEqual(EXPECTED_CRYPTOCURRENCY_WALLET);
  });
  it('should convert Bank Account', async () => {
    const result = convertBankAccountToStix(BANK_ACCOUNT_INSTANCE);
    expect(result).toEqual(EXPECTED_BANK_ACCOUNT);
  });
  it('should convert Phone Number', async () => {
    const result = convertPhoneNumberToStix(PHONE_NUMBER_INSTANCE);
    expect(result).toEqual(EXPECTED_PHONE_NUMBER);
  });
  it('should convert Persona', async () => {
    const result = convertPersonaToStix(PERSONA_INSTANCE);
    expect(result).toEqual(EXPECTED_PERSONA);
  });
  it('should convert Email Message', async () => {
    const result = convertEmailMessageToStix(EMAIL_MESSAGE_INSTANCE);
    expect(result).toEqual(EXPECTED_EMAIL_MESSAGE);
  });
  it('should convert Email Mime Part', async () => {
    const result = convertEmailMimePartToStix(EMAIL_MIME_PART_INSTANCE);
    expect(result).toEqual(EXPECTED_EMAIL_MIME_PART);
  });
  it('should convert Windows Registry Key', async () => {
    const result = convertWindowsRegistryKeyToStix(WINDOWS_REGISTRY_KEY_INSTANCE);
    expect(result).toEqual(EXPECTED_WINDOWS_REGISTRY_KEY);
  });
  it('should convert Windows Registry Value', async () => {
    const result = convertWindowsRegistryValueToStix(WINDOWS_REGISTRY_VALUE_INSTANCE);
    expect(result).toEqual(EXPECTED_WINDOWS_REGISTRY_VALUE);
  });
  it('should convert Credential', async () => {
    const result = convertCredentialToStix(CREDENTIAL_INSTANCE);
    expect(result).toEqual(EXPECTED_CREDENTIAL);
  });
  it('should convert Text', async () => {
    const result = convertTextToStix(TEXT_INSTANCE);
    expect(result).toEqual(EXPECTED_TEXT);
  });
  it('should convert User Agent', async () => {
    const result = convertUserAgentToStix(USER_AGENT_INSTANCE);
    expect(result).toEqual(EXPECTED_USER_AGENT);
  });
  it('should convert Tracking Number', async () => {
    const result = convertTrackingNumberToStix(TRACKING_NUMBER_INSTANCE);
    expect(result).toEqual(EXPECTED_TRACKING_NUMBER);
  });
  it('should convert Media Content', async () => {
    const result = convertMediaContentToStix(MEDIA_CONTENT_INSTANCE);
    expect(result).toEqual(EXPECTED_MEDIA_CONTENT);
  });
  it('should convert SSH Key', async () => {
    const result = convertSSHKeyToStix(SSH_KEY_INSTANCE);
    expect(result).toEqual(EXPECTED_SSH_KEY);
  });
  it('should convert Cryptographic Key', async () => {
    const result = convertCryptographicKeyToStix(CRYPTOGRAPHIC_KEY_INSTANCE);
    expect(result).toEqual(EXPECTED_CRYPTOGRAPHIC_KEY);
  });
  it('should convert Payment Card', async () => {
    const result = convertPaymentCardToStix(PAYMENT_CARD_INSTANCE);
    expect(result).toEqual(EXPECTED_PAYMENT_CARD);
  });
  it('should convert AI Prompt', async () => {
    const result = convertAIPromptToStix(AI_PROMPT_INSTANCE);
    expect(result).toEqual(EXPECTED_AI_PROMPT);
  });
  it('should convert IMEI', async () => {
    const result = convertIMEIToStix(IMEI_INSTANCE);
    expect(result).toEqual(EXPECTED_IMEI);
  });
  it('should convert ICCID', async () => {
    const result = convertICCIDToStix(ICCID_INSTANCE);
    expect(result).toEqual(EXPECTED_ICCID);
  });
  it('should convert IMSI', async () => {
    const result = convertIMSIToStix(IMSI_INSTANCE);
    expect(result).toEqual(EXPECTED_IMSI);
  });
  // Locations
  it('should convert Region', async () => {
    const result = convertLocationToStix(REGION_INSTANCE, ENTITY_TYPE_LOCATION_REGION);
    expect(result).toEqual(EXPECTED_REGION);
  });
  it('should convert Country', async () => {
    const result = convertLocationToStix(COUNTRY_INSTANCE, ENTITY_TYPE_LOCATION_COUNTRY);
    expect(result).toEqual(EXPECTED_COUNTRY);
  });
  it('should convert City', async () => {
    const result = convertLocationToStix(CITY_INSTANCE, ENTITY_TYPE_LOCATION_CITY);
    expect(result).toEqual(EXPECTED_CITY);
  });
  it('should convert Position', async () => {
    const result = convertLocationToStix(POSITION_INSTANCE, ENTITY_TYPE_LOCATION_POSITION);
    expect(result).toEqual(EXPECTED_POSITION);
  });
  it('should convert Administrative Area', async () => {
    const result = convertAdministrativeAreaToStix_2_0(ADMINISTRATIVE_AREA_INSTANCE);
    expect(result).toEqual(EXPECTED_ADMINISTRATIVE_AREA);
  });
  // SMOs
  it('should convert Marking Definition', () => {
    const result = convertMarkingDefinitionToStix(MARKING_DEFINITION_INSTANCE);
    expect(result).toEqual(EXPECTED_MARKING_DEFINITION);
  });
  it('should convert Marking Definition (non-TLP, e.g. PAP)', () => {
    const result = convertMarkingDefinitionToStix(PAP_MARKING_DEFINITION_INSTANCE);
    expect(result).toEqual(EXPECTED_PAP_MARKING_DEFINITION);
  });
  it('should convert Label', () => {
    const result = convertLabelToStix(LABEL_INSTANCE);
    expect(result).toEqual(EXPECTED_LABEL);
  });
  it('should convert Kill Chain Phase', () => {
    const result = convertKillChainPhaseToStix(KILL_CHAIN_PHASE_INSTANCE);
    expect(result).toEqual(EXPECTED_KILL_CHAIN_PHASE);
  });
  it('should convert External Reference', () => {
    const result = convertExternalReferenceToStix(EXTERNAL_REFERENCE_INSTANCE);
    expect(result).toEqual(EXPECTED_EXTERNAL_REFERENCE);
  });
});

describe('Stix 2.0 opencti converter - dispatch via convertStoreToStix_2_0', () => {
  // SROs
  it('should dispatch StixCoreRelationship', () => {
    const result = convertStoreToStix_2_0(RELATION_INSTANCE);
    expect(result.type).toBe('relationship');
    expect((result as any).relationship_type).toBe('uses');
    expect((result as any).source_ref).toBe('intrusion-set--738e5ee3-6781-5f4c-93b0-d914bbf0c1d3');
    expect((result as any).target_ref).toBe('tool--6dabb5b8-a30d-5bd3-ab61-5e1f048a3dc3');
  });
  it('should dispatch StixSightingRelationship', () => {
    const result = convertStoreToStix_2_0(SIGHTING_INSTANCE);
    expect(result.type).toBe('sighting');
    expect((result as any).sighting_of_ref).toBe('indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752');
    expect((result as any).where_sighted_refs).toEqual(['identity--4f347cc9-4658-59ee-9707-134f434f9d1c']);
  });
  it('should dispatch InPirRelationship', () => {
    const result = convertStoreToStix_2_0(PIR_RELATION_INSTANCE);
    expect(result.type).toBe('in-pir');
    expect((result as any).relationship_type).toBe('in-pir');
    expect((result as any).source_ref).toBe('malware--b1c2d3e4-f5a6-7890-bcde-f01234567890');
    expect((result as any).target_ref).toBe('identity--c2d3e4f5-a6b7-8901-cdef-123456789012');
  });
  // SDO
  it('should dispatch Malware (SDO)', () => {
    const result = convertStoreToStix_2_0(MALWARE_INSTANCE);
    expect(result.type).toBe('malware');
    expect((result as any).name).toBe('Malware Stix 2.0');
    expect(result.spec_version).toBe('2.0');
  });
  // SCO
  it('should dispatch IPv4 Address (SCO)', () => {
    const result = convertStoreToStix_2_0(IPV4_INSTANCE);
    expect(result.type).toBe('ipv4-addr');
    expect(result.spec_version).toBe('2.0');
  });
  // SMOs
  it('should dispatch Marking Definition (SMO)', () => {
    const result = convertStoreToStix_2_0(MARKING_DEFINITION_INSTANCE);
    expect(result.type).toBe('marking-definition');
    expect((result as any).definition_type).toBe('tlp');
    expect((result as any).name).toBe('TLP:AMBER+STRICT');
    expect(result.spec_version).toBe('2.0');
  });
  it('should dispatch Label (SMO)', () => {
    const result = convertStoreToStix_2_0(LABEL_INSTANCE);
    expect(result.type).toBe('label');
    expect((result as any).value).toBe('small');
    expect(result.spec_version).toBe('2.0');
  });
  it('should dispatch Kill Chain Phase (SMO)', () => {
    const result = convertStoreToStix_2_0(KILL_CHAIN_PHASE_INSTANCE);
    expect(result.type).toBe('kill-chain-phase');
    expect((result as any).kill_chain_name).toBe('mitre-pre-attack');
    expect((result as any).phase_name).toBe('launch');
    expect(result.spec_version).toBe('2.0');
  });
  it('should dispatch External Reference (SMO)', () => {
    const result = convertStoreToStix_2_0(EXTERNAL_REFERENCE_INSTANCE);
    expect(result.type).toBe('external-reference');
    expect((result as any).source_name).toBe('20th January – Threat Intelligence Report');
    expect(result.spec_version).toBe('2.0');
  });
  // Error cases
  it('should throw when standard_id is missing', () => {
    const invalidInstance = { entity_type: 'Malware' } as any;
    expect(() => convertStoreToStix_2_0(invalidInstance)).toThrow();
  });
  it('should throw when entity_type is missing', () => {
    const invalidInstance = { standard_id: 'malware--some-id' } as any;
    expect(() => convertStoreToStix_2_0(invalidInstance)).toThrow();
  });
});
