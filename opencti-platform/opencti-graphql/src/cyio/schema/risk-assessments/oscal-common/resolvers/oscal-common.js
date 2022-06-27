import { objectMap } from '../../../global/global-utils.js';

const oscalCommonResolvers = {
  // Map enum GraphQL values to data model required values
  OscalLocationType: {
    data_center: 'data-center',
  },
  OscalLocationClass: {
    primary: 'primary',
    alternate: 'alternate',
  },
  PartyType: {
    person: 'person',
    organization: 'organization',
  },
  PrivilegeLevel: {
    privileged: 'privileged',
    non_privileged: 'non-privileged',
    no_logical_access: 'no-logical-asses',
  },
  ResourceType: {
    logo: 'logo',
    image: 'image',
    screen_shot: 'screen-shot',
    law: 'law',
    regulation: 'regulation',
    standard: 'standard',
    external_guidance: 'external-guidance',
    acronyms: 'acronyms',
    citation: 'citation',
    policy: 'policy',
    procedure: 'procedure',
    system_guide: 'system-guide',
    users_guide: 'users-guide',
    administrators_guide: 'administrators-guide',
    rules_of_behavior: 'rules-of-behavior',
    plan: 'plan',
    artifact: 'artifact',
    evidence: 'evidence',
    tool_output: 'tool-output',
    raw_data: 'raw-data',
    interview_notes: 'interview-notes',
    questionnaire: 'questionnaire',
    report: 'report',
    agreement: 'agreement',
  },
  RoleType: {
    asset_administrator: 'asset-administrator',
    asset_owner: 'asset-owner',
    authorizing_official_poc: 'authorizing-official-poc',
    authorizing_official: 'authorizing-official',
    configuration_management: 'configuration-management',
    contact: 'contact',
    content_approver: 'content-approver',
    creator: 'creator',
    help_desk: 'help-desk',
    incident_response: 'incident-response',
    information_system_security_officer: 'information-system-security-officer',
    isa_authorizing_official_local: 'isa-authorizing-official-local',
    isa_authorizing_official_remote: 'isa-authorizing-official-remote',
    isa_poc_local: 'isa-poc-local',
    isa_poc_remote: 'isa-poc-remote',
    maintainer: 'maintainer',
    network_operations: 'network-operations',
    prepared_by: 'prepared-by',
    prepared_for: 'prepared-for',
    privacy_poc: 'privacy-poc',
    provider: 'provider',
    security_operations: 'security-operations',
    system_owner: 'system-owner',
    system_poc_management: 'system-poc-management',
    system_poc_other: 'system-poc-other',
    system_poc_technical: 'system-poc-technical',
  },
  UserType: {
    internal: 'internal',
    external: 'external',
    general_public: 'general-public',
  },
  OscalMediaType: {
    application_oscal_json: 'application/oscal+json',
    // application_oscal_xml: 'application/oscal+xml',
    // application_oscal_yaml: 'application/oscal+yaml',
    // application_oscal_csv: 'application/oscal+csv',
  },
  ReportMediaType: {
    markdown: 'text/markdown',
    // html: 'text/html',
    // pdf: 'application/pdf',
  },
  // PartyOrComponent: {
  //   __resolveType: (item) => {
  //     return objectMap[item.entity_type].graphQLType;
  //   }
  // }
};

export default oscalCommonResolvers;