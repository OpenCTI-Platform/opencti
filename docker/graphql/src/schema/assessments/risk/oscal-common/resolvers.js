
const query = {
  // Map enum GraphQL values to data model required values
  LocationType: {
    data_center: 'data-center',
  },
  LocationClass: {
    primary: 'primary',
    alternate: 'alternate',
  },
  PartyType: {
    person: 'person',
    organization: 'organization',
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
    asset_owner: 'asset-owner',
    asset_administrator: 'asset-administrator',
    configuration_management: 'configuration-management',
    help_desk: 'help-desk',
    incident_response: 'incident-response',
    network_operations: 'network-operations',
    security_operations: 'security-operations',
    maintainer: 'maintainer',
    provider: 'provider',
  }

}