import { v4 as uuid4 } from 'uuid';
import { CyioError } from '../../../utils.js';
// import { objectMap } from '../../../global/global-utils.js';

const oscalCommonResolvers = {
  Query: {},
  Mutation: {
    exportOscal: async (_, { model, id, media_type }, { clientId, kauth, token, dataSources }) => {
      switch (model) {
        case 'poam':
          if (id === undefined || id === null || id === '') id = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
          break;
        case 'ap':
        case 'ar':
        case 'ssp':
        default:
          throw new CyioError(`Unsupported OSCAL model type '${model}'`);
      }

      // Generate a unique identifier to associated with the tasking
      const taskId = uuid4();
      let bearer_token = '';
      bearer_token = token;
      if (kauth && kauth.accessToken && kauth.accessToken.token) {
        console.log(`kauth has accessToken: ${kauth.accessToken.token}`);
        // bearer_token = kauth.accessToken.token;
      }

      // build the tasking request payload
      const payload = {
        '@type': 'task',
        'task-uid': `${taskId}`,
        type: 'export',
        token: `${bearer_token}`,
        'cyio-client': `${clientId}`,
        options: {
          export: {
            'media-format': `${media_type}`,
            'oscal-model': `${model}`,
            'object-id': `${id}`,
          },
        },
      };

      let response;
      response = await dataSources.Artemis.publish(taskId, 'queues/cyio.tasks.export', payload);

      // return the tasking id for tracking purposes
      return response;
    },
    generateRiskReport: async (_, { report, id, media_type, options }, { clientId, kauth, token, dataSources }) => {
      let exportMediaType;
      let model;
      let description = null;
      let purpose = null;
      let maxItems = 'all';
      const sectionList = [];
      const appendixList = [];
      switch (report) {
        case 'sar':
          if (id === undefined || id === null || id === '') id = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
          exportMediaType = 'application/oscal+json';
          model = 'poam';
          break;
        case 'var':
        case 'air':
        case 'cra':
        case 'tar':
        default:
          throw new CyioError(`Unsupported OSCAL report type '${report}'`);
      }

      // Generate a unique identifier to associated with the tasking
      const taskId = uuid4();
      let bearer_token = '';
      bearer_token = token;
      if (kauth && kauth.accessToken && kauth.accessToken.token) {
        console.log(`kauth has accessToken: ${kauth.accessToken.token}`);
        // bearer_token = kauth.accessToken.token;
      }

      for (const option of options) {
        switch (option.name) {
          case 'description':
            description = `${option.values[0]}`;
            break;
          case 'purpose':
            purpose = `${option.values[0]}`;
            break;
          case 'max_items':
            maxItems = `${option.values[0]}`;
            break;
          case 'appendices':
            for (const appendix of option.values) appendixList.push(`${appendix}`);
            break;
          case 'sections':
            for (const section of option.values) sectionList.push(`${section}`);
            break;
        }
      }

      // build the tasking request payload
      const payload = {
        '@type': 'task',
        'task-uid': `${taskId}`,
        type: 'report',
        token: `${bearer_token}`,
        'cyio-client': `${clientId}`,
        options: {
          export: {
            'media-format': `${exportMediaType}`,
            'oscal-model': `${model}`,
            'object-id': `${id}`,
          },
          report: {
            'report-type': `${report}`,
            'media-format': `${media_type}`,
            'max-items': `${maxItems}`,
            description: `${description}`,
            purpose: `${purpose}`,
            appendices: appendixList,
            sections: sectionList,
          },
        },
      };

      let response;
      response = await dataSources.Artemis.publish(taskId, 'queues/cyio.tasks.report', payload);

      // return the tasking id for tracking purposes
      return response;
    },
  },
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
