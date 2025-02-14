import { isFeatureEnabled, logApp } from '../config/conf';
import { addSettings } from '../domain/settings';
import { BYPASS, ROLE_ADMINISTRATOR, ROLE_DEFAULT, SYSTEM_USER } from '../utils/access';
import { findByType as findEntitySettingsByType, initCreateEntitySettings } from '../modules/entitySetting/entitySetting-domain';
import { initDecayRules } from '../modules/decayRule/decayRule-domain';
import { initManagerConfigurations } from '../modules/managerConfiguration/managerConfiguration-domain';
import { createStatus, createStatusTemplate } from '../domain/status';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { StatusScope, VocabularyCategory } from '../generated/graphql';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { addAllowedMarkingDefinition } from '../domain/markingDefinition';
import { addCapability, addGroup, addRole } from '../domain/grant';
import { GROUP_DEFAULT, groupAddRelation } from '../domain/group';
import { TAXIIAPI } from '../domain/user';
import { KNOWLEDGE_COLLABORATION, KNOWLEDGE_DELETE, KNOWLEDGE_FRONTEND_EXPORT, KNOWLEDGE_MANAGE_AUTH_MEMBERS, KNOWLEDGE_UPDATE } from '../schema/general';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { updateAttribute } from './middleware';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';

// region Platform capabilities definition
const KNOWLEDGE_CAPABILITY = 'KNOWLEDGE';
const BYPASS_CAPABILITIES = { name: BYPASS, description: 'Bypass all capabilities', attribute_order: 1 };
export const TAXII_CAPABILITIES = {
  name: TAXIIAPI,
  attribute_order: 2500,
  description: 'Access data sharing',
  dependencies: [
    { name: 'SETCOLLECTIONS', description: 'Manage data sharing', attribute_order: 2510 },
  ],
};
const KNOWLEDGE_CAPABILITIES = {
  name: KNOWLEDGE_CAPABILITY,
  description: 'Access knowledge',
  attribute_order: 100,
  dependencies: [
    { name: KNOWLEDGE_COLLABORATION, description: 'Access to collaborative creation', attribute_order: 150 },
    { name: KNOWLEDGE_FRONTEND_EXPORT, description: 'Can use web interface export functions (PDF, PNG, etc.)', attribute_order: 160 },
    {
      name: KNOWLEDGE_UPDATE,
      description: 'Create / Update knowledge',
      attribute_order: 200,
      dependencies: [
        { name: 'KNORGARESTRICT', attribute_order: 290, description: 'Restrict organization access' },
        { name: KNOWLEDGE_DELETE, description: 'Delete knowledge', attribute_order: 300 },
        { name: KNOWLEDGE_MANAGE_AUTH_MEMBERS, description: 'Manage authorized members', attribute_order: 310 },
        { name: 'KNBYPASSREFERENCE', description: 'Bypass enforced reference', attribute_order: 320 },
        { name: 'KNBYPASSFIELDS', description: 'Bypass mandatory fields', attribute_order: 330 },
      ],
    },
    { name: 'KNUPLOAD', description: 'Upload knowledge files', attribute_order: 400 },
    { name: 'KNASKIMPORT', description: 'Import knowledge', attribute_order: 500 },
    {
      name: 'KNGETEXPORT',
      description: 'Download knowledge export',
      attribute_order: 700,
      dependencies: [{ name: 'KNASKEXPORT', description: 'Generate knowledge export', attribute_order: 710 }],
    },
    { name: 'KNENRICHMENT', description: 'Ask for knowledge enrichment', attribute_order: 800 },
    { name: 'KNDISSEMINATION', description: 'Disseminate files by email', attribute_order: 900 },
  ],
};
export const SETTINGS_CAPABILITIES = {
  name: 'SETTINGS',
  description: 'Access to admin functionalities',
  attribute_order: 3000,
  dependencies: [
    { name: 'SETPARAMETERS', description: 'Manage parameters', attribute_order: 3100 },
    { name: 'SETACCESSES', description: 'Manage credentials', attribute_order: 3200 },
    { name: 'SETMARKINGS', description: 'Manage marking definitions', attribute_order: 3300 },
    { name: 'SETDISSEMINATION', description: 'Manage dissemination lists', attribute_order: 3320 },
    { name: 'SETCUSTOMIZATION', description: 'Manage customization', attribute_order: 3350 },
    { name: 'SETLABELS', description: 'Manage taxonomies', attribute_order: 3400 },
    { name: 'SECURITYACTIVITY', description: 'Access security activity', attribute_order: 3500 },
    { name: 'FILEINDEXING', description: 'Access to file indexing', attribute_order: 3600 },
    { name: 'SUPPORT', description: 'Access to support data', attribute_order: 3700 },
  ],
};
export const CAPABILITIES = [
  BYPASS_CAPABILITIES,
  KNOWLEDGE_CAPABILITIES,
  {
    name: 'EXPLORE',
    description: 'Access dashboards',
    attribute_order: 1000,
    dependencies: [
      {
        name: 'EXUPDATE',
        description: 'Create / Update dashboards',
        attribute_order: 1100,
        dependencies: [
          { name: 'EXDELETE', description: 'Delete dashboards', attribute_order: 1200 },
          { name: 'PUBLISH', description: 'Manage public dashboards', attribute_order: 1300 },
        ],
      },
    ],
  },
  {
    name: 'INVESTIGATION',
    description: 'Access investigations',
    attribute_order: 1400,
    dependencies: [
      {
        name: 'INUPDATE',
        description: 'Create / Update investigations',
        attribute_order: 1410,
        dependencies: [
          { name: 'INDELETE', description: 'Delete investigations', attribute_order: 1420 },
        ],
      },
    ],
  },
  {
    name: 'MODULES',
    description: 'Access connectors',
    attribute_order: 2000,
    dependencies: [{ name: 'MODMANAGE', description: 'Manage connector state', attribute_order: 2100 }],
  },
  TAXII_CAPABILITIES,
  SETTINGS_CAPABILITIES,
  {
    name: 'CONNECTORAPI',
    attribute_order: 2300,
    description: 'Connectors API usage: register, ping, export push ...',
  },
  {
    name: 'INGESTION',
    attribute_order: 2600,
    description: 'Access ingestion',
    dependencies: [
      { name: 'SETINGESTIONS', description: 'Manage ingestion', attribute_order: 2610 },
    ]
  },
  {
    name: 'CSVMAPPERS',
    description: 'Manage CSV mappers',
    attribute_order: 2700
  }
];
// endregion

const createMarkingDefinitions = async (context) => {
  // Create marking defs for TLP
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:CLEAR',
    x_opencti_color: '#ffffff',
    x_opencti_order: 1,
  });
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:GREEN',
    x_opencti_color: '#2e7d32',
    x_opencti_order: 2,
  });
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:AMBER+STRICT',
    x_opencti_color: '#d84315',
    x_opencti_order: 4,
  });
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:RED',
    x_opencti_color: '#c62828',
    x_opencti_order: 5,
  });

  // Creation markings for PAP
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'PAP',
    definition: 'PAP:CLEAR',
    x_opencti_color: '#ffffff',
    x_opencti_order: 1,
  });
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'PAP',
    definition: 'PAP:GREEN',
    x_opencti_color: '#2e7d32',
    x_opencti_order: 2,
  });
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'PAP',
    definition: 'PAP:AMBER',
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  await addAllowedMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'PAP',
    definition: 'PAP:RED',
    x_opencti_color: '#c62828',
    x_opencti_order: 4,
  });
};

const createVocabularies = async (context) => {
  const categories = Object.values(VocabularyCategory);
  for (let index = 0; index < categories.length; index += 1) {
    const category = categories[index];
    const vocabularies = openVocabularies[category] ?? [];
    for (let i = 0; i < vocabularies.length; i += 1) {
      const { key, description, aliases, order } = vocabularies[i];
      const data = {
        name: key,
        description: description ?? '',
        aliases: aliases ?? [],
        category,
        order,
        builtIn: builtInOv.includes(category)
      };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }
};

const createDefaultStatusTemplates = async (context) => {
  const statusNew = await createStatusTemplate(context, SYSTEM_USER, { name: 'NEW', color: '#ff9800' });
  const statusProgress = await createStatusTemplate(context, SYSTEM_USER, { name: 'IN_PROGRESS', color: '#5c7bf5' });
  await createStatusTemplate(context, SYSTEM_USER, { name: 'PENDING', color: '#5c7bf5' });
  await createStatusTemplate(context, SYSTEM_USER, { name: 'TO_BE_QUALIFIED', color: '#5c7bf5' });
  const statusAnalyzed = await createStatusTemplate(context, SYSTEM_USER, { name: 'ANALYZED', color: '#4caf50' });
  const statusClosed = await createStatusTemplate(context, SYSTEM_USER, { name: 'CLOSED', color: '#607d8b' });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusNew.id, order: 1, scope: StatusScope.Global });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusProgress.id, order: 2, scope: StatusScope.Global });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusAnalyzed.id, order: 3, scope: StatusScope.Global });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusClosed.id, order: 4, scope: StatusScope.Global });

  if (isFeatureEnabled('ORGA_SHARING_REQUEST_FF')) {
    await createStatus(
      context,
      SYSTEM_USER,
      ENTITY_TYPE_CONTAINER_CASE_RFI,
      { template_id: statusNew.id, order: 0, scope: StatusScope.RequestAccess }
    );
  }
};

export const createInitialRequestAccessFlow = async (context) => {
  const statusTemplateDeclined = await createStatusTemplate(context, SYSTEM_USER, { name: 'DECLINED', color: '#b83f13' });
  const statusTemplateApproved = await createStatusTemplate(context, SYSTEM_USER, { name: 'APPROVED', color: '#4caf50' });

  // TODO exclude scope request-access from search first status and order can be 0.
  const statusEntityRFIDeclined = await createStatus(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_CASE_RFI,
    { template_id: statusTemplateDeclined.id, order: 1, scope: StatusScope.RequestAccess }
  );
  const statusEntityRFIApproved = await createStatus(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_CASE_RFI,
    { template_id: statusTemplateApproved.id, order: 1, scope: StatusScope.RequestAccess }
  );

  const initialConfig = {
    approved_workflow_id: statusEntityRFIApproved.id,
    declined_workflow_id: statusEntityRFIDeclined.id,
  };

  const rfiEntitySettings = await findEntitySettingsByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
  if (rfiEntitySettings) {
    const editInput = [
      { key: 'request_access_workflow', value: [initialConfig] }
    ];
    // TODO use updateAttribute instead
    // await updateAttribute(context, user, rfiEntitySettings.id, ENTITY_TYPE_ENTITY_SETTING, {request_access_workflow});
    await updateAttribute(context, SYSTEM_USER, rfiEntitySettings.id, ENTITY_TYPE_ENTITY_SETTING, editInput);
    // await entitySettingEditField(context, SYSTEM_USER, rfiEntitySettings.id, editInput);
  }
};

export const createCapabilities = async (context, capabilities, parentName = '') => {
  for (let i = 0; i < capabilities.length; i += 1) {
    const capability = capabilities[i];
    const { name, description, attribute_order: AttributeOrder } = capability;
    const capabilityName = `${parentName}${name}`;
    await addCapability(context, SYSTEM_USER, { name: capabilityName, description, attribute_order: AttributeOrder });
    if (capability.dependencies && capability.dependencies.length > 0) {
      await createCapabilities(context, capability.dependencies, `${capabilityName}_`);
    }
  }
};

const createBasicRolesAndCapabilities = async (context) => {
  // Create capabilities
  await createCapabilities(context, CAPABILITIES);

  // Create Default(s) Role and Group
  const defaultRoleInput = await addRole(context, SYSTEM_USER, {
    name: ROLE_DEFAULT,
    description: 'Default role associated to the default group',
    capabilities: [KNOWLEDGE_CAPABILITY],
    can_manage_sensitive_config: false,
  });

  const defaultGroup = await addGroup(context, SYSTEM_USER, {
    name: GROUP_DEFAULT,
    description: 'Default group associated to all users',
    default_assignation: true,
  });
  const defaultRoleRelationInput = {
    toId: defaultRoleInput.id,
    relationship_type: 'has-role',
  };
  await groupAddRelation(context, SYSTEM_USER, defaultGroup.id, defaultRoleRelationInput);

  // Create Administrator(s) Role and Group
  const administratorRoleInput = {
    name: ROLE_ADMINISTRATOR,
    description: 'Administrator role that bypass every capabilities',
    capabilities: [BYPASS],
    can_manage_sensitive_config: false,
  };

  const administratorRole = await addRole(context, SYSTEM_USER, administratorRoleInput);

  const administratorGroup = await addGroup(context, SYSTEM_USER, {
    name: 'Administrators',
    description: 'Administrator group',
    auto_new_marking: true,
  });
  const administratorRoleRelationInput = {
    toId: administratorRole.id,
    relationship_type: 'has-role',
  };
  await groupAddRelation(context, SYSTEM_USER, administratorGroup.id, administratorRoleRelationInput);

  // Create Connector(s) Role and Group
  const connectorRoleInput = {
    name: 'Connector',
    description: 'Connector role that has the recommended capabilities',
    capabilities: [
      'KNOWLEDGE_KNUPDATE_KNDELETE',
      'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS',
      'KNOWLEDGE_KNUPLOAD',
      'KNOWLEDGE_KNASKIMPORT',
      'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT',
      'KNOWLEDGE_KNENRICHMENT',
      'CONNECTORAPI',
      'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE',
      'MODULES_MODMANAGE',
      'TAXIIAPI',
      'INGESTION',
      'SETTINGS_SETMARKINGS',
      'SETTINGS_SETLABELS',
    ],
    can_manage_sensitive_config: false
  };

  const connectorRole = await addRole(context, SYSTEM_USER, connectorRoleInput);
  // Create default group with default role

  // Create connector group with connector role
  const connectorGroup = await addGroup(context, SYSTEM_USER, {
    name: 'Connectors',
    description: 'Connector group',
    auto_new_marking: true,
  });
  const connectorRoleRelationInput = {
    toId: connectorRole.id,
    relationship_type: 'has-role',
  };
  await groupAddRelation(context, SYSTEM_USER, connectorGroup.id, connectorRoleRelationInput);
};

export const initializeData = async (context, withMarkings = true) => {
  logApp.info('[INIT] Initialization of settings and basic elements');
  // Create default elements
  await addSettings(context, SYSTEM_USER, {
    platform_title: 'OpenCTI - Cyber Threat Intelligence Platform',
    platform_email: 'admin@opencti.io',
    platform_theme: 'Dark',
    platform_language: 'auto',
  });
  await initCreateEntitySettings(context, SYSTEM_USER);
  await initManagerConfigurations(context, SYSTEM_USER);
  await initDecayRules(context, SYSTEM_USER);
  await createDefaultStatusTemplates(context);
  if (isFeatureEnabled('ORGA_SHARING_REQUEST_FF')) {
    await createInitialRequestAccessFlow(context);
  }
  await createBasicRolesAndCapabilities(context);
  await createVocabularies(context);
  if (withMarkings) {
    await createMarkingDefinitions(context);
  }
  logApp.info('[INIT] Platform default initialized');
  return true;
};
