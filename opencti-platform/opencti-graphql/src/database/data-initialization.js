import validator from 'validator';
import { addSettings } from '../domain/settings';
import { BYPASS, KNOWLEDGE, ROLE_ADMINISTRATOR, ROLE_DEFAULT, SYSTEM_USER } from '../utils/access';
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
import { CAPABILITIES } from '../schema/capabilities';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { loadEntity, updateAttribute } from './middleware';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import conf, { CONFIG_PRESET_FEATURE_FLAG, isFeatureEnabled, LOCAL_AUTH_LOCKOUT_FEATURE_FLAG, logApp } from '../config/conf';
import { isNotEmptyField } from './utils';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { elRawDelete, elRawGet, elRawIndex } from './engine';
import { ConfigurationError } from '../config/errors';
import { initDefaultTheme } from '../modules/theme/theme-domain';
import { addEmailTemplate } from '../modules/emailTemplate/emailTemplate-domain';
import { DEFAULT_EMAIL_TEMPLATE_INPUT } from './default-email-template-input';
import { createRetentionRule } from '../modules/retentionRules/retentionRules-domain';

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
        builtIn: builtInOv.includes(category),
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
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI, { template_id: statusNew.id, order: 0, scope: StatusScope.RequestAccess });
};

export const createInitialRequestAccessFlow = async (context) => {
  const statusTemplateDeclined = await createStatusTemplate(context, SYSTEM_USER, { name: 'DECLINED', color: '#b83f13' });
  const statusTemplateApproved = await createStatusTemplate(context, SYSTEM_USER, { name: 'APPROVED', color: '#4caf50' });

  const statusEntityRFIDeclined = await createStatus(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_CASE_RFI,
    { template_id: statusTemplateDeclined.id, order: 1, scope: StatusScope.RequestAccess },
  );
  const statusEntityRFIApproved = await createStatus(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_CASE_RFI,
    { template_id: statusTemplateApproved.id, order: 1, scope: StatusScope.RequestAccess },
  );

  const initialConfig = {
    approved_workflow_id: statusEntityRFIApproved.id,
    declined_workflow_id: statusEntityRFIDeclined.id,
  };

  const rfiEntitySettings = await findEntitySettingsByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
  if (rfiEntitySettings) {
    const editInput = [
      { key: 'request_access_workflow', value: [initialConfig] },
    ];
    await updateAttribute(context, SYSTEM_USER, rfiEntitySettings.id, ENTITY_TYPE_ENTITY_SETTING, editInput);
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

export const createDefaultRetentionRules = async (context) => {
  // Create default disabled retention rule for global files (30 days, inactive)
  await createRetentionRule(context, SYSTEM_USER, {
    name: 'Global files retention',
    max_retention: 30,
    retention_unit: 'days',
    scope: 'file',
    active: false,
  });
  // Create default disabled retention rule for all workbenches (30 days, inactive)
  await createRetentionRule(context, SYSTEM_USER, {
    name: 'All workbenches retention',
    max_retention: 30,
    retention_unit: 'days',
    scope: 'workbench',
    active: false,
  });
  // Create default disabled retention rule for history (30 days, inactive)
  await createRetentionRule(context, SYSTEM_USER, {
    name: 'History retention',
    max_retention: 30,
    retention_unit: 'days',
    scope: 'history',
    active: false,
  });
  // Create default disabled retention rule for activity (30 days, inactive)
  await createRetentionRule(context, SYSTEM_USER, {
    name: 'Activity retention',
    max_retention: 30,
    retention_unit: 'days',
    scope: 'activity',
    active: false,
  });
};

const createBasicRolesAndCapabilities = async (context) => {
  // Create capabilities
  await createCapabilities(context, CAPABILITIES);

  // Create Default(s) Role and Group
  const defaultRoleInput = await addRole(context, SYSTEM_USER, {
    name: ROLE_DEFAULT,
    description: 'Default role associated to the default group',
    capabilities: [
      KNOWLEDGE,
    ],
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
      'APIACCESS_USETOKEN',
      'KNOWLEDGE_KNUPDATE_KNDELETE',
      'KNOWLEDGE_KNUPDATE_KNMERGE',
      'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS',
      'KNOWLEDGE_KNUPLOAD',
      'KNOWLEDGE_KNASKIMPORT',
      'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT',
      'KNOWLEDGE_KNENRICHMENT',
      'CONNECTORAPI',
      'APIACCESS_USETOKEN',
      'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE',
      'MODULES_MODMANAGE',
      'TAXIIAPI',
      'SETTINGS_SETMARKINGS',
      'SETTINGS_SETLABELS',
      'SETTINGS_SETVOCABULARIES',
      'SETTINGS_SETKILLCHAINPHASES',
      // Granted to every role with Create / Update knowledge by the migration that added it: same on a fresh install
      'KNOWLEDGE_KNFORMINTAKE',
    ],
    can_manage_sensitive_config: false,
  };

  const connectorRole = await addRole(context, SYSTEM_USER, connectorRoleInput);
  // Create default group with default role

  // Create connector group with connector role
  const connectorGroup = await addGroup(context, SYSTEM_USER, {
    name: 'Connectors',
    description: 'Connector group',
    auto_new_marking: true,
    auto_integration_assignation: ['global'],
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
  const platformId = conf.get('platform_id') || undefined;
  if (isNotEmptyField(platformId)) {
    logApp.warn(`[INIT] Platform identifier forced to [${platformId}]`);
  }
  const darkTheme = await initDefaultTheme(context);
  await addSettings(context, SYSTEM_USER, {
    internal_id: platformId,
    platform_title: 'OpenCTI - Cyber Threat Intelligence Platform',
    platform_email: 'admin@opencti.io',
    platform_theme: darkTheme.id,
    platform_language: 'auto',
    // Only a new platform goes through here: the wizard opens at the first login
    ...(isFeatureEnabled(CONFIG_PRESET_FEATURE_FLAG) ? { platform_bootstrap_status: 'pending' } : {}),
    view_all_users: false,
    local_auth: { enabled: true },
    // A new platform starts with the local authentication lockout enabled (NIST SP 800-53 AC-7),
    // existing platforms keep it disabled at upgrade
    ...(isFeatureEnabled(LOCAL_AUTH_LOCKOUT_FEATURE_FLAG) ? { local_auth_lockout_enabled: true } : {}),
    cert_auth: {
      enabled: false,
      description: null,
      user_info_mapping: {
        email_expr: 'subject.emailAddress',
        name_expr: 'subject.CN',
        firstname_expr: null,
        lastname_expr: null,
      },
      groups_mapping: {
        default_groups: [],
        groups_expr: ['subject.OU'],
        groups_mapping: [],
        auto_create_groups: false,
        prevent_default_groups: false,
        extend_platform_groups: false,
      },
      organizations_mapping: {
        default_organizations: [],
        organizations_expr: ['subject.O'],
        organizations_mapping: [],
        auto_create_organizations: false,
      },
    },
    headers_auth: {
      enabled: false,
      description: null,
      button_label_override: null,
      logout_uri: null,
      headers_audit: [],
      user_info_mapping: {
        email_expr: 'x-email',
        name_expr: 'x-name',
        firstname_expr: null,
        lastname_expr: null,
      },
      groups_mapping: {
        default_groups: [],
        groups_expr: [],
        group_splitter: null,
        groups_mapping: [],
        auto_create_groups: false,
        prevent_default_groups: false,
        extend_platform_groups: false,
      },
      organizations_mapping: {
        default_organizations: [],
        organizations_expr: [],
        organizations_splitter: null,
        organizations_mapping: [],
        auto_create_organizations: false,
      },
    },
  });
  await initCreateEntitySettings(context, SYSTEM_USER);
  await initManagerConfigurations(context, SYSTEM_USER);
  await initDecayRules(context, SYSTEM_USER);
  await createDefaultStatusTemplates(context);
  await createInitialRequestAccessFlow(context);
  await createBasicRolesAndCapabilities(context);
  await createVocabularies(context);
  await addEmailTemplate(context, SYSTEM_USER, DEFAULT_EMAIL_TEMPLATE_INPUT, false);
  await createDefaultRetentionRules(context);
  if (withMarkings) {
    await createMarkingDefinitions(context);
  }
  logApp.info('[INIT] Platform default initialized');
  return true;
};

export const setPlatformId = async (context, platformId) => {
  if (isNotEmptyField((platformId))) {
    if (!validator.isUUID(platformId)) {
      throw ConfigurationError('Cannot switch platform identifier: platform_id is not a valid UUID', { platform_id: platformId });
    }

    const platformSettings = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS]);
    if (platformSettings.id !== platformId) {
      logApp.warn(`[INIT] Switching platform identifier from [${platformSettings.id}] to [${platformId}]`);
      // to change the id in elastic, we have no choice but to create a patched copy and delete the old document
      // Use the concrete index name from the loaded entity (_index) instead of the alias (INDEX_INTERNAL_OBJECTS).
      const settingCurrentIndex = platformSettings._index;
      const response = await elRawGet({
        index: settingCurrentIndex,
        id: platformSettings.id,
      });
      await elRawIndex({
        index: settingCurrentIndex,
        id: platformId,
        body: {
          ...response._source,
          internal_id: platformId,
          id: platformId,
        },
        refresh: true,
      });
      await elRawDelete({
        index: settingCurrentIndex,
        id: platformSettings.id,
        refresh: true,
      });
    }
  }
};

export const patchPlatformId = async (context) => {
  const platformId = conf.get('platform_id') || undefined;
  await setPlatformId(context, platformId);
};
