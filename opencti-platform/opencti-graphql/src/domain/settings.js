import { getHeapStatistics } from 'node:v8';
import nconf from 'nconf';
import { createEntity, fullEntitiesOrRelationsList, loadEntity, patchAttribute, updateAttribute } from '../database/middleware';
import conf, { ACCOUNT_STATUSES, booleanConf, BUS_TOPICS, ENABLED_DEMO_MODE, ENABLED_FEATURE_FLAGS, getBaseUrl, PLATFORM_VERSION, PLAYGROUND_ENABLED } from '../config/conf';
import { delEditContext, getRedisVersion, notify, setEditContext } from '../database/redis';
import { isRuntimeSortEnable, searchEngineVersion } from '../database/engine';
import { getRabbitMQVersion } from '../database/rabbitmq';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { isUserHasCapability, SETTINGS_SET_ACCESSES, SETTINGS_SETMANAGEXTMHUB, SETTINGS_SETPARAMETERS, SYSTEM_USER } from '../utils/access';
import { storeLoadById } from '../database/middleware-loader';
import { INTERNAL_SECURITY_PROVIDER, PROVIDERS } from '../config/providers-configuration';
import { publishUserAction } from '../listener/UserActionListener';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { now } from '../utils/format';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { UnsupportedError } from '../config/errors';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { getEnterpriseEditionInfoFromPem } from '../modules/settings/licensing';
import { getClusterInformation } from '../database/cluster-module';
import { completeXTMHubDataForRegistration } from '../utils/settings.helper';
import { XTM_ONE_CHATBOT_URL } from '../http/httpChatbotProxy';
import { findById as findThemeById } from '../modules/theme/theme-domain';

export const getMemoryStatistics = () => {
  return { ...process.memoryUsage(), ...getHeapStatistics() };
};

export const getApplicationInfo = () => ({
  version: PLATFORM_VERSION,
  debugStats: {}, // Lazy loaded
});

export const getApplicationDependencies = (context) => ([
  { name: 'Search engine', version: searchEngineVersion().then((v) => `${v.platform} - ${v.version}`) },
  { name: 'RabbitMQ', version: getRabbitMQVersion(context) },
  { name: 'Redis', version: getRedisVersion() },
]);

const getAIEndpointType = () => {
  if (isEmptyField(nconf.get('ai:endpoint'))) {
    return '';
  }
  if (nconf.get('ai:endpoint').includes('filigran.io')) {
    return 'Filigran';
  }
  return 'Custom';
};

const getProtectedMarkingsIdsByNames = async (context, user, names) => {
  if (!names || names.length === 0) {
    return [];
  }
  const entities = await getEntitiesListFromCache(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  const filteredEntities = entities.filter((entity) => names.includes(entity.definition));
  return filteredEntities.map((entity) => entity.standard_id);
};

const getStandardIdsByNames = (entityType, names) => {
  if (!names || names.length === 0) {
    return [];
  }
  return names.map((name) => generateStandardId(entityType, { name }));
};

export const getProtectedSensitiveConfig = async (context, user) => {
  return {
    enabled: booleanConf('protected_sensitive_config:enabled', false),
    markings: {
      enabled: booleanConf('protected_sensitive_config:markings:enabled', false),
      protected_ids: await getProtectedMarkingsIdsByNames(context, user, nconf.get('protected_sensitive_config:markings:protected_definitions') ?? []),
    },
    groups: {
      enabled: booleanConf('protected_sensitive_config:groups:enabled', false),
      protected_ids: getStandardIdsByNames(ENTITY_TYPE_GROUP, nconf.get('protected_sensitive_config:groups:protected_names') ?? []),
    },
    roles: {
      enabled: booleanConf('protected_sensitive_config:roles:enabled', false),
      protected_ids: getStandardIdsByNames(ENTITY_TYPE_ROLE, nconf.get('protected_sensitive_config:roles:protected_names') ?? []),
    },
    rules: {
      enabled: booleanConf('protected_sensitive_config:rules:enabled', false),
      protected_ids: [],
    },
    ce_ee_toggle: {
      enabled: booleanConf('protected_sensitive_config:ce_ee_toggle:enabled', false),
      protected_ids: [],
    },
    connector_reset: {
      enabled: booleanConf('protected_sensitive_config:connector_reset:enabled', false),
      protected_ids: [],
    },
    file_indexing: {
      enabled: booleanConf('protected_sensitive_config:file_indexing:enabled', false),
      protected_ids: [],
    },
    platform_organization: {
      enabled: booleanConf('protected_sensitive_config:platform_organization:enabled', false),
      protected_ids: [],
    }
  };
};

export const getSettings = async (context) => {
  const platformSettings = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_SETTINGS]);
  const clusterInfo = await getClusterInformation();
  const eeInfo = getEnterpriseEditionInfoFromPem(platformSettings.internal_id, platformSettings.enterprise_license);

  const platformTheme = await findThemeById(context, SYSTEM_USER, platformSettings.platform_theme);

  return {
    ...platformSettings,
    platform_url: getBaseUrl(context.req),
    platform_enterprise_edition: eeInfo,
    valid_enterprise_edition: eeInfo.license_validated,
    platform_providers: PROVIDERS.filter((p) => p.name !== INTERNAL_SECURITY_PROVIDER),
    platform_user_statuses: Object.entries(ACCOUNT_STATUSES).map(([k, v]) => ({ status: k, message: v })),
    platform_cluster: clusterInfo.info,
    platform_demo: ENABLED_DEMO_MODE,
    platform_modules: clusterInfo.modules,
    platform_reference_attachment: conf.get('app:reference_attachment'),
    platform_map_tile_server_dark: nconf.get('app:map_tile_server_dark'),
    platform_map_tile_server_light: nconf.get('app:map_tile_server_light'),
    platform_openaev_url: nconf.get('xtm:openaev_url'),
    platform_opengrc_url: nconf.get('xtm:opengrc_url'),
    platform_xtmhub_url: nconf.get('xtm:xtmhub_url'),
    platform_ai_type: `${getAIEndpointType()} ${nconf.get('ai:type')}`,
    platform_ai_model: nconf.get('ai:model'),
    platform_ai_has_token: !!isNotEmptyField(nconf.get('ai:token')),
    platform_theme: platformTheme,
    platform_trash_enabled: nconf.get('app:trash:enabled') ?? true,
    platform_translations: nconf.get('app:translations') ?? '{}',
    filigran_chatbot_ai_url: XTM_ONE_CHATBOT_URL,
    platform_feature_flags: [
      { id: 'RUNTIME_SORTING', enable: isRuntimeSortEnable() },
      ...(ENABLED_FEATURE_FLAGS.map((feature) => ({ id: feature, enable: true })))
    ],
    playground_enabled: PLAYGROUND_ENABLED,
  };
};

export const getPublicSettings = async (context) => {
  const { platform_enterprise_edition, platform_providers, ...settings } = await getSettings(context);

  return {
    ...settings,
    platform_enterprise_edition_license_validated: platform_enterprise_edition.license_validated,
    platform_providers: platform_providers.filter((p) => p.type === 'SSO' || p.type === 'FORM'),
  };
};

export const addSettings = async (context, user, settings) => {
  const created = await createEntity(context, user, settings, ENTITY_TYPE_SETTINGS);
  return notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user);
};

export const settingsCleanContext = async (context, user, settingsId) => {
  await delEditContext(user, settingsId);
  const settings = await storeLoadById(context, user, settingsId, ENTITY_TYPE_SETTINGS);
  return await notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user);
};

export const settingsEditContext = async (context, user, settingsId, input) => {
  await setEditContext(user, settingsId, input);
  const settings = await storeLoadById(context, user, settingsId, ENTITY_TYPE_SETTINGS);
  return await notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user);
};

const ACCESS_SETTINGS_RESTRICTED_KEYS = [
  'platform_organization',
  'otp_mandatory',
  'password_policy_min_length',
  'password_policy_max_length',
  'password_policy_min_symbols',
  'password_policy_min_numbers',
  'password_policy_min_words',
  'password_policy_min_lowercase',
  'password_policy_min_uppercase',
];

const PARAMETERS_SETTINGS_RESTRICTED_KEYS = [
  'filigran_chatbot_ai_cgu_status',
  'platform_ai_enabled',
];

const ACCESS_SETTINGS_MANAGE_XTMHUB_KEYS = [
  'xtm_hub_token',
  'xtm_hub_registration_user_id',
  'xtm_hub_last_connectivity_check',
  'xtm_hub_registration_date',
  'xtm_hub_registration_user_name',
  'xtm_hub_registration_status',
  'xtm_hub_should_send_connectivity_email',
  'xtm_hub_backend_is_reachable'
];

export const settingsEditField = async (context, user, settingsId, input) => {
  const hasSetAccessCapability = isUserHasCapability(user, SETTINGS_SET_ACCESSES);
  const hasSetParameterCapability = isUserHasCapability(user, SETTINGS_SETPARAMETERS);
  const hasSetXTMHubCapability = isUserHasCapability(user, SETTINGS_SETMANAGEXTMHUB);
  const keysUserCannotModify = [
    ...(hasSetAccessCapability ? [] : ACCESS_SETTINGS_RESTRICTED_KEYS),
    ...(hasSetParameterCapability ? [] : PARAMETERS_SETTINGS_RESTRICTED_KEYS),
    ...(hasSetXTMHubCapability ? [] : ACCESS_SETTINGS_MANAGE_XTMHUB_KEYS),
  ];

  const dataWithRestrictKeys = keysUserCannotModify.length === 0
    ? input
    : input.filter((i) => !keysUserCannotModify.includes(i.key));

  const data = hasSetXTMHubCapability ? completeXTMHubDataForRegistration(user, dataWithRestrictKeys) : dataWithRestrictKeys;

  const settings = await getSettings(context);
  const enterpriseLicense = data.find((inputData) => inputData.key === 'enterprise_license');
  if (enterpriseLicense && enterpriseLicense.value?.length > 0) {
    const license = enterpriseLicense.value[0];
    if (isNotEmptyField(license)) {
      const info = getEnterpriseEditionInfoFromPem(settings.internal_id, license);
      if (!info.license_validated) {
        throw UnsupportedError('Invalid license');
      }
    }
  }
  await updateAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, data);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${data.map((i) => i.key).join(', ')}\` for \`platform settings\``,
    context_data: { id: settingsId, entity_type: ENTITY_TYPE_SETTINGS, input: data }
  });
  const updatedSettings = await getSettings(context);
  return notify(BUS_TOPICS.Settings.EDIT_TOPIC, updatedSettings, user);
};

export const getMessagesFilteredByRecipients = (user, settings) => {
  const messages = JSON.parse(settings.platform_messages ?? '[]');
  return messages.filter(({ recipients }) => {
    // eslint-disable-next-line max-len
    return isEmptyField(recipients) || recipients.some((recipientId) => [user.id, ...user.groups.map(({ id }) => id), ...user.organizations.map(({ id }) => id)].includes(recipientId));
  });
};

export const settingEditMessage = async (context, user, settingsId, message) => {
  const messageToStore = {
    ...message,
    updated_at: now()
  };
  const settings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
  const messages = JSON.parse(settings.platform_messages ?? '[]');
  const existingIdx = messages.findIndex((m) => m.id === message.id);
  if (existingIdx > -1) {
    messages[existingIdx] = messageToStore;
  } else {
    messages.push({
      ...messageToStore,
      id: generateInternalId()
    });
  }
  const patch = { platform_messages: JSON.stringify(messages) };
  const { element } = await patchAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, patch);
  return notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
};

export const settingDeleteMessage = async (context, user, settingsId, messageId) => {
  const settings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
  const messages = JSON.parse(settings.platform_messages ?? '[]');
  const existingIdx = messages.findIndex((m) => m.id === messageId);
  if (existingIdx > -1) {
    messages.splice(existingIdx, 1);
  } else {
    throw UnsupportedError('This message does not exist', { messageId });
  }
  const patch = { platform_messages: JSON.stringify(messages) };
  const { element } = await patchAttribute(context, user, settingsId, ENTITY_TYPE_SETTINGS, patch);
  return notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
};

export const getCriticalAlerts = async (context, user) => {
  // only 1 critical alert is checked: null confidence level on groups
  // it's for admins only (only them can take action)
  if (isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    const allGroups = await fullEntitiesOrRelationsList(context, user, [ENTITY_TYPE_GROUP], {});
    // if at least one have a null effective confidence level, it's an issue
    const groupsWithNull = allGroups.filter((group) => !group.group_confidence_level);
    if (groupsWithNull.length === 0) {
      return [];
    }
    return [{
      type: 'GROUP_WITH_NULL_CONFIDENCE_LEVEL',
      // default message for API users
      message: 'Some groups have field group_confidence_level to null, members will not be able to use the platform properly.',
      details: {
        groups: groupsWithNull,
      }
    }];
  }

  // no alert
  return [];
};
