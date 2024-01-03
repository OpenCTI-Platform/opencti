// Admin user initialization
import { v4 as uuidv4 } from 'uuid';
import semver from 'semver';
import { logApp, PLATFORM_VERSION } from './config/conf';
import { elCreateIndices, elIndexExists, elUpdateIndicesMappings, searchEngineInit } from './database/engine';
import { initializeAdminUser } from './config/providers';
import { initializeBucket, isStorageAlive } from './database/file-storage';
import { rabbitMQIsAlive, registerConnectorQueues } from './database/rabbitmq';
import { addMarkingDefinition } from './domain/markingDefinition';
import { addSettings } from './domain/settings';
import { TAXIIAPI } from './domain/user';
import { addCapability, addGroup, addRole } from './domain/grant';
import { initDefaultNotifiers } from './modules/notifier/notifier-domain';
import { checkPythonAvailability } from './python/pythonBridge';
import { lockResource, redisIsAlive } from './database/redis';
import { ENTITY_TYPE_MIGRATION_STATUS } from './schema/internalObject';
import { applyMigration, lastAvailableMigrationTime } from './database/migration';
import { createEntity, loadEntity } from './database/middleware';
import { INDEX_INTERNAL_OBJECTS, INTERNAL_PLAYBOOK_QUEUE, INTERNAL_SYNC_QUEUE } from './database/utils';
import { ConfigurationError, LockTimeoutError, TYPE_LOCK_ERROR, UnsupportedError } from './config/errors';
import { BYPASS, BYPASS_REFERENCE, executionContext, ROLE_ADMINISTRATOR, ROLE_DEFAULT, SYSTEM_USER } from './utils/access';
import { smtpIsAlive } from './database/smtp';
import { createStatus, createStatusTemplate } from './domain/status';
import { ENTITY_TYPE_CONTAINER_REPORT } from './schema/stixDomainObject';
import { KNOWLEDGE_COLLABORATION, KNOWLEDGE_DELETE, KNOWLEDGE_MANAGE_AUTH_MEMBERS, KNOWLEDGE_ORGANIZATION_RESTRICT, KNOWLEDGE_UPDATE } from './schema/general';
import { VocabularyCategory } from './generated/graphql';
import { addVocabulary } from './modules/vocabulary/vocabulary-domain';
import { builtInOv, openVocabularies } from './modules/vocabulary/vocabulary-utils';
import { initCreateEntitySettings } from './modules/entitySetting/entitySetting-domain';
import { initManagerConfigurations } from './modules/managerConfiguration/managerConfiguration-domain';
import { GROUP_DEFAULT, groupAddRelation } from './domain/group';

// region Platform constants
const PLATFORM_LOCK_ID = 'platform_init_lock';
// endregion

// region Platform capabilities definition
const KNOWLEDGE_CAPABILITY = 'KNOWLEDGE';
const BYPASS_CAPABILITIES = { name: BYPASS, description: 'Bypass all capabilities', attribute_order: 1 };
export const TAXII_CAPABILITIES = {
  name: TAXIIAPI,
  attribute_order: 2500,
  description: 'Access data sharing',
  dependencies: [
    { name: 'SETCOLLECTIONS', description: 'Manage data sharing', attribute_order: 2510 },
    { name: 'SETCSVMAPPERS', description: 'Manage CSV mappers', attribute_order: 2520 }
  ],
};
const KNOWLEDGE_CAPABILITIES = {
  name: KNOWLEDGE_CAPABILITY,
  description: 'Access knowledge',
  attribute_order: 100,
  dependencies: [
    { name: KNOWLEDGE_COLLABORATION, description: 'Access to collaborative creation', attribute_order: 150 },
    {
      name: KNOWLEDGE_UPDATE,
      description: 'Create / Update knowledge',
      attribute_order: 200,
      dependencies: [
        { name: KNOWLEDGE_ORGANIZATION_RESTRICT, attribute_order: 290, description: 'Restrict organization access' },
        { name: KNOWLEDGE_DELETE, description: 'Delete knowledge', attribute_order: 300 },
        { name: KNOWLEDGE_MANAGE_AUTH_MEMBERS, description: 'Manage authorized members', attribute_order: 310 },
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
  ],
};
export const SETTINGS_CAPABILITIES = {
  name: 'SETTINGS',
  description: 'Access administration',
  attribute_order: 3000,
  dependencies: [
    { name: 'SETACCESSES', description: 'Manage credentials', attribute_order: 3200 },
    { name: 'SETMARKINGS', description: 'Manage marking definitions', attribute_order: 3300 },
    { name: 'SETLABELS', description: 'Manage labels & Attributes', attribute_order: 3400 },
  ],
};
export const CAPABILITIES = [
  BYPASS_CAPABILITIES,
  KNOWLEDGE_CAPABILITIES,
  {
    name: 'EXPLORE',
    description: 'Access exploration',
    attribute_order: 1000,
    dependencies: [
      {
        name: 'EXUPDATE',
        description: 'Create  / Update exploration',
        attribute_order: 1100,
        dependencies: [{ name: 'EXDELETE', description: 'Delete exploration', attribute_order: 1200 }],
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
    attribute_order: 4000,
    description: 'Connectors API usage: register, ping, export push ...',
  },
  {
    name: BYPASS_REFERENCE,
    attribute_order: 6000,
    description: 'Bypass mandatory references if any',
  },
];
// endregion

// Check every dependency
export const checkSystemDependencies = async () => {
  logApp.info('[OPENCTI] Checking dependencies statuses');
  // Check if elasticsearch is available
  await searchEngineInit();
  logApp.info('[CHECK] Search engine is alive');
  // Check if minio is here
  await isStorageAlive();
  logApp.info('[CHECK] Minio is alive');
  // Check if RabbitMQ is here and create the logs exchange/queue
  await rabbitMQIsAlive();
  logApp.info('[CHECK] RabbitMQ is alive');
  // Check if redis is here
  await redisIsAlive();
  logApp.info('[CHECK] Redis is alive');
  // Check if SMTP is here
  await smtpIsAlive();
  // Check if Python is available
  const context = executionContext('system_dependencies');
  await checkPythonAvailability(context, SYSTEM_USER);
  logApp.info('[CHECK] Python3 is available');
  return true;
};

// Initialize
const initializeSchema = async () => {
  // New platform so delete all indices to prevent conflict
  const isInternalIndexExists = await elIndexExists(INDEX_INTERNAL_OBJECTS);
  if (isInternalIndexExists) {
    throw ConfigurationError('Fail initialize schema, index already exists, previous initialization fail '
      + 'because you kill the platform before the end of the initialization. Please remove your '
      + 'elastic/opensearch data and restart.');
  }
  // Create default indexes
  await elCreateIndices();
  logApp.info('[INIT] Search engine indexes loaded');
  return true;
};

const refreshMappingsAndIndices = async () => {
  await elUpdateIndicesMappings();
};

const initializeInternalQueues = async () => {
  await registerConnectorQueues(INTERNAL_PLAYBOOK_QUEUE, 'Internal playbook manager', 'internal', 'playbook');
  await registerConnectorQueues(INTERNAL_SYNC_QUEUE, 'Internal sync manager', 'internal', 'sync');
};

const initializeMigration = async (context) => {
  logApp.info('[INIT] Creating migration structure');
  const time = lastAvailableMigrationTime();
  const lastRun = `${time}-init`;
  const migrationStatus = { internal_id: uuidv4(), lastRun };
  await createEntity(context, SYSTEM_USER, migrationStatus, ENTITY_TYPE_MIGRATION_STATUS);
};

const createMarkingDefinitions = async (context) => {
  // Create marking defs
  await addMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:CLEAR',
    x_opencti_color: '#ffffff',
    x_opencti_order: 1,
  });
  await addMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:GREEN',
    x_opencti_color: '#2e7d32',
    x_opencti_order: 2,
  });
  await addMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  await addMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:AMBER+STRICT',
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  await addMarkingDefinition(context, SYSTEM_USER, {
    definition_type: 'TLP',
    definition: 'TLP:RED',
    x_opencti_color: '#c62828',
    x_opencti_order: 4,
  });
};

const createDefaultStatusTemplates = async (context) => {
  const statusNew = await createStatusTemplate(context, SYSTEM_USER, { name: 'NEW', color: '#ff9800' });
  const statusProgress = await createStatusTemplate(context, SYSTEM_USER, { name: 'IN_PROGRESS', color: '#5c7bf5' });
  await createStatusTemplate(context, SYSTEM_USER, { name: 'PENDING', color: '#5c7bf5' });
  await createStatusTemplate(context, SYSTEM_USER, { name: 'TO_BE_QUALIFIED', color: '#5c7bf5' });
  const statusAnalyzed = await createStatusTemplate(context, SYSTEM_USER, { name: 'ANALYZED', color: '#4caf50' });
  const statusClosed = await createStatusTemplate(context, SYSTEM_USER, { name: 'CLOSED', color: '#607d8b' });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusNew.id, order: 1 });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusProgress.id, order: 2 });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusAnalyzed.id, order: 3 });
  await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_REPORT, { template_id: statusClosed.id, order: 4 });
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

export const createBasicRolesAndCapabilities = async (context) => {
  // Create capabilities
  await createCapabilities(context, CAPABILITIES);
  // Create roles
  const defaultRole = await addRole(context, SYSTEM_USER, {
    name: ROLE_DEFAULT,
    description: 'Default role associated to the default group',
    capabilities: [KNOWLEDGE_CAPABILITY],
  });
  await addRole(context, SYSTEM_USER, {
    name: ROLE_ADMINISTRATOR,
    description: 'Administrator role that bypass every capabilities',
    capabilities: [BYPASS],
  });
  const connectorRole = await addRole(context, SYSTEM_USER, {
    name: 'Connector',
    description: 'Connector role that has the recommended capabilities',
    capabilities: [
      'KNOWLEDGE_KNUPDATE_KNDELETE',
      'KNOWLEDGE_KNUPLOAD',
      'KNOWLEDGE_KNASKIMPORT',
      'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT',
      'KNOWLEDGE_KNENRICHMENT',
      'CONNECTORAPI',
      'BYPASSREFERENCE',
      'MODULES_MODMANAGE',
      'TAXIIAPI',
      'SETTINGS_SETMARKINGS',
      'SETTINGS_SETLABELS',
    ],
  });
  // Create default group with default role
  const defaultGroup = await addGroup(context, SYSTEM_USER, {
    name: GROUP_DEFAULT,
    description: 'Default group associated to all users',
    default_assignation: true,
  });
  const defaultRoleRelationInput = {
    toId: defaultRole.id,
    relationship_type: 'has-role',
  };
  await groupAddRelation(context, SYSTEM_USER, defaultGroup.id, defaultRoleRelationInput);
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

const createVocabularies = async (context) => {
  const categories = Object.values(VocabularyCategory);
  for (let index = 0; index < categories.length; index += 1) {
    const category = categories[index];
    const vocabularies = openVocabularies[category] ?? [];
    for (let i = 0; i < vocabularies.length; i += 1) {
      const { key, description, aliases, order } = vocabularies[i];
      const data = { name: key,
        description: description ?? '',
        aliases: aliases ?? [],
        category,
        order,
        builtIn: builtInOv.includes(category) };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }
};

const initializeDefaultValues = async (context, withMarkings = true) => {
  logApp.info('[INIT] Initialization of settings and basic elements');
  // Create default elements
  await addSettings(context, SYSTEM_USER, {
    platform_title: 'OpenCTI - Cyber Threat Intelligence Platform',
    platform_email: 'admin@opencti.io',
    platform_theme: 'dark',
    platform_language: 'auto',
  });
  await initCreateEntitySettings(context, SYSTEM_USER);
  await initManagerConfigurations(context, SYSTEM_USER);
  await createDefaultStatusTemplates(context);
  await createBasicRolesAndCapabilities(context);
  await createVocabularies(context);
  if (withMarkings) {
    await createMarkingDefinitions(context);
  }
};

const initializeData = async (context, withMarkings = true) => {
  await initializeDefaultValues(context, withMarkings);
  logApp.info('[INIT] Platform default initialized');
  return true;
};

const isExistingPlatform = async (context) => {
  try {
    const migration = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
    return migration !== undefined;
  } catch {
    return false;
  }
};

const isCompatiblePlatform = async (context) => {
  const migration = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
  const { platformVersion: currentVersion } = migration;
  // For old platform, version is not set yet, continue
  if (!currentVersion) return;
  // Runtime version must be >= of the stored runtime
  const runtimeVersion = semver.coerce(PLATFORM_VERSION).version;
  if (semver.lt(runtimeVersion, currentVersion)) {
    throw UnsupportedError('Your platform data are too recent to start on', { currentVersion, runtimeVersion });
  }
};

// eslint-disable-next-line
const platformInit = async (withMarkings = true) => {
  let lock;
  try {
    lock = await lockResource([PLATFORM_LOCK_ID]);
    const context = executionContext('platform_initialization');
    logApp.info('[INIT] Starting platform initialization');
    const alreadyExists = await isExistingPlatform(context);
    if (!alreadyExists) {
      logApp.info('[INIT] New platform detected, initialization...');
      await initializeInternalQueues();
      await initializeBucket();
      await initializeSchema();
      await initializeMigration(context);
      await initializeData(context, withMarkings);
      await initializeAdminUser(context);
      await initDefaultNotifiers(context);
    } else {
      logApp.info('[INIT] Existing platform detected, initialization...');
      await refreshMappingsAndIndices();
      await initializeInternalQueues();
      await isCompatiblePlatform(context);
      await initializeAdminUser(context);
      await applyMigration(context);
      await initCreateEntitySettings(context, SYSTEM_USER);
      await initManagerConfigurations(context, SYSTEM_USER);
    }
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      const reason = 'Platform cant get the lock for initialization (can be due to other instance currently migrating/initializing)';
      throw LockTimeoutError({ participantIds: [PLATFORM_LOCK_ID] }, reason);
    } else {
      throw e;
    }
  } finally {
    if (lock) {
      await lock.unlock();
      logApp.info('[INIT] Platform initialization done');
    }
  }
  return true;
};

export default platformInit;
