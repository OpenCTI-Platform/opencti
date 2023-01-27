// Admin user initialization
import { ApolloError } from 'apollo-errors';
import { v4 as uuidv4 } from 'uuid';
// import semver from 'semver';
import { booleanConf, logApp } from './config/conf';
import { elCreateIndexes, elIndexExists, elIsAlive } from './database/elasticSearch';
import { initializeAdminUser } from './config/providers';
import { isStorageAlive } from './database/s3';
import { amqpIsAlive } from './database/amqp';
import { artemisAlive } from './service/artemis';
import { keycloakAlive } from './service/keycloak';
import { stardogAlive } from './service/stardog';
import { addMarkingDefinition } from './domain/markingDefinition';
import { addSettings } from './domain/settings';
import { ROLE_DEFAULT, STREAMAPI, TAXIIAPI } from './domain/user';
import { addCapability, addRole } from './domain/grant';
import { addAttribute } from './domain/attribute';
import { checkPythonStix2 } from './python/pythonBridge';
import { cachePurge, lockResource, redisIsAlive } from './database/redis';
import { ENTITY_TYPE_MIGRATION_STATUS } from './schema/internalObject';
import applyMigration, { lastAvailableMigrationTime } from './database/migration';
import { createEntity, loadEntity, patchAttribute } from './database/middleware';
import { INDEX_INTERNAL_OBJECTS } from './database/utils';
import { ConfigurationError, TYPE_LOCK_ERROR } from './config/errors';
import { BYPASS, ROLE_ADMINISTRATOR, SYSTEM_USER } from './utils/access';
import { smtpIsAlive } from './database/smtp';
import { generateStandardId } from './schema/identifier';
import { ENTITY_TYPE_MARKING_DEFINITION } from './schema/stixMetaObject';
import { createStatus, createStatusTemplate } from './domain/status';
import { ENTITY_TYPE_CONTAINER_REPORT } from './schema/stixDomainObject';

// region Platform constants
const PLATFORM_LOCK_ID = 'platform_init_lock';
// endregion

// region Platform capabilities definition
const KNOWLEDGE_CAPABILITY = 'KNOWLEDGE';
const BYPASS_CAPABILITIES = { name: BYPASS, description: 'Bypass all capabilities', attribute_order: 1 };
export const TAXII_CAPABILITIES = {
  name: TAXIIAPI,
  attribute_order: 2500,
  description: 'Access Taxii feed',
  dependencies: [{ name: 'SETCOLLECTIONS', description: 'Manage Taxii collections', attribute_order: 2510 }],
};
export const KNOWLEDGE_DELETE = 'KNDELETE';
const KNOWLEDGE_CAPABILITIES = {
  name: KNOWLEDGE_CAPABILITY,
  description: 'Access knowledge',
  attribute_order: 100,
  dependencies: [
    {
      name: 'KNUPDATE',
      description: 'Create / Update knowledge',
      attribute_order: 200,
      dependencies: [{ name: KNOWLEDGE_DELETE, description: 'Delete knowledge', attribute_order: 300 }],
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
    name: STREAMAPI,
    attribute_order: 5000,
    description: 'Connect and consume the platform stream',
  },
];
// endregion

// Check every dependencies
export const checkSystemDependencies = async () => {
  // Check if stardog is alive
  if (await stardogAlive()) {
    logApp.info('[Check] Stardog service is alive');
  } else {
    logApp.info('[Check] Stardog service is not available.');
  }
  // Check if keycloak is alive
  if (await keycloakAlive()) {
    logApp.info('[Check] Keycloak service is alive');
  } else {
    logApp.info('[Check] Keycloak service did not load.');
  }
  // Check if ActiveMQ Artemis REST API is alive
  if (await artemisAlive()) {
    logApp.info('[Check] ActiveMQ Artemis REST service is alive');
  } else {
    logApp.info('[Check] ActiveMQ Artemis REST service did not load.');
  }
  // Check if elasticsearch is available
  await elIsAlive();
  logApp.info(`[CHECK] ElasticSearch is alive`);
  // Check if s3 is accessible
  if (await isStorageAlive()) {
    logApp.info(`[CHECK] S3 is alive`);
  } else {
    logApp.info(`[CHECK] S3 skipped`);
  }
  // Check if AMQP connection is here and create the logs exchange/queue
  await amqpIsAlive();
  logApp.info(`[CHECK] AMQP is alive`);
  // Check if redis is here
  await redisIsAlive();
  logApp.info(`[CHECK] Redis is alive`);
  if (booleanConf('subscription_scheduler:enabled', true)) {
    // Check if SMTP is here
    await smtpIsAlive();
    logApp.info(`[CHECK] SMTP is alive`);
  }
  // Check if Python is available
  await checkPythonStix2();
  logApp.info(`[CHECK] Python3 is available`);
  return true;
};

// Initialize
const initializeSchema = async () => {
  // New platform so delete all indices to prevent conflict
  const isInternalIndexExists = await elIndexExists(INDEX_INTERNAL_OBJECTS);
  if (isInternalIndexExists) {
    throw ConfigurationError('[INIT] Fail initialize schema, index already exists');
  }
  // Create default indexes
  await elCreateIndexes();
  logApp.info(`[INIT] Elasticsearch indexes loaded`);
  return true;
};

const initializeMigration = async () => {
  logApp.info('[INIT] Creating migration structure');
  const time = lastAvailableMigrationTime();
  const lastRun = `${time}-init`;
  const migrationStatus = { internal_id: uuidv4(), lastRun };
  await createEntity(SYSTEM_USER, migrationStatus, ENTITY_TYPE_MIGRATION_STATUS);
};

// This code will patch release <= 4.0.1
// This prevent some complex procedure for users. To be removed after some times
const alignMigrationLastRun = async () => {
  logApp.info('[INIT] Aligning migration');
  const migrationStatus = await loadEntity(SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
  const { lastRun } = migrationStatus;
  const [lastRunTime] = lastRun.split('-');
  const lastRunStamp = parseInt(lastRunTime, 10);
  const timeAvailableMigrationTimestamp = lastAvailableMigrationTime();
  if (lastRunStamp > timeAvailableMigrationTimestamp) {
    // Reset the last run to apply migration.
    const patch = { lastRun: `1608026400000-init` };
    await patchAttribute(SYSTEM_USER, migrationStatus.internal_id, ENTITY_TYPE_MIGRATION_STATUS, patch);
  }
  logApp.info('[INIT] Migration aligned');
};

// eslint-disable-next-line
const createAttributesTypes = async () => {
  await addAttribute(SYSTEM_USER, { key: 'report_types', value: 'threat-report' });
  await addAttribute(SYSTEM_USER, { key: 'report_types', value: 'internal-report' });
};

const createMarkingDefinitions = async () => {
  // Create marking defs
  const WHITE = { definition_type: 'TLP', definition: 'TLP:WHITE' };
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    stix_id: generateStandardId(ENTITY_TYPE_MARKING_DEFINITION, WHITE),
    ...WHITE,
    x_opencti_color: '#ffffff',
    x_opencti_order: 1,
  });
  const GREEN = { definition_type: 'TLP', definition: 'TLP:GREEN' };
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    stix_id: generateStandardId(ENTITY_TYPE_MARKING_DEFINITION, GREEN),
    ...GREEN,
    x_opencti_color: '#2e7d32',
    x_opencti_order: 2,
  });
  const AMBER = { definition_type: 'TLP', definition: 'TLP:AMBER' };
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    stix_id: generateStandardId(ENTITY_TYPE_MARKING_DEFINITION, AMBER),
    ...AMBER,
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  const RED = { definition_type: 'TLP', definition: 'TLP:RED' };
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    stix_id: generateStandardId(ENTITY_TYPE_MARKING_DEFINITION, RED),
    ...RED,
    x_opencti_color: '#c62828',
    x_opencti_order: 4,
  });
};

const createDefaultStatusTemplates = async () => {
  const statusNew = await createStatusTemplate(SYSTEM_USER, {
    name: 'NEW',
    color: '#ff9800',
  });
  const statusInProgress = await createStatusTemplate(SYSTEM_USER, {
    name: 'IN_PROGRESS',
    color: '#5c7bf5',
  });
  await createStatusTemplate(SYSTEM_USER, {
    name: 'PENDING',
    color: '#5c7bf5',
  });
  await createStatusTemplate(SYSTEM_USER, {
    name: 'TO_BE_QUALIFIED',
    color: '#5c7bf5',
  });
  const statusAnalyzed = await createStatusTemplate(SYSTEM_USER, {
    name: 'ANALYZED',
    color: '#4caf50',
  });
  const statusClosed = await createStatusTemplate(SYSTEM_USER, {
    name: 'CLOSED',
    color: '#607d8b',
  });
  await createStatus(
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_REPORT,
    {
      template_id: statusNew.id,
      order: 1,
    },
    true
  );
  await createStatus(
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_REPORT,
    {
      template_id: statusInProgress.id,
      order: 2,
    },
    true
  );
  await createStatus(
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_REPORT,
    {
      template_id: statusAnalyzed.id,
      order: 3,
    },
    true
  );
  await createStatus(
    SYSTEM_USER,
    ENTITY_TYPE_CONTAINER_REPORT,
    {
      template_id: statusClosed.id,
      order: 4,
    },
    true
  );
};

export const createCapabilities = async (capabilities, parentName = '') => {
  for (let i = 0; i < capabilities.length; i += 1) {
    const capability = capabilities[i];
    const { name, description, attribute_order: AttributeOrder } = capability;
    const capabilityName = `${parentName}${name}`;
    await addCapability(SYSTEM_USER, { name: capabilityName, description, attribute_order: AttributeOrder });
    if (capability.dependencies && capability.dependencies.length > 0) {
      await createCapabilities(capability.dependencies, `${capabilityName}_`);
    }
  }
};

export const createBasicRolesAndCapabilities = async () => {
  // Create capabilities
  await createCapabilities(CAPABILITIES);
  // Create roles
  await addRole(SYSTEM_USER, {
    name: ROLE_DEFAULT,
    description: 'Default role associated to all users',
    capabilities: [KNOWLEDGE_CAPABILITY],
    default_assignation: true,
  });
  await addRole(SYSTEM_USER, {
    name: ROLE_ADMINISTRATOR,
    description: 'Administrator role that bypass every capabilities',
    capabilities: [BYPASS],
  });
  await addRole(SYSTEM_USER, {
    name: 'Connector',
    description: 'Connector role that has the recommended capabilities',
    capabilities: [
      'KNOWLEDGE_KNUPDATE_KNDELETE',
      'KNOWLEDGE_KNUPLOAD',
      'KNOWLEDGE_KNASKIMPORT',
      'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT',
      'KNOWLEDGE_KNENRICHMENT',
      'CONNECTORAPI',
      'MODULES_MODMANAGE',
      'STREAMAPI',
      'SETTINGS_SETMARKINGS',
      'SETTINGS_SETLABELS',
    ],
  });
};

const initializeDefaultValues = async (withMarkings = true) => {
  logApp.info(`[INIT] Initialization of settings and basic elements`);
  // Create default elements
  await addSettings(SYSTEM_USER, {
    platform_title: 'Cyber threat intelligence platform',
    platform_email: 'admin@opencti.io',
    platform_url: '',
    platform_theme: 'dark',
    platform_language: 'auto',
    // TODO: Workaround
    platform_theme_dark_primary: '#075AD3',
    platform_theme_dark_secondary: '#F9B406',
  });
  await createDefaultStatusTemplates();
  await createAttributesTypes();
  await createBasicRolesAndCapabilities();
  if (withMarkings) {
    await createMarkingDefinitions();
  }
};

const initializeData = async (withMarkings = true) => {
  await initializeDefaultValues(withMarkings);
  logApp.info(`[INIT] Platform default initialized`);
  return true;
};

const isExistingPlatform = async () => {
  try {
    const migration = await loadEntity(SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
    return migration !== undefined;
  } catch {
    return false;
  }
};

// const isCompatiblePlatform = async () => {
//   const migration = await loadEntity(SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
//   const { platformVersion } = migration;
//   // For old platform, version is not set yet, continue
//   if (!platformVersion) return;
//   // Runtime version must be >= of the stored runtime
//   if (semver.lt(PLATFORM_VERSION, platformVersion)) {
//     throw UnsupportedError(
//       `Your platform data (${PLATFORM_VERSION}) are too old to start on version ${platformVersion}`
//     );
//   }
// };

// eslint-disable-next-line
const platformInit = async (withMarkings = true) => {
  let lock;
  try {
    await checkSystemDependencies();
    await cachePurge();
    lock = await lockResource([PLATFORM_LOCK_ID]);
    logApp.info(`[INIT] Starting platform initialization`);
    const alreadyExists = await isExistingPlatform();
    if (!alreadyExists) {
      logApp.info(`[INIT] New platform detected, initialization...`);
      await initializeSchema();
      await initializeMigration();
      await initializeData(withMarkings);
      await initializeAdminUser();
    } else {
      logApp.info('[INIT] Existing platform detected, initialization...');
      // await isCompatiblePlatform();
      await initializeAdminUser();
      await alignMigrationLastRun();
      await applyMigration();
    }
  } catch (e) {
    if (e.name === TYPE_LOCK_ERROR) {
      logApp.error(`[CYIO] Platform cant get the lock for initialization`);
    } else {
      const isApolloError = e instanceof ApolloError;
      const error = isApolloError
        ? e
        : { name: 'UnknownError', error: e.name, data: { message: e.message, _stack: e.stack } };
      logApp.error(`[CYIO] Platform initialization fail`, { error });
    }
    throw e;
  } finally {
    if (lock) {
      await lock.unlock();
      logApp.info(`[INIT] Platform initialization done`);
    }
  }
  return true;
};

export default platformInit;
