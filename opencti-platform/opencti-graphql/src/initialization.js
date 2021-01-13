// Admin user initialization
import { ApolloError } from 'apollo-errors';
import { logger } from './config/conf';
import { elCreateIndexes, elIndexExists, elIsAlive } from './database/elasticSearch';
import { initializeAdminUser } from './config/providers';
import { isStorageAlive } from './database/minio';
import { rabbitMQIsAlive } from './database/rabbitmq';
import { addMarkingDefinition } from './domain/markingDefinition';
import { addSettings } from './domain/settings';
import { BYPASS, ROLE_ADMINISTRATOR, ROLE_DEFAULT, STREAMAPI, SYSTEM_USER } from './domain/user';
import { addCapability, addRole } from './domain/grant';
import { addAttribute } from './domain/attribute';
import { checkPythonStix2 } from './python/pythonBridge';
import { redisIsAlive } from './database/redis';
import { ENTITY_TYPE_MIGRATION_STATUS } from './schema/internalObject';
import applyMigration, { lastAvailableMigrationTime } from './database/migration';
import { createEntity, loadEntity, patchAttribute } from './database/middleware';
import { INDEX_INTERNAL_OBJECTS } from './database/utils';
import { ConfigurationError } from './config/errors';

// Platform capabilities definition
const KNOWLEDGE_CAPABILITY = 'KNOWLEDGE';
export const CAPABILITIES = [
  { name: BYPASS, description: 'Bypass all capabilities', attribute_order: 1 },
  {
    name: KNOWLEDGE_CAPABILITY,
    description: 'Access knowledge',
    attribute_order: 100,
    dependencies: [
      {
        name: 'KNUPDATE',
        description: 'Create / Update knowledge',
        attribute_order: 200,
        dependencies: [{ name: 'KNDELETE', description: 'Delete knowledge', attribute_order: 300 }],
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
  },
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
  {
    name: 'SETTINGS',
    description: 'Access administration',
    attribute_order: 3000,
    dependencies: [
      { name: 'SETINFERENCES', description: 'Manage inference rules', attribute_order: 3100 },
      { name: 'SETACCESSES', description: 'Manage credentials', attribute_order: 3200 },
      { name: 'SETMARKINGS', description: 'Manage marking definitions', attribute_order: 3300 },
    ],
  },
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

// Check every dependencies
export const checkSystemDependencies = async () => {
  // Check if elasticsearch is available
  await elIsAlive();
  logger.info(`[CHECK] ElasticSearch is alive`);
  // Check if minio is here
  await isStorageAlive();
  logger.info(`[CHECK] Minio is alive`);
  // Check if RabbitMQ is here and create the logs exchange/queue
  await rabbitMQIsAlive();
  logger.info(`[CHECK] RabbitMQ is alive`);
  // Check if redis is here
  await redisIsAlive();
  logger.info(`[CHECK] Redis is alive`);
  // Check if Python is available
  await checkPythonStix2();
  logger.info(`[CHECK] Python3 is available`);
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
  logger.info(`[INIT] Elasticsearch indexes loaded`);
  return true;
};

const initializeMigration = async (testMode = false) => {
  logger.info('[INIT] Creating migration structure');
  const time = testMode ? new Date().getTime() : lastAvailableMigrationTime();
  const lastRun = `${time}-init`;
  const migrationStatus = { lastRun };
  await createEntity(SYSTEM_USER, migrationStatus, ENTITY_TYPE_MIGRATION_STATUS);
};

// This code will patch release <= 4.0.1
// This prevent some complex procedure for users. To be removed after some times
const alignMigrationLastRun = async () => {
  const migrationStatus = await loadEntity([ENTITY_TYPE_MIGRATION_STATUS]);
  const { lastRun } = migrationStatus;
  const [lastRunTime] = lastRun.split('-');
  const lastRunStamp = parseInt(lastRunTime, 10);
  const timeAvailableMigrationTimestamp = lastAvailableMigrationTime();
  if (lastRunStamp > timeAvailableMigrationTimestamp) {
    // Reset the last run to apply migration.
    const patch = { lastRun: `1608026400000-init` };
    await patchAttribute(SYSTEM_USER, migrationStatus.internal_id, ENTITY_TYPE_MIGRATION_STATUS, patch);
  }
};

// eslint-disable-next-line
const createAttributesTypes = async () => {
  await addAttribute(SYSTEM_USER, { key: 'report_types', value: 'threat-report' });
  await addAttribute(SYSTEM_USER, { key: 'report_types', value: 'internal-report' });
};

const createMarkingDefinitions = async () => {
  // Create marking defs
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    stix_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    definition_type: 'TLP',
    definition: 'TLP:WHITE',
    x_opencti_color: '#ffffff',
    x_opencti_order: 1,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    stix_id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    definition_type: 'TLP',
    definition: 'TLP:GREEN',
    x_opencti_color: '#2e7d32',
    x_opencti_order: 2,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    stix_id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    standard_id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    stix_id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    definition_type: 'TLP',
    definition: 'TLP:RED',
    x_opencti_color: '#c62828',
    x_opencti_order: 4,
  });
};

export const createCapabilities = async (capabilities, parentName = '') => {
  for (let i = 0; i < capabilities.length; i += 1) {
    const capability = capabilities[i];
    const { name, description, attribute_order: AttributeOrder } = capability;
    const capabilityName = `${parentName}${name}`;
    // eslint-disable-next-line no-await-in-loop
    await addCapability(SYSTEM_USER, { name: capabilityName, description, attribute_order: AttributeOrder });
    if (capability.dependencies && capability.dependencies.length > 0) {
      // eslint-disable-next-line no-await-in-loop
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
};

const initializeDefaultValues = async () => {
  logger.info(`[INIT] Initialization of settings and basic elements`);
  // Create default elements
  await addSettings(SYSTEM_USER, {
    platform_title: 'Cyber threat intelligence platform',
    platform_email: 'admin@opencti.io',
    platform_url: '',
    platform_language: 'auto',
  });
  await createAttributesTypes();
  await createMarkingDefinitions();
  await createBasicRolesAndCapabilities();
};

const initializeData = async () => {
  await initializeDefaultValues();
  logger.info(`[INIT] Platform default initialized`);
  return true;
};

const isExistingPlatform = async () => {
  try {
    const migration = await loadEntity([ENTITY_TYPE_MIGRATION_STATUS]);
    return migration !== undefined;
  } catch {
    return false;
  }
};

// eslint-disable-next-line
const platformInit = async (testMode = false) => {
  try {
    await checkSystemDependencies();
    const alreadyExists = await isExistingPlatform();
    if (!alreadyExists) {
      logger.info(`[INIT] New platform detected, initialization...`);
      await initializeSchema();
      await initializeMigration(testMode);
      await initializeData();
      await initializeAdminUser();
    } else {
      logger.info('[INIT] Existing platform detected, initialization...');
      // Always reset the admin user
      await initializeAdminUser();
      if (!testMode) {
        await alignMigrationLastRun();
        await applyMigration();
      }
    }
  } catch (e) {
    const isApolloError = e instanceof ApolloError;
    const error = isApolloError ? e : { name: 'UnknownError', data: { message: e.message, _stack: e.stack } };
    logger.error(`[OPENCTI] Platform initialization fail`, { error });
    throw e;
  }
  return true;
};

export default platformInit;
