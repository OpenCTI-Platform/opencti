// Admin user initialization
import { logger } from './config/conf';
import { elCreateIndexes, elIsAlive } from './database/elasticSearch';
import { graknIsAlive, internalDirectWrite, executeRead } from './database/grakn';
import applyMigration from './database/migration';
import { initializeAdminUser } from './config/providers';
import { isStorageAlive } from './database/minio';
import { ensureRabbitMQAndLogsQueue } from './database/rabbitmq';
import { addMarkingDefinition } from './domain/markingDefinition';
import { addSettings } from './domain/settings';
import { BYPASS, ROLE_ADMINISTRATOR, ROLE_DEFAULT, SYSTEM_USER } from './domain/user';
import { addCapability, addRole } from './domain/grant';
import { addAttribute } from './domain/attribute';
import { checkPythonStix2 } from './python/pythonBridge';
import { redisIsAlive } from './database/redis';

// noinspection NodeJsCodingAssistanceForCoreModules
const fs = require('fs');

// Platform capabilities definition
const KNOWLEDGE_CAPABILITY = 'KNOWLEDGE';
export const CAPABILITIES = [
  { name: BYPASS, description: 'Bypass all capabilities', ordering: 1 },
  {
    name: KNOWLEDGE_CAPABILITY,
    description: 'Access knowledge',
    ordering: 100,
    dependencies: [
      {
        name: 'KNUPDATE',
        description: 'Create / Update knowledge',
        ordering: 200,
        dependencies: [{ name: 'KNDELETE', description: 'Delete knowledge', ordering: 300 }],
      },
      { name: 'KNUPLOAD', description: 'Upload knowledge files', ordering: 400 },
      { name: 'KNASKIMPORT', description: 'Import knowledge', ordering: 500 },
      {
        name: 'KNGETEXPORT',
        description: 'Download knowledge export',
        ordering: 700,
        dependencies: [{ name: 'KNASKEXPORT', description: 'Generate knowledge export', ordering: 710 }],
      },
      { name: 'KNENRICHMENT', description: 'Ask for knowledge enrichment', ordering: 800 },
    ],
  },
  {
    name: 'EXPLORE',
    description: 'Access exploration',
    ordering: 1000,
    dependencies: [
      {
        name: 'EXUPDATE',
        description: 'Create  / Update exploration',
        ordering: 1100,
        dependencies: [{ name: 'EXDELETE', description: 'Delete exploration', ordering: 1200 }],
      },
    ],
  },
  {
    name: 'MODULES',
    description: 'Access connectors',
    ordering: 2000,
    dependencies: [{ name: 'MODMANAGE', description: 'Manage connector state', ordering: 2100 }],
  },
  {
    name: 'SETTINGS',
    description: 'Access administration',
    ordering: 3000,
    dependencies: [
      { name: 'SETINFERENCES', description: 'Manage inference rules', ordering: 3100 },
      { name: 'SETACCESSES', description: 'Manage credentials', ordering: 3200 },
      { name: 'SETMARKINGS', description: 'Manage marking definitions', ordering: 3300 },
    ],
  },
  {
    name: 'CONNECTORAPI',
    ordering: 4000,
    description: 'Connectors API usage: register, ping, export push ...',
  },
];

// Check every dependencies
const checkSystemDependencies = async () => {
  // Check if Grakn is available
  await graknIsAlive();
  logger.info(`[PRE-CHECK] > Grakn is alive`);
  // Check if elasticsearch is available
  await elIsAlive();
  logger.info(`[PRE-CHECK] > ElasticSearch is alive`);
  // Check if minio is here
  await isStorageAlive();
  logger.info(`[PRE-CHECK] > Minio is alive`);
  // Check if RabbitMQ is here and create the logs exchange/queue
  await ensureRabbitMQAndLogsQueue();
  logger.info(`[PRE-CHECK] > RabbitMQ is alive`);
  // Check if redis is here
  await redisIsAlive();
  logger.info(`[PRE-CHECK] > Redis is alive`);
  // Check if Python is available
  await checkPythonStix2();
  logger.info(`[PRE-CHECK] > Python3 is available`);
  return true;
};

// Initialize
const initializeSchema = async () => {
  // Inject grakn schema
  const schema = fs.readFileSync('./src/opencti.gql', 'utf8');
  await internalDirectWrite(schema);
  logger.info(`[INIT] > Grakn schema loaded`);
  // Create default indexes
  // TODO To remove with https://github.com/OpenCTI-Platform/opencti/issues/673
  // await elDeleteIndexes();
  await elCreateIndexes();
  logger.info(`[INIT] > Elasticsearch indexes loaded`);
  return true;
};

const createAttributesTypes = async () => {
  await addAttribute({ type: 'report_class', value: 'Threat Report' });
  await addAttribute({ type: 'report_class', value: 'Internal Report' });
  await addAttribute({ type: 'role_played', value: 'C2 server' });
  await addAttribute({ type: 'role_played', value: 'Relay node' });
};

const createMarkingDefinitions = async () => {
  // Create marking defs
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    definition_type: 'TLP',
    definition: 'TLP:WHITE',
    color: '#ffffff',
    level: 1,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    definition_type: 'TLP',
    definition: 'TLP:GREEN',
    color: '#2e7d32',
    level: 2,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    color: '#d84315',
    level: 3,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    definition_type: 'TLP',
    definition: 'TLP:RED',
    color: '#c62828',
    level: 4,
  });
};

export const createCapabilities = async (capabilities, parentName = '') => {
  for (let i = 0; i < capabilities.length; i += 1) {
    const capability = capabilities[i];
    const { name, description, ordering } = capability;
    const capabilityName = `${parentName}${name}`;
    // eslint-disable-next-line no-await-in-loop
    await addCapability(SYSTEM_USER, { name: capabilityName, description, ordering });
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
  logger.info(`[INIT] > Initialization of settings and basic elements`);
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
  logger.info(`[INIT] > Platform default initialized`);
  return true;
};

const isEmptyPlatform = async () => {
  const entityCount = await executeRead(async (rTx) => {
    const iterator = await rTx.tx.query('match $x sub entity; get;');
    const answers = await iterator.collect();
    return answers.length;
  });
  return entityCount <= 1; // Only type entity is available on an empty platform.
};

const platformInit = async () => {
  await checkSystemDependencies();
  const needToBeInitialized = await isEmptyPlatform();
  if (needToBeInitialized) {
    logger.info(`[INIT] > New platform detected, initialization...`);
    await initializeSchema();
    await initializeData();
    await initializeAdminUser();
  } else {
    logger.info('[INIT] > Existing platform detected, migration...');
    // TODO To remove with https://github.com/OpenCTI-Platform/opencti/issues/673
    await initializeSchema();
    // Always reset the admin user
    await initializeAdminUser();
    await applyMigration();
  }
  return true;
};

export default platformInit;
