// Admin user initialization
import { logger } from './config/conf';
import { elCreateIndexes, elDeleteIndexes, elIsAlive } from './database/elasticSearch';
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
const initializeSchema = async (purgeIndex = false) => {
  // Inject grakn schema
  const schema = fs.readFileSync('./src/opencti.gql', 'utf8');
  await internalDirectWrite(schema);
  logger.info(`[INIT] > Grakn schema loaded`);
  // Create default indexes
  // TODO To remove with https://github.com/OpenCTI-Platform/opencti/issues/673
  if (purgeIndex) {
    await elDeleteIndexes();
  }
  await elCreateIndexes();
  logger.info(`[INIT] > Elasticsearch indexes loaded`);
  return true;
};

const createAttributesTypes = async () => {
  await addAttribute({ type: 'report_types', value: 'threat-report' });
  await addAttribute({ type: 'report_types', value: 'internal-report' });
  await addAttribute({ type: 'malware_types', value: 'adware' });
  await addAttribute({ type: 'malware_types', value: 'backdoor' });
  await addAttribute({ type: 'malware_types', value: 'bot' });
  await addAttribute({ type: 'malware_types', value: 'bootkit' });
  await addAttribute({ type: 'malware_types', value: 'ddos' });
  await addAttribute({ type: 'malware_types', value: 'downloader' });
  await addAttribute({ type: 'malware_types', value: 'dropper' });
  await addAttribute({ type: 'malware_types', value: 'exploit-kit' });
  await addAttribute({ type: 'malware_types', value: 'keylogger' });
  await addAttribute({ type: 'malware_types', value: 'ransomware' });
  await addAttribute({ type: 'malware_types', value: 'remote-access-trojan' });
  await addAttribute({ type: 'malware_types', value: 'resource-exploitation' });
  await addAttribute({ type: 'malware_types', value: 'rogue-security-software' });
  await addAttribute({ type: 'malware_types', value: 'rootkit' });
  await addAttribute({ type: 'malware_types', value: 'screen-capture' });
  await addAttribute({ type: 'malware_types', value: 'spyware' });
  await addAttribute({ type: 'malware_types', value: 'trojan' });
  await addAttribute({ type: 'malware_types', value: 'unknown' });
  await addAttribute({ type: 'malware_types', value: 'virus' });
  await addAttribute({ type: 'malware_types', value: 'webshell' });
  await addAttribute({ type: 'malware_types', value: 'wiper' });
  await addAttribute({ type: 'malware_types', value: 'worm' });
};

const createMarkingDefinitions = async () => {
  // Create marking defs
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    definition_type: 'TLP',
    definition: 'TLP:WHITE',
    x_opencti_color: '#ffffff',
    x_opencti_order: 1,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    definition_type: 'TLP',
    definition: 'TLP:GREEN',
    x_opencti_color: '#2e7d32',
    x_opencti_order: 2,
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    x_opencti_color: '#d84315',
    x_opencti_order: 3,
  });
  await addMarkingDefinition(SYSTEM_USER, {
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
    const iterator = await rTx.query('match $x sub entity; get;');
    const answers = await iterator.collect();
    return answers.length;
  });
  return entityCount <= 1; // Only type entity is available on an empty platform.
};

const platformInit = async (noMigration = false) => {
  await checkSystemDependencies();
  try {
    const needToBeInitialized = await isEmptyPlatform();
    if (needToBeInitialized) {
      logger.info(`[INIT] > New platform detected, initialization...`);
      await initializeSchema(true);
      await initializeData();
      await initializeAdminUser();
    } else {
      logger.info('[INIT] > Existing platform detected, migration...');
      // TODO To remove with https://github.com/OpenCTI-Platform/opencti/issues/673
      await initializeSchema(false);
      // Always reset the admin user
      await initializeAdminUser();
      if (!noMigration) {
        await applyMigration();
      }
    }
  } catch (e) {
    logger.error(`[OPENCTI] platform init fail`, { error: e });
    throw e;
  }
  return true;
};

export default platformInit;
