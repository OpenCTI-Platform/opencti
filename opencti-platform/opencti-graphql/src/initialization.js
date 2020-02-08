// Admin user initialization
import { logger } from './config/conf';
import { elCreateIndexes, elIsAlive } from './database/elasticSearch';
import { graknIsAlive, write } from './database/grakn';
import applyMigration from './database/migration';
import { initializeAdminUser } from './config/security';
import { isStorageAlive } from './database/minio';
import { checkPythonStix2 } from './database/utils';
import { addMarkingDefinition } from './domain/markingDefinition';
import { addSettings, getSettings } from './domain/settings';
import { ROLE_ADMINISTRATOR, ROLE_DEFAULT, SYSTEM_USER } from './domain/user';
import { addCapability, addRole } from './domain/grant';
import { addAttribute } from './domain/attribute';

const fs = require('fs');

// Platform capabilities definition
const BYPASS_CAPABILITY = 'BYPASS';
const KNOWLEDGE_CAPABILITY = 'KNOWLEDGE';
const CAPABILITIES = [
  { name: BYPASS_CAPABILITY, description: 'Bypass all capabilities' },
  {
    name: KNOWLEDGE_CAPABILITY,
    description: 'Access knowledge',
    dependencies: [
      { name: 'KNCREATE', description: 'Create knowledge' },
      { name: 'KNEDIT', description: 'Edit knowledge' },
      { name: 'KNASKIMPORT', description: 'Import knowledge' },
      { name: 'KNASKEXPORT', description: 'Export knowledge' }
    ]
  },
  {
    name: 'MODULES',
    description: 'Access connectors',
    dependencies: [
      { name: 'MODMANAGE', description: 'Manage connector state' },
      { name: 'MODEXPORT', description: 'Push export files through API' }
    ]
  },
  {
    name: 'SETTINGS',
    description: 'Access administration',
    dependencies: [{ name: 'SETACCESSES', description: 'Manage credentials' }]
  }
];

// Check every dependencies
export const checkSystemDependencies = async () => {
  // Check if Grakn is available
  await graknIsAlive();
  logger.info(`[PRE-CHECK] > Grakn is alive`);
  // Check if elasticsearch is available
  await elIsAlive();
  logger.info(`[PRE-CHECK] > Elasticsearch is alive`);
  // Check if minio is here
  await isStorageAlive();
  logger.info(`[PRE-CHECK] > Minio is alive`);
  // Check if Python is available
  await checkPythonStix2();
  logger.info(`[PRE-CHECK] > Python3 is available`);
};

// Initialize
export const initializeSchema = async () => {
  // Inject grakn schema
  const schema = fs.readFileSync('./src/opencti.gql', 'utf8');
  await write(schema);
  logger.info(`[INIT] > Grakn schema loaded`);
  // Create default indexes
  await elCreateIndexes();
  logger.info(`[INIT] > Elasticsearch indexes loaded`);
};

const createReportsTypes = async () => {
  await addAttribute({ type: 'report_class', value: 'Threat Report' });
  await addAttribute({ type: 'report_class', value: 'Internal Report' });
};

const createMarkingDefinitions = async () => {
  // Create marking defs
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    definition_type: 'TLP',
    definition: 'TLP:WHITE',
    color: '#ffffff',
    level: 1
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    definition_type: 'TLP',
    definition: 'TLP:GREEN',
    color: '#2e7d32',
    level: 2
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    color: '#d84315',
    level: 3
  });
  await addMarkingDefinition(SYSTEM_USER, {
    stix_id_key: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    definition_type: 'TLP',
    definition: 'TLP:RED',
    color: '#c62828',
    level: 4
  });
};

const createCapabilities = async (capabilities, parentName = '') => {
  for (let i = 0; i < capabilities.length; i += 1) {
    const capability = capabilities[i];
    const { name, description } = capability;
    const capabilityName = `${parentName}${name}`;
    // eslint-disable-next-line no-await-in-loop
    await addCapability({ name: capabilityName, description });
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
  await addRole({
    name: ROLE_DEFAULT,
    description: 'Default role associated to all users',
    capabilities: [KNOWLEDGE_CAPABILITY],
    default_assignation: true
  });
  await addRole({
    name: ROLE_ADMINISTRATOR,
    description: 'Administrator role that bypass every capabilities',
    capabilities: [BYPASS_CAPABILITY]
  });
};

const initializeDefaultValues = async () => {
  await addSettings(SYSTEM_USER, {
    platform_title: 'Cyber threat intelligence platform',
    platform_email: 'admin@opencti.io',
    platform_url: '',
    platform_language: 'auto',
    platform_external_auth: true,
    platform_registration: false,
    platform_demo: false
  });
  await createReportsTypes();
  await createMarkingDefinitions();
  await createBasicRolesAndCapabilities();
};

const initializeData = async () => {
  // Init default values only if platform as no settings
  const settings = await getSettings();
  if (!settings) await initializeDefaultValues();
  logger.info(`[INIT] > Platform default initialized`);
  await initializeAdminUser();
};

const init = async () => {
  await checkSystemDependencies();
  await initializeSchema();
  await applyMigration();
  await initializeData();
};

export default init;
