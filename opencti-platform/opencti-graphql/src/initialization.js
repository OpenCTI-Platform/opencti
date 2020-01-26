// Admin user initialization
import { logger } from './config/conf';
import { elCreateIndexes, elIsAlive } from './database/elasticSearch';
import { graknIsAlive, write } from './database/grakn';
import applyMigration from './database/migration';
import { initializeAdminUser } from './config/security';
import { isStorageAlive } from './database/minio';
import { checkPythonStix2 } from './database/utils';
import { addMarkingDefinition, findById as markingById } from './domain/markingDefinition';
import { addSettings, getSettings } from './domain/settings';

const fs = require('fs');

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

const initMarkingDef = async marking => {
  const getMarking = await markingById(marking.stix_id_key);
  if (getMarking === null) {
    await addMarkingDefinition({}, marking);
    logger.info(`[INIT] > Marking ${marking.definition} injected`);
  }
};

const initSettings = async () => {
  const settings = await getSettings();
  if (!settings) {
    await addSettings(
      {},
      {
        platform_title: 'Cyber threat intelligence platform',
        platform_email: 'admin@opencti.io',
        platform_url: '',
        platform_language: 'auto',
        platform_external_auth: true,
        platform_registration: false,
        platform_demo: false
      }
    );
    logger.info(`[INIT] > Platform default settings initialized`);
  }
};

const initializeDefaultValues = async () => {
  await initMarkingDef({
    stix_id_key: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    definition_type: 'TLP',
    definition: 'TLP:WHITE',
    color: '#ffffff',
    level: 1
  });
  await initMarkingDef({
    stix_id_key: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    definition_type: 'TLP',
    definition: 'TLP:GREEN',
    color: '#2e7d32',
    level: 2
  });
  await initMarkingDef({
    stix_id_key: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    color: '#d84315',
    level: 3
  });
  await initMarkingDef({
    stix_id_key: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    definition_type: 'TLP',
    definition: 'TLP:RED',
    color: '#c62828',
    level: 4
  });
  await initSettings();
};

const initializeData = async () => {
  await initializeAdminUser();
  await initializeDefaultValues();
};

const init = async () => {
  await checkSystemDependencies();
  await initializeSchema();
  await applyMigration();
  await initializeData();
};

export default init;
