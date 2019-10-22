// Admin user initialization
import { logger } from './config/conf';
import { createIndexes, elasticIsAlive } from './database/elasticSearch';
import { graknIsAlive, write } from './database/grakn';
import applyMigration from './database/migration';
import { initializeAdminUser } from './config/security';
import { isStorageAlive } from './database/minio';

const fs = require('fs');

// Check every dependencies
export const checkSystemDependencies = async () => {
  // Check if Grakn is available
  await graknIsAlive();
  logger.info(`[PRE-CHECK] > Grakn is alive`);
  // Check if elasticsearch is available
  await elasticIsAlive();
  logger.info(`[PRE-CHECK] > Elasticsearch is alive`);
  // Check if minio is here
  await isStorageAlive();
  logger.info(`[PRE-CHECK] > Minio is alive`);
};

// Initialize
export const initializeSchema = async () => {
  // Inject grakn schema
  const schema = fs.readFileSync('./src/opencti.gql', 'utf8');
  await write(schema);
  logger.info(`[INIT] > Grakn schema loaded`);
  // Create default indexes
  await createIndexes();
  logger.info(`[INIT] > Elasticsearch indexes loaded`);
};

const init = async () => {
  await checkSystemDependencies();
  await initializeSchema();
  await applyMigration();
  await initializeAdminUser();
};

export default init;
