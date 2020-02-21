import { executeWrite, graknIsAlive } from '../../src/database/grakn';
import { elDeleteIndexes, elIsAlive } from '../../src/database/elasticSearch';
import { internalFlushAll } from '../../src/database/redis';
import { initializeData, initializeSchema } from '../../src/initialization';
import { execPython3 } from '../../src/database/utils';
import { logger } from '../../src/config/conf';

const cleanDependenciesData = async () => {
  // Cleaning grakn
  await executeWrite(async wTx => {
    await wTx.tx.query('match $entity isa entity; delete $entity;');
    await wTx.tx.query('match $relation isa relation; delete $relation;');
    await wTx.tx.query('match $attribute isa attribute; delete $attribute;');
  });
  // Cleaning elastic
  await elDeleteIndexes();
  // Cleaning Redis
  await internalFlushAll();
};

const provision = async () => {
  await graknIsAlive();
  await elIsAlive();
  let start = new Date().getTime();
  logger.info('[TESTING] > Cleaning data');
  await cleanDependenciesData();
  logger.info(`[TESTING] > Data cleaned in ${new Date().getTime() - start} ms`);
  await initializeSchema();
  await initializeData();
  logger.info(`[TESTING] > Platform initialized in ${new Date().getTime() - start} ms`);
  start = new Date().getTime();
  await execPython3('./tests/import', 'local_importer.py');
  logger.info(`[TESTING] > Platform data loaded in ${new Date().getTime() - start} ms`);
};

(async () => {
  await provision();
  process.exit(0);
})();
