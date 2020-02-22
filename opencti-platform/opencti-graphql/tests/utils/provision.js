import { executeWrite, graknIsAlive } from '../../src/database/grakn';
import { elDeleteIndexes, elIsAlive } from '../../src/database/elasticSearch';
import { internalFlushAll } from '../../src/database/redis';
import { initializeData, initializeSchema } from '../../src/initialization';
import { execPython3 } from '../../src/database/utils';
import conf, { logger } from '../../src/config/conf';
import { listenServer, stopServer } from '../../src/httpServer';

const cleanDependenciesData = async () => {
  // Cleaning grakn
  await executeWrite(async wTx => {
    await wTx.tx.query('match $relation isa relation; delete $relation;');
  });
  await executeWrite(async wTx => {
    await wTx.tx.query('match $entity isa entity; delete $entity;');
  });
  // Cleaning elastic
  await elDeleteIndexes();
  // Cleaning Redis
  await internalFlushAll();
};

const provision = async () => {
  await graknIsAlive();
  await elIsAlive();
  const httpServer = await listenServer();
  let start = new Date().getTime();
  logger.warn('[TESTING] > Cleaning data');
  await cleanDependenciesData();
  logger.warn(`[TESTING] > Data cleaned in ${new Date().getTime() - start} ms`);
  await initializeSchema();
  await initializeData();
  logger.warn(`[TESTING] > Platform initialized in ${new Date().getTime() - start} ms`);
  start = new Date().getTime();
  const apiUri = `http://localhost:${conf.get('app:port')}`;
  const apiToken = conf.get('app:admin:token');
  const fileToInject = '/tests/data/CERTFR-2020-CTI-001-STIX2_v2.json';
  const importOpts = [apiUri, apiToken, fileToInject];
  await execPython3('./src/python', 'local_importer.py', importOpts);
  logger.warn(`[TESTING] > Platform data loaded in ${new Date().getTime() - start} ms`);
  await stopServer(httpServer);
};

(async () => {
  await provision();
  process.exit(0);
})();
