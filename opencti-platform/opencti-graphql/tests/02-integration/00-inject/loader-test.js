/* eslint-disable prettier/prettier */
import { checkSystemDependencies, initializeData, initializeSchema } from '../../../src/initialization';
import { listenServer, stopServer } from '../../../src/httpServer';
import conf from '../../../src/config/conf';
import { ONE_MINUTE, ONE_HOUR } from '../../utils/testQuery';
import { execPython3 } from "../../../src/python/pythonBridge";

describe('Database provision', () => {
  let httpServer = null;
  beforeAll(async () => {
    httpServer = await listenServer();
  });
  afterAll(async () => {
    await stopServer(httpServer);
  });

  it('should dependencies accessible', () => {
    return checkSystemDependencies();
  }, ONE_MINUTE);
  it('should schema initialized', () => {
    return initializeSchema();
  }, ONE_MINUTE);
  it('should default data initialized', () => {
    return initializeData();
  }, ONE_MINUTE);
  it('Should import succeed', () => {
    const apiUri = `http://localhost:${conf.get('app:port')}`;
    const apiToken = conf.get('app:admin:token');
    const importOpts = [apiUri, apiToken, '/tests/data/DATA-TEST-STIX2_v2.json'];
    return execPython3('./src/python', 'local_importer.py', importOpts);
  }, ONE_HOUR);
});
