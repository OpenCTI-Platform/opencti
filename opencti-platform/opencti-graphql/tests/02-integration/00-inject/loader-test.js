/* eslint-disable prettier/prettier */
import { checkSystemDependencies, initializeData, initializeSchema } from '../../../src/initialization';
import { listenServer, stopServer } from '../../../src/httpServer';
import {ONE_MINUTE, FIVE_MINUTES, PYTHON_PATH, API_TOKEN, API_URI} from '../../utils/testQuery';
import { execPython3 } from "../../../src/python/pythonBridge";

describe('Database provision', () => {
  const importOpts = [API_URI, API_TOKEN, '/tests/data/DATA-TEST-STIX2_v2.json'];

  it('should dependencies accessible',  () => {
    return expect(checkSystemDependencies()).resolves.toBe(true);
  }, ONE_MINUTE);

  it('should schema initialized', () => {
    return expect(initializeSchema()).resolves.toBe(true);
  }, FIVE_MINUTES);

  it('should default data initialized', () => {
    return expect(initializeData()).resolves.toBe(true);
  }, FIVE_MINUTES);

  it('Should import creation succeed', async () => {
    const httpServer = await listenServer();
    const execution = await execPython3(PYTHON_PATH, 'local_importer.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
    await stopServer(httpServer);
  }, FIVE_MINUTES);

  // Python lib is fixed but we need to wait for a new release
  it('Should import update succeed', async () => {
    const httpServer = await listenServer();
    const execution = await execPython3(PYTHON_PATH, 'local_importer.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
    await stopServer(httpServer);
  }, FIVE_MINUTES);
});
