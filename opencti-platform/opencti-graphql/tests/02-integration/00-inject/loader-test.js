import platformInit from '../../../src/initialization';
import { FIVE_MINUTES, PYTHON_PATH, API_TOKEN, API_URI } from '../../utils/testQuery';
import { execPython3 } from '../../../src/python/pythonBridge';
import { startModules, shutdownModules } from '../../../src/modules';

describe('Database provision', () => {
  const importOpts = [API_URI, API_TOKEN, './tests/data/DATA-TEST-STIX2_v2.json'];
  it(
    'should platform init',
    () => {
      return expect(platformInit()).resolves.toBe(true);
    },
    FIVE_MINUTES
  );
  it(
    'Should import creation succeed',
    async () => {
      await startModules();
      const execution = await execPython3(PYTHON_PATH, 'local_importer.py', importOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
    },
    FIVE_MINUTES
  );
  // Python lib is fixed but we need to wait for a new release
  it(
    'Should import update succeed',
    async () => {
      await startModules();
      const execution = await execPython3(PYTHON_PATH, 'local_importer.py', importOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
