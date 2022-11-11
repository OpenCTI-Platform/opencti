import { describe, expect, it } from 'vitest';
import platformInit from '../../../src/initialization';
import { ADMIN_USER, API_TOKEN, API_URI, FIVE_MINUTES, PYTHON_PATH, testContext } from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';
import httpServer from '../../../src/http/httpServer';

describe('Database provision', () => {
  const importOpts = [API_URI, API_TOKEN, './tests/data/poisonivy.json'];
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
      await httpServer.start();
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await httpServer.shutdown();
    },
    FIVE_MINUTES
  );
});
