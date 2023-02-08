import { describe, expect, it } from 'vitest';
import {
  ADMIN_USER,
  API_TOKEN,
  API_URI,
  FIFTEEN_MINUTES,
  PYTHON_PATH,
  RAW_EVENTS_SIZE,
  SYNC_RAW_START_REMOTE_URI,
  testContext,
} from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';
import { checkPostSyncContent, checkPreSyncContent } from '../sync-utils';

describe('Database sync raw', () => {
  it(
    'Should python raw sync succeed',
    async () => {
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Sync
      const syncOpts = [API_URI, API_TOKEN, SYNC_RAW_START_REMOTE_URI, API_TOKEN, RAW_EVENTS_SIZE, '0', 'None'];
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      // Post check
      await checkPostSyncContent(SYNC_RAW_START_REMOTE_URI, objectMap, relMap, initStixReport);
    },
    FIFTEEN_MINUTES
  );
});
