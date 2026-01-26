import { describe, expect, it } from 'vitest';
import { ADMIN_USER, ADMIN_API_TOKEN, API_URI, FIFTEEN_MINUTES, PYTHON_PATH, SYNC_LIVE_EVENTS_SIZE, SYNC_LIVE_START_REMOTE_URI, testContext } from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';
import { FROM_START, now } from '../../../src/utils/format';
import { checkPostSyncContent, checkPreSyncContent } from '../sync-utils';

describe('Database sync live', () => {
  it(
    'Should python live sync succeed',
    async () => {
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Sync
      const syncOpts = [
        API_URI,
        ADMIN_API_TOKEN,
        SYNC_LIVE_START_REMOTE_URI,
        ADMIN_API_TOKEN,
        SYNC_LIVE_EVENTS_SIZE,
        FROM_START,
        now(),
        'live',
      ];
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      // Post check
      await checkPostSyncContent(SYNC_LIVE_START_REMOTE_URI, objectMap, relMap, initStixReport);
    },
    FIFTEEN_MINUTES
  );
});
