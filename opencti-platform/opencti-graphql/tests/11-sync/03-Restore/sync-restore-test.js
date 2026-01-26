import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import path from 'node:path';
import {
  ADMIN_USER,
  ADMIN_API_TOKEN,
  createHttpClient,
  DATA_FILE_TEST,
  executeExternalQuery,
  FIFTEEN_MINUTES,
  SYNC_LIVE_EVENTS_SIZE,
  SYNC_RESTORE_START_REMOTE_URI,
  SYNC_TEST_REMOTE_URI,
  testContext,
} from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';
import { checkPostSyncContent, checkPreSyncContent, REPORT_QUERY, UPLOADED_FILE_SIZE } from '../sync-utils';

const backupFiles = async () => {
  const BACKUP_CONFIG = {
    opencti: {
      url: SYNC_TEST_REMOTE_URI,
      token: ADMIN_API_TOKEN,
    },
    connector: {
      id: uuidv4(),
      type: 'STREAM',
      live_stream_id: 'live',
      name: 'BackupFiles',
      scope: 'backup',
      confidence_level: 15,
      log_level: 'info',
    },
    backup: {
      protocol: 'local',
      path: path.resolve('tests'),
    },
  };
  const backupConf = JSON.stringify(BACKUP_CONFIG);
  await execChildPython(
    testContext,
    ADMIN_USER,
    path.resolve('../../opencti-connectors/stream/backup-files/src'),
    'backup-files.py',
    [backupConf],
    (last, messages) => {
      const eventsMessage = messages.filter((m) => m.includes('processed event'));
      return eventsMessage.length === SYNC_LIVE_EVENTS_SIZE;
    }
  );
};
const restoreFile = async () => {
  const RESTORE_CONFIG = {
    opencti: {
      url: SYNC_RESTORE_START_REMOTE_URI,
      token: ADMIN_API_TOKEN,
    },
    connector: {
      id: uuidv4(),
      type: 'EXTERNAL_IMPORT',
      name: 'RestoreFiles',
      scope: 'restore',
      confidence_level: 15,
      log_level: 'info',
    },
    backup: {
      protocol: 'local',
      direct_creation: true,
      path: path.resolve('tests'),
    },
  };
  const restoreConf = JSON.stringify(RESTORE_CONFIG);
  await execChildPython(
    testContext,
    ADMIN_USER,
    path.resolve('../../opencti-connectors/external-import/restore-files/src'),
    'restore-files.py',
    [restoreConf],
    (message) => message.includes('restore run completed')
  );
};

describe('Database sync backup/restore', () => {
  it(
    'Should backup/restore sync succeed',
    async () => {
      const client = createHttpClient();
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Create the backup
      await backupFiles();
      // Restore the backup
      await restoreFile();
      // Post check
      await checkPostSyncContent(SYNC_RESTORE_START_REMOTE_URI, objectMap, relMap, initStixReport);
      // Check file availability
      const reportData = await executeExternalQuery(client, SYNC_RESTORE_START_REMOTE_URI, REPORT_QUERY, {
        id: 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7',
      });
      const files = reportData.report.importFiles.edges;
      expect(files.length).toEqual(1);
      const uploadedFile = R.head(files).node;
      expect(uploadedFile.name).toEqual(DATA_FILE_TEST);
      expect(uploadedFile.size).toEqual(UPLOADED_FILE_SIZE);
    },
    FIFTEEN_MINUTES
  );
});
