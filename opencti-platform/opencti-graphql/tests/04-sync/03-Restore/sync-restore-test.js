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
import { logApp } from '../../../src/config/conf';

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
  const scriptPath = path.resolve('../../opencti-connectors/stream/backup-files/src');
  const scriptName = 'backup-files.py';

  logApp.info('[TEST] Starting backup', {
    config: BACKUP_CONFIG,
    scriptPath,
    scriptName
  });

  try {
    await execChildPython(
      testContext,
      ADMIN_USER,
      scriptPath,
      scriptName,
      [backupConf],
      (last, messages) => {
        const eventsMessage = messages.filter((m) => m.includes('processed event'));
        const progress = eventsMessage.length;
        logApp.info(`[TEST] Backup progress: ${progress}/${SYNC_LIVE_EVENTS_SIZE}`, {
          progress,
          total: SYNC_LIVE_EVENTS_SIZE,
          lastMessage: last
        });
        return eventsMessage.length === SYNC_LIVE_EVENTS_SIZE;
      }
    );
    logApp.info('[TEST] Backup completed successfully');
  } catch (error) {
    logApp.error('[TEST] Backup failed', {
      errorMessage: error.message,
      errorStack: error.stack,
      scriptPath,
      scriptName,
      config: BACKUP_CONFIG
    });
    throw error;
  }
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
  const scriptPath = path.resolve('../../opencti-connectors/external-import/restore-files/src');
  const scriptName = 'restore-files.py';

  logApp.info('[TEST] Starting restore', {
    config: RESTORE_CONFIG,
    scriptPath,
    scriptName
  });

  try {
    await execChildPython(
      testContext,
      ADMIN_USER,
      scriptPath,
      scriptName,
      [restoreConf],
      (message) => {
        logApp.info('[TEST] Restore message', { message });
        return message.includes('restore run completed');
      }
    );
    logApp.info('[TEST] Restore completed successfully');
  } catch (error) {
    logApp.error('[TEST] Restore failed', {
      errorMessage: error.message,
      errorStack: error.stack,
      scriptPath,
      scriptName,
      config: RESTORE_CONFIG
    });
    throw error;
  }
};

describe('Database sync backup/restore', () => {
  it(
    'Should backup/restore sync succeed',
    async () => {
      logApp.info('[TEST] ========== SYNC RESTORE TEST STARTED ==========', {
        timestamp: new Date().toISOString(),
        environment: {
          NODE_ENV: process.env.NODE_ENV,
          DEBUG_PYTHON: process.env.DEBUG_PYTHON,
          PYTHON_EXECUTOR: process.env.PYTHON_EXECUTOR
        }
      });
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
