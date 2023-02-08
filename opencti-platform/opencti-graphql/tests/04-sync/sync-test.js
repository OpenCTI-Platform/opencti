import { expect, it, describe } from 'vitest';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { createReadStream } from 'fs';
import path from 'path';
import {
  ADMIN_USER,
  API_TOKEN,
  API_URI,
  createHttpClient,
  DATA_FILE_TEST,
  executeExternalQuery,
  FIFTEEN_MINUTES,
  PYTHON_PATH,
  RAW_EVENTS_SIZE,
  SYNC_DIRECT_START_REMOTE_URI,
  SYNC_LIVE_EVENTS_SIZE,
  SYNC_LIVE_START_REMOTE_URI,
  SYNC_RAW_START_REMOTE_URI,
  SYNC_RESTORE_START_REMOTE_URI,
  SYNC_TEST_REMOTE_URI,
  testContext,
} from '../utils/testQuery';
import { elAggregationCount } from '../../src/database/engine';
import { execChildPython } from '../../src/python/pythonBridge';
import { checkInstanceDiff } from '../utils/testStream';
import { FROM_START, now } from '../../src/utils/format';
import { SYSTEM_USER } from '../../src/utils/access';
import { stixCoreObjectImportPush } from '../../src/domain/stixCoreObject';
import { convertStoreToStix } from '../../src/database/stix-converter';
import { READ_DATA_INDICES, wait } from '../../src/database/utils';
import { storeLoadByIdWithRefs } from '../../src/database/middleware';
import { logAudit } from '../../src/config/conf';

const STAT_QUERY = `query stats {
      about {
        debugStats {
          objects {
            label
            value
          }
          relationships {
            label
            value
          }
        }
      }
    }
  `;
const REPORT_QUERY = `query report($id: String) {
      report(id: $id) {
        toStix
        importFiles {
          edges {
            node {
              id
              name
              size
            }
          }
        }
      }
    }
  `;
const STANDARD_LOADER_QUERY = `query standard($id: String!) {
      stixObjectOrStixRelationship(id: $id) {
        ... on StixObject {
          standard_id
        }
        ... on StixRelationship {
          standard_id
        }
      }
    }
  `;
const SYNC_CREATION_QUERY = `mutation SynchronizerAdd($input: SynchronizerAddInput) {
      synchronizerAdd(input: $input) {
        id
      }
    }
  `;
const SYNC_START_QUERY = `mutation SynchronizerStart($id: ID!) {
      synchronizerStart(id: $id) {
        id
      }
    }
  `;

const UPLOADED_FILE_SIZE = 35514;

describe('Database sync testing', () => {
  const checkPreSyncContent = async () => {
    const initObjectAggregation = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['Stix-Object'], field: 'entity_type' });
    const objectMap = new Map(initObjectAggregation.map((i) => [i.label, i.value]));
    expect(objectMap.get('Indicator')).toEqual(28);
    expect(objectMap.get('Malware')).toEqual(27);
    expect(objectMap.get('Label')).toEqual(13);
    expect(objectMap.get('Vocabulary')).toEqual(263);
    // Relations
    const initRelationAggregation = await elAggregationCount(testContext, ADMIN_USER, READ_DATA_INDICES, { types: ['stix-relationship'], field: 'entity_type' });
    const relMap = new Map(initRelationAggregation.map((i) => [i.label, i.value]));
    expect(relMap.get('Object')).toEqual(191);
    expect(relMap.get('Indicates')).toEqual(59);
    expect(relMap.get('Uses')).toEqual(28);
    // Report content
    const initReport = await storeLoadByIdWithRefs(testContext, ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
    const initStixReport = convertStoreToStix(initReport);
    return { objectMap, relMap, initStixReport };
  };
  const checkMapConsistency = (before, after) => {
    after.forEach((value, key) => {
      const compareValue = before.get(key);
      expect(`${key} - ${value}`).toEqual(`${key} - ${compareValue}`);
    });
  };
  const checkPostSyncContent = async (remoteUri, objectMap, relMap, initStixReport) => {
    const client = createHttpClient();
    const data = await executeExternalQuery(client, remoteUri, STAT_QUERY);
    const { objects, relationships } = data.about.debugStats;
    const syncObjectMap = new Map(objects.map((i) => [i.label, i.value]));
    const syncRelMap = new Map(relationships.map((i) => [i.label, i.value]));
    checkMapConsistency(objectMap, syncObjectMap);
    checkMapConsistency(relMap, syncRelMap);
    const reportData = await executeExternalQuery(client, remoteUri, REPORT_QUERY, {
      id: 'report--f2b63e80-b523-4747-a069-35c002c690db',
    });
    const stixReport = JSON.parse(reportData.report.toStix);
    const idLoader = async (context, user, id) => {
      const dataId = await executeExternalQuery(client, remoteUri, STANDARD_LOADER_QUERY, { id });
      return dataId.stixObjectOrStixRelationship;
    };
    const diffElements = await checkInstanceDiff(initStixReport, stixReport, idLoader);
    if (diffElements.length > 0) {
      logAudit.info(JSON.stringify(diffElements));
    }
    expect(diffElements.length).toBe(0);
  };

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

  it(
    'Should python live sync succeed',
    async () => {
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Sync
      const syncOpts = [
        API_URI,
        API_TOKEN,
        SYNC_LIVE_START_REMOTE_URI,
        API_TOKEN,
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

  it(
    'Should direct sync succeed',
    async () => {
      const client = createHttpClient();
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Upload a file
      const file = {
        createReadStream: () => createReadStream('./tests/data/DATA-TEST-STIX2_v2.json'),
        filename: DATA_FILE_TEST,
        mimetype: 'application/json',
      };
      await stixCoreObjectImportPush(testContext, SYSTEM_USER, 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7', file);
      // Need to create the synchronizer on the remote host
      const SYNC_CREATE = {
        input: {
          name: 'SYNC',
          uri: SYNC_TEST_REMOTE_URI,
          listen_deletion: true,
          no_dependencies: false,
          stream_id: 'live',
          token: API_TOKEN,
        },
      };
      const synchronizer = await executeExternalQuery(client, SYNC_DIRECT_START_REMOTE_URI, SYNC_CREATION_QUERY, SYNC_CREATE);
      // Start the sync
      const syncId = synchronizer.synchronizerAdd.id;
      await executeExternalQuery(client, SYNC_DIRECT_START_REMOTE_URI, SYNC_START_QUERY, { id: syncId });
      // Wait 2 min sync to consume all the stream
      await wait(120000);
      // Post check
      await checkPostSyncContent(SYNC_DIRECT_START_REMOTE_URI, objectMap, relMap, initStixReport);
      // Check file availability
      const reportData = await executeExternalQuery(client, SYNC_DIRECT_START_REMOTE_URI, REPORT_QUERY, {
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

  const backupFiles = async () => {
    const BACKUP_CONFIG = {
      opencti: {
        url: SYNC_TEST_REMOTE_URI,
        token: API_TOKEN,
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
        token: API_TOKEN,
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
