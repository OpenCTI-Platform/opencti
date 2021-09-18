import {
  ADMIN_USER,
  API_TOKEN,
  API_URI,
  executeExternalQuery,
  FIFTEEN_MINUTES,
  PYTHON_PATH,
  SYNC_LIVE_START_REMOTE_URI,
  SYNC_RAW_START_REMOTE_URI,
} from '../utils/testQuery';
import { elAggregationCount } from '../../src/database/elasticSearch';
import { execPython3 } from '../../src/python/pythonBridge';
import { fullLoadById } from '../../src/database/middleware';
import { buildStixData } from '../../src/database/stix';
import { checkInstanceDiff } from '../utils/testStream';
import { shutdownModules, startModules } from '../../src/modules';
import { FROM_START_STR } from '../../src/utils/format';

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

describe('Database provision', () => {
  const checkPreSyncContent = async () => {
    const initObjectAggregation = await elAggregationCount(ADMIN_USER, 'Stix-Object', 'entity_type');
    const objectMap = new Map(initObjectAggregation.map((i) => [i.label, i.value]));
    expect(objectMap.get('Indicator')).toEqual(28);
    expect(objectMap.get('Malware')).toEqual(27);
    expect(objectMap.get('Label')).toEqual(13);
    // Relations
    const initRelationAggregation = await elAggregationCount(ADMIN_USER, 'stix-relationship', 'entity_type');
    const relMap = new Map(initRelationAggregation.map((i) => [i.label, i.value]));
    expect(relMap.get('Object')).toEqual(191);
    expect(relMap.get('Indicates')).toEqual(59);
    expect(relMap.get('Uses')).toEqual(28);
    // Report content
    const initReport = await fullLoadById(ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
    const initStixReport = buildStixData(initReport);
    return { objectMap, relMap, initStixReport };
  };
  const checkMapConsistency = (before, after) => {
    after.forEach((value, key) => {
      const compareValue = before.get(key);
      expect(compareValue).toEqual(value);
    });
  };
  const checkPostSyncContent = async (remoteUri, objectMap, relMap, initStixReport) => {
    const data = await executeExternalQuery(remoteUri, STAT_QUERY);
    const { objects, relationships } = data.about.debugStats;
    const syncObjectMap = new Map(objects.map((i) => [i.label, i.value]));
    const syncRelMap = new Map(relationships.map((i) => [i.label, i.value]));
    checkMapConsistency(objectMap, syncObjectMap);
    checkMapConsistency(relMap, syncRelMap);
    const reportData = await executeExternalQuery(remoteUri, REPORT_QUERY, {
      id: 'report--f2b63e80-b523-4747-a069-35c002c690db',
    });
    const stixReport = JSON.parse(reportData.report.toStix);
    const idLoader = async (user, id) => {
      const dataId = await executeExternalQuery(remoteUri, STANDARD_LOADER_QUERY, { id });
      return dataId.stixObjectOrStixRelationship;
    };
    const diffElements = await checkInstanceDiff(initStixReport, stixReport, idLoader);
    expect(diffElements.length).toBe(0);
  };

  // eslint-disable-next-line prettier/prettier
  it('Should raw sync succeed', async () => {
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Sync
      await startModules();
      const syncOpts = [API_URI, API_TOKEN, SYNC_RAW_START_REMOTE_URI, API_TOKEN, 421, '0'];
      const execution = await execPython3(PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
      // Post check
      await checkPostSyncContent(SYNC_RAW_START_REMOTE_URI, objectMap, relMap, initStixReport);
    },
    FIFTEEN_MINUTES
  );

  // eslint-disable-next-line prettier/prettier
  it('Should live sync succeed', async () => {
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Sync
      const syncOpts = [API_URI, API_TOKEN, SYNC_LIVE_START_REMOTE_URI, API_TOKEN, 239, FROM_START_STR, 'live'];
      await startModules();
      const execution = await execPython3(PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
      // Post check
      await checkPostSyncContent(SYNC_LIVE_START_REMOTE_URI, objectMap, relMap, initStixReport);
    },
    FIFTEEN_MINUTES
  );
});
