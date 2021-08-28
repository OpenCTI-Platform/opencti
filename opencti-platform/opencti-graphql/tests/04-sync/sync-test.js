import platformInit from '../../src/initialization';
import {
  ADMIN_USER,
  API_TOKEN,
  API_URI,
  executeExternalQuery,
  FIVE_MINUTES,
  PYTHON_PATH,
  SYNC_REMOTE_URI,
} from '../utils/testQuery';
import { elAggregationCount, elDeleteIndexes } from '../../src/database/elasticSearch';
import { execPython3 } from '../../src/python/pythonBridge';
import { addUser } from '../../src/domain/user';
import { ROLE_ADMINISTRATOR } from '../../src/utils/access';
import { ES_INDEX_PREFIX, SYNC_USER_EMAIL, SYNC_USER_TOKEN } from '../../src/database/utils';
import { fullLoadById } from '../../src/database/middleware';
import { buildStixData } from '../../src/database/stix';
import { checkInstanceDiff } from '../utils/testStream';
import { createStreamCollection, streamCollectionDelete } from '../../src/domain/stream';
import { shutdownModules, startModules } from '../../src/modules';

describe('Database provision', () => {
  const platformReset = async () => {
    await elDeleteIndexes([`${ES_INDEX_PREFIX}*`]);
    const init = await platformInit(false);
    expect(init).toBeTruthy();
    // Ensure the sync specific user exists
    await addUser(ADMIN_USER, {
      name: 'sync-user',
      user_email: SYNC_USER_EMAIL,
      api_token: SYNC_USER_TOKEN,
      roles: [ROLE_ADMINISTRATOR],
    });
  };
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
  const checkPostSyncContent = async (objectMap, relMap, initStixReport) => {
    // Objects
    const objectAggregation = await elAggregationCount(ADMIN_USER, 'Stix-Object', 'entity_type');
    const syncObjectMap = new Map(objectAggregation.map((i) => [i.label, i.value]));
    checkMapConsistency(objectMap, syncObjectMap);
    // Relations
    const relationAggregation = await elAggregationCount(ADMIN_USER, 'stix-relationship', 'entity_type');
    const syncRelMap = new Map(relationAggregation.map((i) => [i.label, i.value]));
    checkMapConsistency(relMap, syncRelMap);
    // Report check
    const report = await fullLoadById(ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
    const stixReport = buildStixData(report);
    const diffElements = await checkInstanceDiff(initStixReport, stixReport);
    expect(diffElements.length).toBe(0);
  };

  // eslint-disable-next-line prettier/prettier
  it('Should raw sync succeed', async () => {
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      await platformReset();
      // Sync
      await startModules();
      const syncOpts = [API_URI, SYNC_USER_TOKEN, API_URI, SYNC_USER_TOKEN, 611];
      const execution = await execPython3(PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
      // Post check
      await checkPostSyncContent(objectMap, relMap, initStixReport);
    },
    FIVE_MINUTES
  );

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
  // eslint-disable-next-line prettier/prettier
  it('Should live sync succeed', async () => {
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Create live stream
      const stream = await createStreamCollection(ADMIN_USER, {
        name: 'Live sync',
        description: 'Global live stream',
        filters: '{}',
      });
      // Sync
      const syncOpts = [API_URI, SYNC_USER_TOKEN, SYNC_REMOTE_URI, API_TOKEN, 239, stream.id];
      await startModules();
      const execution = await execPython3(PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
      // Delete live stream
      await streamCollectionDelete(ADMIN_USER, stream.id);
      // Post check
      const data = await executeExternalQuery(SYNC_REMOTE_URI, STAT_QUERY);
      const { objects, relationships } = data.about.debugStats;
      const syncObjectMap = new Map(objects.map((i) => [i.label, i.value]));
      const syncRelMap = new Map(relationships.map((i) => [i.label, i.value]));
      checkMapConsistency(objectMap, syncObjectMap);
      checkMapConsistency(relMap, syncRelMap);
      const reportData = await executeExternalQuery(SYNC_REMOTE_URI, REPORT_QUERY, {
        id: 'report--f2b63e80-b523-4747-a069-35c002c690db',
      });
      const stixReport = JSON.parse(reportData.report.toStix);
      const idLoader = async (user, id) => {
        const dataId = await executeExternalQuery(SYNC_REMOTE_URI, STANDARD_LOADER_QUERY, { id });
        return dataId.stixObjectOrStixRelationship;
      };
      const diffElements = await checkInstanceDiff(initStixReport, stixReport, idLoader);
      expect(diffElements.length).toBe(0);
    },
    FIVE_MINUTES
  );
});
