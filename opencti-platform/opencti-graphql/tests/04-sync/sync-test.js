import platformInit from '../../src/initialization';
import { ADMIN_USER, API_URI, FIVE_MINUTES, PYTHON_PATH } from '../utils/testQuery';
import { elAggregationCount, elDeleteIndexes } from '../../src/database/elasticSearch';
import { shutdownModules, startModules } from '../../src/modules';
import { execPython3 } from '../../src/python/pythonBridge';
import { addUser } from '../../src/domain/user';
import { ROLE_ADMINISTRATOR } from '../../src/utils/access';
import { SYNC_USER_EMAIL, SYNC_USER_TOKEN } from '../../src/database/utils';
import { fullLoadById } from '../../src/database/middleware';
import { buildStixData } from '../../src/database/stix';
import { checkInstanceDiff } from '../utils/testStream';

describe('Database provision', () => {
  const syncOpts = [API_URI, SYNC_USER_TOKEN, 611];
  // eslint-disable-next-line prettier/prettier
  it('Should sync succeed', async () => {
      // Objects
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
      // region sync
      // Reset
      await elDeleteIndexes(['opencti_*']);
      const init = await platformInit(false);
      expect(init).toBeTruthy();
      // Ensure the sync specific user exists
      await addUser(ADMIN_USER, {
        name: 'sync-user',
        user_email: SYNC_USER_EMAIL,
        api_token: SYNC_USER_TOKEN,
        roles: [ROLE_ADMINISTRATOR],
      });
      await startModules();
      const execution = await execPython3(PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
      // endregion
      // Objects
      const objectAggregation = await elAggregationCount(ADMIN_USER, 'Stix-Object', 'entity_type');
      const syncObjectMap = new Map(objectAggregation.map((i) => [i.label, i.value]));
      syncObjectMap.forEach((value, key) => {
        const compareValue = objectMap.get(key);
        expect(compareValue).toEqual(value);
      });
      // Relations
      const relationAggregation = await elAggregationCount(ADMIN_USER, 'stix-relationship', 'entity_type');
      const syncRelMap = new Map(relationAggregation.map((i) => [i.label, i.value]));
      syncRelMap.forEach((value, key) => {
        const compareValue = relMap.get(key);
        expect(compareValue).toEqual(value);
      });
      // Report check
      const report = await fullLoadById(ADMIN_USER, 'report--f2b63e80-b523-4747-a069-35c002c690db');
      const stixReport = buildStixData(report);
      const diffElements = await checkInstanceDiff(initStixReport, stixReport);
      expect(diffElements.length).toBe(0);
    },
    FIVE_MINUTES
  );
});
