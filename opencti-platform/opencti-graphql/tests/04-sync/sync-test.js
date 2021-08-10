import platformInit from '../../src/initialization';
import { ADMIN_USER, API_URI, FIVE_MINUTES, PYTHON_PATH } from '../utils/testQuery';
import { elDeleteIndexes } from '../../src/database/elasticSearch';
import { shutdownModules, startModules } from '../../src/modules';
import { execPython3 } from '../../src/python/pythonBridge';
import { addUser } from '../../src/domain/user';
import { ROLE_ADMINISTRATOR } from '../../src/utils/access';
import { SYNC_USER_EMAIL, SYNC_USER_TOKEN } from '../../src/database/utils';

describe('Database provision', () => {
  // eslint-disable-next-line prettier/prettier
  it.skip('should platform init', async () => {
      await elDeleteIndexes(['opencti_*']);
      const init = await platformInit();
      expect(init).toBeTruthy();
      // Ensure the sync specific user exists
      await addUser(ADMIN_USER, {
        name: 'sync-user',
        user_email: SYNC_USER_EMAIL,
        api_token: SYNC_USER_TOKEN,
        roles: [ROLE_ADMINISTRATOR],
      });
    },
    FIVE_MINUTES
  );

  const syncOpts = [API_URI, SYNC_USER_TOKEN];
  // eslint-disable-next-line prettier/prettier
  it.skip('Should sync succeed', async () => {
      await startModules();
      const execution = await execPython3(PYTHON_PATH, 'local_synchronizer.py', syncOpts);
      // Execution of the script will create a connector
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
      // Remove the connector
      // TODO
    },
    FIVE_MINUTES
  );
});
