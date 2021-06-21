/* eslint-disable prettier/prettier */
import platformInit from '../../../src/initialization';
import { FIVE_MINUTES, PYTHON_PATH, API_TOKEN, API_URI } from '../../utils/testQuery';
import { execPython3 } from '../../../src/python/pythonBridge';
import { startModules, shutdownModules } from "../../../src/modules";
import { SYSTEM_USER } from "../../../src/utils/access";
import { createEntity } from "../../../src/database/middleware";
import { ENTITY_TYPE_RULE } from "../../../src/schema/internalObject";

describe('Database provision', () => {
  // eslint-disable-next-line no-unused-vars
  const activateRule = (ruleId) => {
    return createEntity(SYSTEM_USER, { internal_id: ruleId, active: true }, ENTITY_TYPE_RULE);
  }
  const importOpts = [API_URI, API_TOKEN, '/tests/data/DATA-TEST-STIX2_v2.json'];
  it(
    'should platform init',
    () => {
      return expect(platformInit(true)).resolves.toBe(true);
    },
    FIVE_MINUTES
  );
  it(
    'Should import creation succeed',
    async () => {
      // Start platform
      await startModules();
      // Activate rules
      // await activateRule('location_targets');
      // Start import
      const execution = await execPython3(PYTHON_PATH, 'local_importer.py', importOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
    },
    FIVE_MINUTES
  );
  // Python lib is fixed but we need to wait for a new release
  it(
    'Should import update succeed',
    async () => {
      await startModules();
      const execution = await execPython3(PYTHON_PATH, 'local_importer.py', importOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
