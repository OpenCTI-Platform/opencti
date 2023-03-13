/* eslint-disable function-paren-newline */
import { describe, expect, it } from 'vitest';
import {
  ADMIN_USER,
  API_TOKEN,
  API_URI,
  createUser,
  FIVE_MINUTES,
  PYTHON_PATH,
  testContext,
  USER_EDITOR,
  USER_PARTICIPATE
} from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';

const importOpts = [API_URI, API_TOKEN, './tests/data/DATA-TEST-STIX2_v2.json'];

describe('Database provision', () => {
  it('Should initialize default roles and users', async () => {
    // Create default groups / users / roles
    await createUser(USER_PARTICIPATE);
    await createUser(USER_EDITOR);
  }, FIVE_MINUTES);
  it('Should import creation succeed', async () => {
    // Inject data
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
  }, FIVE_MINUTES);
  // Python lib is fixed but we need to wait for a new release
  it('Should import update succeed', async () => {
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
  }, FIVE_MINUTES);
});
