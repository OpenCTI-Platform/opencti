/* eslint-disable function-paren-newline */
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, ADMIN_API_TOKEN, API_URI, FIVE_MINUTES, PYTHON_PATH, testContext } from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';

const importOpts: string[] = [API_URI, ADMIN_API_TOKEN, './tests/data/DATA-TEST-STIX2_v2.json'];

describe('Database provision', () => {
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
