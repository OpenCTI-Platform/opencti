import { describe, expect, it } from 'vitest';
import { ADMIN_USER, ADMIN_API_TOKEN, API_URI, FIVE_MINUTES, PYTHON_PATH, testContext } from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';

const importOpts_1: string[] = [API_URI, ADMIN_API_TOKEN, './tests/data/DATA-TEST-STIX2_v2_part1.json'];
const importOpts_2: string[] = [API_URI, ADMIN_API_TOKEN, './tests/data/DATA-TEST-STIX2_v2_part2.json'];

describe('Database provision', () => {
  it('Should import creation succeed', async () => {
    const injectDataPart1 = async () => {
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts_1);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
    };

    const injectDataPart2 = async () => {
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts_2);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
    };

    await Promise.all([injectDataPart1, injectDataPart2]);
  }, FIVE_MINUTES);
  // Python lib is fixed but we need to wait for a new release
  it('Should import update succeed', async () => {
    const injectDataPart1 = async () => {
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts_1);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
    };

    const injectDataPart2 = async () => {
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts_2);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
    };
    await Promise.all([injectDataPart1, injectDataPart2]);
  }, FIVE_MINUTES);
});
