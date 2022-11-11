import { describe, expect, it } from 'vitest';
import { ADMIN_USER, API_TOKEN, API_URI, FIVE_MINUTES, PYTHON_PATH, testContext } from '../../utils/testQuery';
import { execChildPython } from '../../../src/python/pythonBridge';
import { shutdownModules, startModules } from '../../../src/modules';
import { elDeleteIndexes } from '../../../src/database/engine';
import { ELASTIC_CREATION_PATTERN } from '../../../src/config/conf';
import { WRITE_PLATFORM_INDICES } from '../../../src/database/utils';
import platformInit from '../../../src/initialization';
import { deleteStream } from '../../../src/database/redis';
import { deleteQueues } from '../../../src/domain/connector';
import { deleteBucket } from '../../../src/database/file-storage';

describe('Database provision', () => {
  const importOpts = [API_URI, API_TOKEN, './tests/data/DATA-TEST-STIX2_v2.json'];
  it(
    'should platform init',
    async () => {
      // Platform cleanup before executing tests
      // Delete the bucket
      await deleteBucket();
      // Delete all rabbitmq queues
      await deleteQueues(testContext, ADMIN_USER);
      // Remove all elastic indices
      await elDeleteIndexes(WRITE_PLATFORM_INDICES.map((id) => `${id}${ELASTIC_CREATION_PATTERN}`));
      // Delete redis streams
      await deleteStream();
      // Starting test with simple platform initialization
      return expect(platformInit()).resolves.toBe(true);
    },
    FIVE_MINUTES
  );
  it(
    'Should import creation succeed',
    async () => {
      await startModules();
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts);
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
      const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_importer.py', importOpts);
      expect(execution).not.toBeNull();
      expect(execution.status).toEqual('success');
      await shutdownModules();
    },
    FIVE_MINUTES
  );
});
