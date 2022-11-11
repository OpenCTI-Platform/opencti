import { beforeAll, afterAll, vi } from 'vitest';
import cacheManager from '../../src/manager/cacheManager';
import { initializeSession } from '../../src/database/session';

vi.mock('../../src/database/migration', () => ({
  applyMigration: () => Promise.resolve(),
  lastAvailableMigrationTime: () => new Date().getTime()
}));

beforeAll(async () => {
  initializeSession();
  await cacheManager.start();
});

afterAll(async () => {
  await cacheManager.shutdown();
});
