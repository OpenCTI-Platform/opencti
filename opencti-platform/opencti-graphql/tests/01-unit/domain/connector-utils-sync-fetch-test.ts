import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildSyncFetch, SYNC_RESOLUTION_TIMEOUT } from '../../../src/domain/connector-utils';

// A platform proxy: the destination is resolved by the platform before the request
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return { ...actual, getPlatformHttpProxyAgent: () => ({}) };
});
// A DNS resolution that never ends
vi.mock('../../../src/utils/internal-destination', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/utils/internal-destination')>();
  return { ...actual, checkUrlDestination: () => new Promise(() => {}) };
});

describe('buildSyncFetch destination check behind a proxy', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should stop waiting for the resolution when the stream is closed', async () => {
    const controller = new AbortController();
    const response = buildSyncFetch(true, undefined)('https://remote.opencti.example/stream/live', { headers: {}, signal: controller.signal });
    controller.abort(new Error('closed'));
    await expect(response).rejects.toThrow('closed');
  });

  it('should stop waiting for the resolution after a timeout', async () => {
    vi.useFakeTimers();
    const response = buildSyncFetch(true, undefined)('https://remote.opencti.example/stream/live', { headers: {} });
    const expectation = expect(response).rejects.toThrow(`Resolution of remote.opencti.example timed out after ${SYNC_RESOLUTION_TIMEOUT}ms`);
    await vi.advanceTimersByTimeAsync(SYNC_RESOLUTION_TIMEOUT);
    await expectation;
  });
});
