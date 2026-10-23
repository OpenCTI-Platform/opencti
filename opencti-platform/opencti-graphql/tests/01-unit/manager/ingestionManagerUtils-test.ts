import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createIngestionLogger } from '../../../src/manager/ingestionManager/ingestionManagerUtils';
import { redisPushIngestionLog } from '../../../src/database/redis';

vi.mock('../../../src/database/redis', () => ({ redisPushIngestionLog: vi.fn() }));

describe('createIngestionLogger', () => {
  beforeEach(() => {
    vi.mocked(redisPushIngestionLog).mockReset().mockResolvedValue(undefined);
  });

  it('should not make the outcome strict by default: a failure to record it is only logged by the redis layer', async () => {
    await createIngestionLogger('sync-id', 'sync', 'sync').success('Feed execution succeeded');
    expect(redisPushIngestionLog).toHaveBeenCalledWith('sync-id', expect.objectContaining({ level: 'success' }), undefined);
  });

  it('should hand the strict outcome option to the redis layer, and let its rejection reach the caller to retry', async () => {
    vi.mocked(redisPushIngestionLog).mockRejectedValueOnce(new Error('redis unavailable'));
    const logger = createIngestionLogger('sync-id', 'sync', 'sync');
    await expect(logger.success('Feed execution succeeded', {}, { strictOutcome: true })).rejects.toThrow('redis unavailable');
    await expect(logger.success('Feed execution succeeded', {}, { strictOutcome: true })).resolves.toBeUndefined();
    expect(redisPushIngestionLog).toHaveBeenCalledTimes(2);
    expect(redisPushIngestionLog).toHaveBeenLastCalledWith('sync-id', expect.objectContaining({ level: 'success' }), { strictOutcome: true });
  });
});
