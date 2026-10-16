import { describe, expect, it, vi } from 'vitest';
import { killSession } from '../../../src/database/redis';
import RedisStore from '../../../src/database/sessionStore-redis';

vi.mock('../../../src/database/redis', () => ({
  clearSessions: vi.fn(),
  extendSession: vi.fn(),
  getSession: vi.fn(),
  getSessionKeys: vi.fn(),
  getSessions: vi.fn(),
  getSessionTtl: vi.fn(),
  killSession: vi.fn(),
  setSession: vi.fn(),
}));

describe('RedisStore destroy', () => {
  const store = new RedisStore({ ttl: 60000, prefix: 'sess:' });

  it('should call back with the killed session', async () => {
    vi.mocked(killSession).mockResolvedValueOnce({ sessionId: 'sess:sid', session: {} });
    const callback = vi.fn();
    await store.destroy('sid', callback);
    expect(killSession).toHaveBeenCalledWith('sess:sid');
    expect(callback).toHaveBeenCalledWith(null, { sessionId: 'sess:sid', session: {} });
  });

  it('should call back with the error when redis fails', async () => {
    const redisError = new Error('Redis unavailable');
    vi.mocked(killSession).mockRejectedValueOnce(redisError);
    const callback = vi.fn();
    await store.destroy('sid', callback);
    expect(callback).toHaveBeenCalledWith(redisError);
  });
});
