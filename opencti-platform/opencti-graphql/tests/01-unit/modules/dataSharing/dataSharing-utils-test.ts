import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { resolvePublicUser } from '../../../../src/modules/dataSharing/dataSharing-utils';

vi.mock('../../../../src/database/cache');
vi.mock('../../../../src/database/redis');
vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

describe('resolvePublicUser', () => {
  const mockContext = { source: 'testing' } as any;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return SYSTEM_USER when userId is null', async () => {
    const result = await resolvePublicUser(mockContext, null);
    expect(result).toBe(SYSTEM_USER);
  });

  it('should return SYSTEM_USER when userId is undefined', async () => {
    const result = await resolvePublicUser(mockContext, undefined);
    expect(result).toBe(SYSTEM_USER);
  });

  it('should throw FunctionalError when userId is an internal system user id', async () => {
    const internalUserId = SYSTEM_USER.id; // '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
    await expect(resolvePublicUser(mockContext, internalUserId))
      .rejects.toThrow('Cannot use an internal system user for public sharing');
  });

  it('should throw FunctionalError when user no longer exists in the platform cache', async () => {
    const nonExistentUserId = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);

    await expect(resolvePublicUser(mockContext, nonExistentUserId))
      .rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should return the resolved user when found in the platform cache', async () => {
    const realUserId = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';
    const mockUser = { id: realUserId, name: 'Real User' } as any;
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[realUserId, mockUser]]) as any);

    const result = await resolvePublicUser(mockContext, realUserId);
    expect(result).toBe(mockUser);
  });
});
