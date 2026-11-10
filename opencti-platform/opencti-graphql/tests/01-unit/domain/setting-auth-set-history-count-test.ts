import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => true),
}));
vi.mock('../../../src/database/middleware', () => ({ loadEntity: vi.fn(), patchAttribute: vi.fn() }));
vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  notify: vi.fn(),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../src/modules/user/user-password-history', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/user/user-password-history')>()),
  trimAllUsersPasswordHistory: vi.fn(),
}));
vi.mock('../../../src/utils/access', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/utils/access')>()),
  isUserHasCapability: vi.fn(() => true),
}));

import { isFeatureEnabled } from '../../../src/config/conf';
import { loadEntity, patchAttribute } from '../../../src/database/middleware';
import { notify } from '../../../src/database/redis';
import { publishUserAction } from '../../../src/listener/UserActionListener';
import { trimAllUsersPasswordHistory } from '../../../src/modules/user/user-password-history';
import { isUserHasCapability } from '../../../src/utils/access';
import { setPasswordHistoryCount } from '../../../src/domain/setting-auth';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;

describe('setPasswordHistoryCount (configuration import)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    vi.mocked(isUserHasCapability).mockReturnValue(true);
    vi.mocked(loadEntity).mockResolvedValue({ id: 'settings-id', password_policy_history_count: 5 } as never);
    vi.mocked(patchAttribute).mockResolvedValue({ element: { id: 'settings-id' } } as never);
  });

  it('writes the count alone, audits it and notifies the other nodes', async () => {
    await setPasswordHistoryCount(context, user, 8);
    expect(patchAttribute).toHaveBeenCalledWith(context, user, 'settings-id', 'Settings', { password_policy_history_count: 8 });
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({ message: 'updates `password_policy_history_count` for `platform settings`' }));
    expect(notify).toHaveBeenCalledTimes(1);
    expect(trimAllUsersPasswordHistory).not.toHaveBeenCalled();
  });

  it('trims the stored histories when the count goes down, as updateLocalAuth does, 0 included', async () => {
    await setPasswordHistoryCount(context, user, 2);
    expect(trimAllUsersPasswordHistory).toHaveBeenCalledWith(2);
    await setPasswordHistoryCount(context, user, 0);
    expect(trimAllUsersPasswordHistory).toHaveBeenCalledWith(0);
  });

  it('trims before saving the lower count, so that a failed trim leaves the count as it was and a retry trims again', async () => {
    await setPasswordHistoryCount(context, user, 2);
    expect(vi.mocked(trimAllUsersPasswordHistory).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(patchAttribute).mock.invocationCallOrder[0]);
    vi.mocked(patchAttribute).mockClear();
    vi.mocked(trimAllUsersPasswordHistory).mockRejectedValueOnce(new Error('Elasticsearch unavailable'));
    await expect(setPasswordHistoryCount(context, user, 2)).rejects.toThrow('Elasticsearch unavailable');
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(publishUserAction).toHaveBeenCalledTimes(1);
  });

  it('fails without writing when the platform settings cannot be read', async () => {
    vi.mocked(loadEntity).mockResolvedValue(undefined as never);
    await expect(setPasswordHistoryCount(context, user, 3)).rejects.toThrow('Cannot find the platform settings');
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(trimAllUsersPasswordHistory).not.toHaveBeenCalled();
  });

  it('needs the capability of updateLocalAuth, and writes nothing without it', async () => {
    vi.mocked(isUserHasCapability).mockReturnValue(false);
    await expect(setPasswordHistoryCount(context, user, 3)).rejects.toThrow();
    expect(isUserHasCapability).toHaveBeenCalledWith(user, 'SETTINGS_SETACCESSES');
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('validates like updateLocalAuth: out of range refused, and without the feature 0 is no change and any other count refused', async () => {
    await expect(setPasswordHistoryCount(context, user, 25)).rejects.toThrow('between 0 and 24');
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    await expect(setPasswordHistoryCount(context, user, 0)).resolves.toBeUndefined();
    await expect(setPasswordHistoryCount(context, user, 3)).rejects.toThrow('not available');
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(trimAllUsersPasswordHistory).not.toHaveBeenCalled();
  });
});
