import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

// Watched rather than run: the test has no session store to look into
vi.mock('../../../src/database/session', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/session')>();
  return { ...actual, killOtherUserSessions: vi.fn(async () => []) };
});

import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { killOtherUserSessions } from '../../../src/database/session';
import { addUser, findById, meEditField, userDelete } from '../../../src/modules/user/user-domain';
import { getSettingsFromDatabase } from '../../../src/domain/settings';
import { updateLocalAuth } from '../../../src/domain/setting-auth';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { BasicStoreSettings } from '../../../src/types/settings';

describe('Forced password change with password history', () => {
  const currentPassword = 'Forced-Change-1!';
  let settings: BasicStoreSettings;
  let userId: string;

  // Only the history count is sent, so the other local policies stay as they are
  const setHistoryCount = (count: number) => updateLocalAuth(testContext, ADMIN_USER, settings.id, { enabled: true, password_policy_history_count: count });

  beforeAll(async () => {
    settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    const user = await addUser(testContext, ADMIN_USER, { name: 'Forced change history', user_email: 'forced.change.history@opencti.invalid', password: currentPassword } as any);
    userId = user.id;
    await setHistoryCount(1);
  });

  afterAll(async () => {
    await setHistoryCount(0);
    await userDelete(testContext, ADMIN_USER, userId);
  });

  it('keeps the other sessions when the new password is refused, and ends them once it is saved', async () => {
    const expired = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const expiredUser = { ...(await findById(testContext, SYSTEM_USER, userId)), password_valid_until: expired };

    await expect(meEditField(testContext, expiredUser, userId, [{ key: 'password', value: [currentPassword] }]))
      .rejects.toMatchObject({ extensions: { code: 'PASSWORD_REUSED' } });
    expect(killOtherUserSessions).not.toHaveBeenCalled();

    await meEditField(testContext, expiredUser, userId, [{ key: 'password', value: ['Forced-Change-2!'] }]);
    expect(killOtherUserSessions).toHaveBeenCalledWith(userId, undefined);
  });
});
