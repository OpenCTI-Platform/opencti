import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, API_URI, createUnauthenticatedClient, executeExternalQuery, testContext } from '../../utils/testQuery';
import { findUserSessions, killUserSessions } from '../../../src/database/session';
import { addUser, findById, meEditField, userDelete } from '../../../src/modules/user/user-domain';
import { getSettingsFromDatabase } from '../../../src/domain/settings';
import { updateLocalAuth } from '../../../src/domain/setting-auth';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { AuthContext } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';

const EMAIL = 'forced.change.history@opencti.invalid';
const CURRENT_PASSWORD = 'Forced-Change-1!';

// A real login through the API, so that the session lands in the shared session store
const login = async () => {
  const client = createUnauthenticatedClient();
  await executeExternalQuery(client, `${API_URI}/graphql`, 'mutation ($input: UserLoginInput) { token(input: $input) }', {
    input: { email: EMAIL, password: CURRENT_PASSWORD },
  });
};

describe('Forced password change with password history', () => {
  let settings: BasicStoreSettings;
  let userId: string;

  // Only the history count is sent, so the other local policies stay as they are
  const setHistoryCount = (count: number) => updateLocalAuth(testContext, ADMIN_USER, settings.id, { enabled: true, password_policy_history_count: count });

  beforeAll(async () => {
    settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
    const user = await addUser(testContext, ADMIN_USER, { name: 'Forced change history', user_email: EMAIL, password: CURRENT_PASSWORD } as any);
    userId = user.id;
    await setHistoryCount(1);
    await login();
    // The login mutation accepts one call per second
    await new Promise((resolve) => {
      setTimeout(resolve, 1100);
    });
    await login();
  });

  afterAll(async () => {
    await killUserSessions(userId);
    await setHistoryCount(0);
    await userDelete(testContext, ADMIN_USER, userId);
  });

  it('keeps the other sessions when the new password is refused, and ends them once it is saved', async () => {
    const sessions = await findUserSessions(userId);
    expect(sessions).toHaveLength(2);
    const [current] = sessions;
    // The change comes from one of the two sessions; the other one is the session to end
    const context = { ...testContext, req: { session: { id: current.id } } } as unknown as AuthContext;
    const expired = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const expiredUser = { ...(await findById(testContext, SYSTEM_USER, userId)), password_valid_until: expired };

    await expect(meEditField(context, expiredUser, userId, [{ key: 'password', value: [CURRENT_PASSWORD] }]))
      .rejects.toMatchObject({ extensions: { code: 'PASSWORD_REUSED' } });
    expect(await findUserSessions(userId)).toHaveLength(2);

    await meEditField(context, expiredUser, userId, [{ key: 'password', value: ['Forced-Change-2!'] }]);
    expect((await findUserSessions(userId)).map((s: { id: string }) => s.id)).toEqual([current.id]);
  });
});
