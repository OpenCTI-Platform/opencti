import { beforeEach, describe, expect, it, vi } from 'vitest';
import { loadEntity, patchAttribute } from '../../../src/database/middleware';
import { getEntityFromCache } from '../../../src/database/cache';
import { isAdministrativeAccount } from '../../../src/domain/local-auth-lockout';
import { LOCAL_AUTH_LOCKOUT_DEFAULTS } from '../../../src/domain/local-auth-lockout-defaults';
import { LOCAL_AUTH_LOCKOUT_DURATION_LIMIT, LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT, LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT, updateLocalAuth } from '../../../src/domain/setting-auth';
import { LocalAuthLockoutFinalAction } from '../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { checkPolicyAcceptsAdminPassword } from '../../../src/modules/user/user-domain';

vi.mock('../../../src/database/middleware', () => ({
  loadEntity: vi.fn(async () => ({})),
  patchAttribute: vi.fn(async () => ({ element: { id: 'settings-id' } })),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({})),
}));

vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn(async (_topic: string, element: unknown) => element),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/modules/user/user-domain', () => ({
  checkPolicyAcceptsAdminPassword: vi.fn(),
  adjustAllUsersPasswordValidUntil: vi.fn(),
  clearAllUsersPasswordValidUntil: vi.fn(),
}));

const context = {} as AuthContext;
const user = { id: 'admin' } as AuthUser;
const LOCKOUT_INPUT = {
  local_auth_lockout_enabled: true,
  local_auth_lockout_max_attempts: 5,
  local_auth_lockout_admin_max_attempts: 3,
  local_auth_lockout_final_action: LocalAuthLockoutFinalAction.Permanent,
  local_auth_lockout_window: 60,
  local_auth_lockout_duration: 10, // minutes
};

// The lockout policy is validated against the settings stored in the database
const mockStoredSettings = (settings: Partial<BasicStoreSettings>) => vi.mocked(loadEntity).mockResolvedValue(settings as BasicStoreSettings);
const mockCachedSettings = (settings: Partial<BasicStoreSettings>) => vi.mocked(getEntityFromCache).mockResolvedValue(settings as BasicStoreSettings);
const patchSentToDatabase = () => vi.mocked(patchAttribute).mock.calls[0][4];

describe('updateLocalAuth - lockout policy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockStoredSettings({});
    mockCachedSettings({});
  });

  it('should patch the lockout policy', async () => {
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, ...LOCKOUT_INPUT });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, ...LOCKOUT_INPUT });
  });

  it('should patch the final action alone, checked against the stored policy', async () => {
    mockStoredSettings({ local_auth_lockout_max_attempts: 5, local_auth_lockout_duration: 60 });
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_final_action: LocalAuthLockoutFinalAction.Permanent });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, local_auth_lockout_final_action: LocalAuthLockoutFinalAction.Permanent });
  });

  it('should validate the input against the stored policy', async () => {
    mockStoredSettings({ local_auth_lockout_window: LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT + 1 });
    await expect(updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_duration: 60 }))
      .rejects.toThrowError(`Lockout window must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT}`);
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should validate the input against the database rather than a stale cache', async () => {
    mockCachedSettings({ local_auth_lockout_window: 60 });
    mockStoredSettings({ local_auth_lockout_window: LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT + 1 });
    await expect(updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_duration: 60 }))
      .rejects.toThrowError(`Lockout window must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT}`);
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should validate a null input against the default policy', async () => {
    mockStoredSettings({ local_auth_lockout_window: LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT + 1 });
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_duration: 60, local_auth_lockout_window: null });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, local_auth_lockout_duration: 60, local_auth_lockout_window: null });
  });

  it('should not check an invalid stored policy when the input leaves it untouched', async () => {
    mockStoredSettings({ local_auth_lockout_duration: LOCAL_AUTH_LOCKOUT_DURATION_LIMIT + 1 });
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, password_policy_min_length: 8 });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, password_policy_min_length: 8 });
  });

  it('should not check an invalid stored policy when the input disables the lockout', async () => {
    mockStoredSettings({ local_auth_lockout_duration: LOCAL_AUTH_LOCKOUT_DURATION_LIMIT + 1 });
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_enabled: false });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, local_auth_lockout_enabled: false });
  });

  it('should check the stored policy when the input enables the lockout', async () => {
    mockStoredSettings({ local_auth_lockout_duration: LOCAL_AUTH_LOCKOUT_DURATION_LIMIT + 1 });
    await expect(updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_enabled: true }))
      .rejects.toThrowError(`Lockout duration must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_DURATION_LIMIT}`);
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should accept a window of 0, which disables it', async () => {
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, ...LOCKOUT_INPUT, local_auth_lockout_window: 0 });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, ...LOCKOUT_INPUT, local_auth_lockout_window: 0 });
  });

  it.each([
    ['max attempts', { local_auth_lockout_max_attempts: LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT + 1 }, `Lockout max attempts must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT}`],
    ['admin max attempts', { local_auth_lockout_admin_max_attempts: LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT + 1 }, `Lockout admin max attempts must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT}`],
    ['window', { local_auth_lockout_window: LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT + 1 }, `Lockout window must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT}`],
    ['duration', { local_auth_lockout_duration: LOCAL_AUTH_LOCKOUT_DURATION_LIMIT + 1 }, `Lockout duration must be lower than or equal to ${LOCAL_AUTH_LOCKOUT_DURATION_LIMIT}`],
  ])('should reject a %s above its upper bound', async (_, lockoutInput, expectedMessage) => {
    await expect(updateLocalAuth(context, user, 'settings-id', { enabled: true, ...LOCKOUT_INPUT, ...lockoutInput }))
      .rejects.toThrowError(expectedMessage);
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should accept every value at its upper bound', async () => {
    const boundInput = {
      ...LOCKOUT_INPUT,
      local_auth_lockout_max_attempts: LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT,
      local_auth_lockout_admin_max_attempts: LOCAL_AUTH_LOCKOUT_MAX_ATTEMPTS_LIMIT,
      local_auth_lockout_window: LOCAL_AUTH_LOCKOUT_WINDOW_LIMIT,
      local_auth_lockout_duration: LOCAL_AUTH_LOCKOUT_DURATION_LIMIT,
    };
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, ...boundInput });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, ...boundInput });
  });

  it('should accept the default policy, which must stay within the upper bounds', async () => {
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, ...LOCAL_AUTH_LOCKOUT_DEFAULTS, local_auth_lockout_enabled: true });
    expect(patchAttribute).toHaveBeenCalled();
  });
});

describe('isAdministrativeAccount - lockout threshold', () => {
  const accountWith = (...names: string[]) => ({ capabilities: names.map((name) => ({ name })) }) as Pick<AuthUser, 'capabilities'>;

  it.each([
    ['BYPASS', ['BYPASS']],
    ['the users, groups and roles management', ['KNOWLEDGE', 'SETTINGS', 'SETTINGS_SETACCESSES']],
    ['the authentication management', ['SETTINGS', 'SETTINGS_SETAUTH']],
    ['the platform parameters management', ['SETTINGS', 'SETTINGS_SETPARAMETERS']],
  ])('should be true with %s', (_, names) => {
    expect(isAdministrativeAccount(accountWith(...names))).toBe(true);
  });

  it.each([
    ['no capability', []],
    ['knowledge capabilities only', ['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE_KNDELETE', 'APIACCESS_USEBASICAUTH']],
    ['the access to the administration only', ['SETTINGS']],
    ['the labels and vocabularies management', ['SETTINGS', 'SETTINGS_SETLABELS', 'SETTINGS_SETVOCABULARIES']],
    ['the other administration capabilities', [
      'SETTINGS', 'SETTINGS_SETMARKINGS', 'SETTINGS_SETDISSEMINATION', 'SETTINGS_SETCUSTOMIZATION', 'SETTINGS_SETCASETEMPLATES',
      'SETTINGS_SETSTATUSTEMPLATES', 'SETTINGS_SETKILLCHAINPHASES', 'SETTINGS_SETMANAGEXTMHUB', 'SETTINGS_SECURITYACTIVITY',
      'SETTINGS_FILEINDEXING', 'SETTINGS_SUPPORT',
    ]],
  ])('should be false with %s', (_, names) => {
    expect(isAdministrativeAccount(accountWith(...names))).toBe(false);
  });
});

describe('updateLocalAuth - admin password policy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockStoredSettings({ password_policy_min_length: 8, password_policy_min_numbers: 1 });
    mockCachedSettings({});
  });

  it('should check the policy once updated against the configured admin password', async () => {
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, password_policy_min_length: 15 });
    expect(checkPolicyAcceptsAdminPassword).toHaveBeenCalledWith(context, expect.objectContaining({ password_policy_min_length: 15, password_policy_min_numbers: 1 }));
  });

  it('should not write a policy the configured admin password does not match', async () => {
    vi.mocked(checkPolicyAcceptsAdminPassword).mockImplementation(() => {
      throw new Error('admin password mismatch');
    });
    await expect(updateLocalAuth(context, user, 'settings-id', { enabled: true, password_policy_min_length: 15 })).rejects.toThrow('admin password mismatch');
    expect(patchAttribute).not.toHaveBeenCalled();
  });
});
