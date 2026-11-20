import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import conf from '../../../src/config/conf';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// The configured admin password of the tests (app:admin:password) matches this stored policy
const settings = { id: 'settings-id', internal_id: 'settings-id', password_policy_min_length: 5 };
const SWITCH = 'app:admin:secure_by_default';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  fullEntitiesOrRelationsList: vi.fn(),
  loadEntity: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../src/database/redis', () => ({
  delEditContext: vi.fn(),
  getRedisVersion: vi.fn(),
  notify: vi.fn(),
  setEditContext: vi.fn(),
}));
vi.mock('../../../src/database/cluster-module', () => ({ getClusterInformation: vi.fn() }));
vi.mock('../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../src/modules/theme/theme-domain', () => ({ findById: vi.fn() }));
vi.mock('../../../src/modules/xtm/one/xtm-one', () => ({
  getXtmOneRegistrationVersion: vi.fn(),
  refreshXtmLicenseProof: vi.fn(),
}));

const { loadEntity, updateAttribute } = await import('../../../src/database/middleware');
const { getClusterInformation } = await import('../../../src/database/cluster-module');
const { settingsEditField } = await import('../../../src/domain/settings');
const { ADMIN_PASSWORD_POLICY_MISMATCH_REASON } = await import('../../../src/modules/user/user-domain');

const context = { source: 'test' } as AuthContext;
const bypassUser = { id: 'user-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;

const edit = (key: string, value: unknown) => settingsEditField(context, bypassUser, 'settings-id', [{ key, value: [value] }]);

describe('settingsEditField, the password policy against the configured admin password', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getClusterInformation).mockResolvedValue({ info: {}, modules: [] } as never);
  });

  afterEach(() => {
    conf.clear(SWITCH);
  });

  it('refuses a policy the admin password does not match, and writes nothing, switch on', async () => {
    // Given
    conf.set(SWITCH, true);
    vi.mocked(loadEntity).mockResolvedValue(settings as never);

    // When / Then
    await expect(edit('password_policy_min_length', '200')).rejects.toThrow(ADMIN_PASSWORD_POLICY_MISMATCH_REASON);
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('checks the edited rules merged with the stored policy, switch on', async () => {
    // Given: the stored policy already asks for an uppercase char, which the admin password does not have
    conf.set(SWITCH, true);
    vi.mocked(loadEntity).mockResolvedValue({ ...settings, password_policy_min_uppercase: 1 } as never);

    // When / Then: the edit alone would be matched
    await expect(edit('password_policy_min_length', '1')).rejects.toThrow(ADMIN_PASSWORD_POLICY_MISMATCH_REASON);
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('accepts a policy the admin password matches, switch on', async () => {
    // Given
    conf.set(SWITCH, true);
    vi.mocked(loadEntity).mockResolvedValue(settings as never);

    // When
    await edit('password_policy_min_length', '5');

    // Then
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it('does not check the policy for another setting, switch on', async () => {
    // Given: a stored policy the admin password does not match
    conf.set(SWITCH, true);
    vi.mocked(loadEntity).mockResolvedValue({ ...settings, password_policy_min_length: 200 } as never);

    // When
    await edit('platform_title', 'My platform');

    // Then
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it('accepts a policy the admin password does not match, switch off', async () => {
    // Given
    conf.set(SWITCH, false);
    vi.mocked(loadEntity).mockResolvedValue(settings as never);

    // When
    await edit('password_policy_min_length', '200');

    // Then
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });
});
