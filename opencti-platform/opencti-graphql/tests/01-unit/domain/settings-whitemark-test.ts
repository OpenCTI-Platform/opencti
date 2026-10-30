import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const settings = { id: 'settings-id', internal_id: 'settings-id', platform_theme: undefined };

vi.mock('../../../src/enterprise-edition/ee', () => ({
  checkEnterpriseEdition: vi.fn(),
  isEnterpriseEdition: vi.fn(),
  isEnterpriseEditionFromSettings: vi.fn(),
}));
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

const { checkEnterpriseEdition } = await import('../../../src/enterprise-edition/ee');
const { loadEntity, updateAttribute } = await import('../../../src/database/middleware');
const { getClusterInformation } = await import('../../../src/database/cluster-module');
const { settingsEditField } = await import('../../../src/domain/settings');
const { UnsupportedError } = await import('../../../src/config/errors');

const context = { source: 'test' } as AuthContext;
const bypassUser = { id: 'user-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;

describe('settingsEditField, the whitemark', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(loadEntity).mockResolvedValue(settings as never);
    vi.mocked(getClusterInformation).mockResolvedValue({ info: {}, modules: [] } as never);
  });

  it('refuses to turn the whitemark on without the Enterprise Edition, and writes nothing', async () => {
    vi.mocked(checkEnterpriseEdition).mockRejectedValue(UnsupportedError('Enterprise edition is not enabled'));
    await expect(settingsEditField(context, bypassUser, 'settings-id', [{ key: 'platform_whitemark', value: [true] }]))
      .rejects.toThrow('Enterprise edition is not enabled');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it.each([[true], ['true']])('checks the Enterprise Edition for the value %s', async (value) => {
    vi.mocked(checkEnterpriseEdition).mockResolvedValue(undefined);
    await settingsEditField(context, bypassUser, 'settings-id', [{ key: 'platform_whitemark', value: [value] }]);
    expect(checkEnterpriseEdition).toHaveBeenCalledWith(context);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it.each([[false], ['false']])('lets the whitemark be turned off without the Enterprise Edition (%s)', async (value) => {
    vi.mocked(checkEnterpriseEdition).mockRejectedValue(UnsupportedError('Enterprise edition is not enabled'));
    await settingsEditField(context, bypassUser, 'settings-id', [{ key: 'platform_whitemark', value: [value] }]);
    expect(checkEnterpriseEdition).not.toHaveBeenCalled();
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it('refuses a whitemark turned on by a repeated key, whatever its position, and writes nothing', async () => {
    vi.mocked(checkEnterpriseEdition).mockRejectedValue(UnsupportedError('Enterprise edition is not enabled'));
    await expect(settingsEditField(context, bypassUser, 'settings-id', [
      { key: 'platform_whitemark', value: ['false'] },
      { key: 'platform_whitemark', value: ['true'] },
    ])).rejects.toThrow('Enterprise edition is not enabled');
    await expect(settingsEditField(context, bypassUser, 'settings-id', [
      { key: 'platform_whitemark', value: ['true'] },
      { key: 'platform_whitemark', value: ['false'] },
    ])).rejects.toThrow('Enterprise edition is not enabled');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('does not look at the Enterprise Edition for another setting', async () => {
    vi.mocked(checkEnterpriseEdition).mockRejectedValue(UnsupportedError('Enterprise edition is not enabled'));
    await settingsEditField(context, bypassUser, 'settings-id', [{ key: 'platform_title', value: ['My platform'] }]);
    expect(checkEnterpriseEdition).not.toHaveBeenCalled();
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });
});
