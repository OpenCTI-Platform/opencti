import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const settings = { id: 'settings-id', internal_id: 'settings-id', platform_theme: undefined };

vi.mock('../../../src/modules/settings/licensing', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/settings/licensing')>()),
  getEnterpriseEditionInfo: vi.fn(),
  decodeLicensePem: vi.fn(),
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

const { decodeLicensePem, getEnterpriseEditionInfo } = await import('../../../src/modules/settings/licensing');
const { loadEntity, updateAttribute } = await import('../../../src/database/middleware');
const { getClusterInformation } = await import('../../../src/database/cluster-module');
const { settingsEditField } = await import('../../../src/domain/settings');

const context = { source: 'test' } as AuthContext;
const bypassUser = { id: 'user-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;

const enterpriseEdition = (enabled: boolean) => vi.mocked(getEnterpriseEditionInfo).mockReturnValue({ license_validated: enabled } as never);
const turnOn = (value: unknown = true) => settingsEditField(context, bypassUser, 'settings-id', [{ key: 'platform_whitemark', value: [value] }]);

describe('settingsEditField, the whitemark', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(loadEntity).mockResolvedValue(settings as never);
    vi.mocked(getClusterInformation).mockResolvedValue({ info: {}, modules: [] } as never);
    enterpriseEdition(false);
  });

  it('refuses to turn the whitemark on without the Enterprise Edition, and writes nothing', async () => {
    await expect(turnOn()).rejects.toThrow('Enterprise edition is not enabled');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it.each([[true], ['true']])('turns the whitemark on with the Enterprise Edition (%s)', async (value) => {
    enterpriseEdition(true);
    await turnOn(value);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it('turns the whitemark on with the license given by the same edit, which is not saved yet', async () => {
    vi.mocked(decodeLicensePem).mockReturnValue({ license_validated: true } as never);
    await settingsEditField(context, bypassUser, 'settings-id', [
      { key: 'enterprise_license', value: ['pem'] },
      { key: 'platform_whitemark', value: [true] },
    ]);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it('refuses the whitemark with an invalid license in the same edit, and writes nothing', async () => {
    vi.mocked(decodeLicensePem).mockReturnValue({ license_validated: false } as never);
    await expect(settingsEditField(context, bypassUser, 'settings-id', [
      { key: 'enterprise_license', value: ['pem'] },
      { key: 'platform_whitemark', value: [true] },
    ])).rejects.toThrow('Invalid license');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it.each([[false], ['false']])('lets the whitemark be turned off without the Enterprise Edition (%s)', async (value) => {
    await turnOn(value);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it('refuses a whitemark turned on by a repeated key, whatever its position, and writes nothing', async () => {
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
    await settingsEditField(context, bypassUser, 'settings-id', [{ key: 'platform_title', value: ['My platform'] }]);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });
});
