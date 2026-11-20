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

const licenseSource = (source: string) => vi.mocked(getEnterpriseEditionInfo).mockReturnValue({ license_validated: true, license_source: source } as never);
const editLicense = (value: unknown[]) => settingsEditField(context, bypassUser, 'settings-id', [{ key: 'enterprise_license', value }]);

describe('settingsEditField, the Enterprise Edition granted by XTM One', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(loadEntity).mockResolvedValue(settings as never);
    vi.mocked(getClusterInformation).mockResolvedValue({ info: {}, modules: [] } as never);
  });

  it.each([[['']], [[]], [[null]]])('refuses to disable it, and writes nothing (%j)', async (value) => {
    licenseSource('XTM_ONE_LICENSE');
    await expect(editLicense(value)).rejects.toThrow('cannot be disabled in this platform');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('still lets an own license be added, which then wins', async () => {
    licenseSource('XTM_ONE_LICENSE');
    vi.mocked(decodeLicensePem).mockReturnValue({ license_validated: true } as never);
    await editLicense(['pem']);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });

  it.each(['OPENCTI_LICENSE', 'FILIGRAN_LICENSE'])('lets a license held by this platform be removed (%s)', async (source) => {
    licenseSource(source);
    await editLicense(['']);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
  });
});
