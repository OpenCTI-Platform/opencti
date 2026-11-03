import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/domain/settings', () => ({ getProtectedSensitiveConfig: vi.fn() }));

import { getProtectedSensitiveConfig } from '../../../../../src/domain/settings';
import { isConfigImportSensitiveChangeAllowed } from '../../../../../src/modules/user/configPreset/sensitive-config-import';
import { OPENCTI_ADMIN_UUID } from '../../../../../src/schema/general';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const PROTECTED_ROLE = 'role--protected';

const userWith = (canManageSensitiveConfig: boolean, id = 'admin-id') => ({ id, roles: [{ id: 'role-id', can_manage_sensitive_config: canManageSensitiveConfig }] } as unknown as AuthUser);
const protection = (enabled: boolean, typeEnabled = true) => (({
  enabled,
  roles: { enabled: typeEnabled, protected_ids: [PROTECTED_ROLE] },
  groups: { enabled: typeEnabled, protected_ids: [] },
  platform_organization: { enabled: typeEnabled, protected_ids: [] },
}) as unknown as Awaited<ReturnType<typeof getProtectedSensitiveConfig>>);

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getProtectedSensitiveConfig).mockResolvedValue(protection(true));
});

describe('isConfigImportSensitiveChangeAllowed', () => {
  it('refuses a protected role to a user who cannot manage the sensitive configuration, as the settings screens do', async () => {
    expect(await isConfigImportSensitiveChangeAllowed(context, userWith(false), 'roles', PROTECTED_ROLE)).toBe(false);
  });

  it('allows an element that is not protected', async () => {
    expect(await isConfigImportSensitiveChangeAllowed(context, userWith(false), 'roles', 'role--other')).toBe(true);
  });

  it('protects the main organization as a whole', async () => {
    expect(await isConfigImportSensitiveChangeAllowed(context, userWith(false), 'platform_organization')).toBe(false);
  });

  it('allows everything to a user who can manage the sensitive configuration, and to the platform administrator', async () => {
    expect(await isConfigImportSensitiveChangeAllowed(context, userWith(true), 'roles', PROTECTED_ROLE)).toBe(true);
    expect(await isConfigImportSensitiveChangeAllowed(context, userWith(false, OPENCTI_ADMIN_UUID), 'platform_organization')).toBe(true);
    expect(getProtectedSensitiveConfig).not.toHaveBeenCalled();
  });

  it('allows everything when the protection, or the protection of the type, is disabled', async () => {
    vi.mocked(getProtectedSensitiveConfig).mockResolvedValue(protection(false));
    expect(await isConfigImportSensitiveChangeAllowed(context, userWith(false), 'roles', PROTECTED_ROLE)).toBe(true);
    vi.mocked(getProtectedSensitiveConfig).mockResolvedValue(protection(true, false));
    expect(await isConfigImportSensitiveChangeAllowed(context, userWith(false), 'platform_organization')).toBe(true);
  });
});
