import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/domain/settings', () => ({
  getSettingsFromDatabase: vi.fn(),
  getPlatformDefaultTheme: vi.fn(),
}));

import { getPlatformDefaultTheme, getSettingsFromDatabase } from '../../../../src/domain/settings';
import { getMessagesConfigPresetConfigurations, getPlatformConfigPresetConfiguration } from '../../../../src/modules/settings/settings-export';
import { messageConfigurationSchemas, platformConfigurationSchema } from '../../../../src/modules/settings/settings-import-schema';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { CUSTOM_THEME_ID } from '../../../utils/configPresetBundle';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
// Settings the allowlists must never let through: a secret, and the whitemark, which a configuration does not carry
const storedSettings = {
  platform_title: 'My platform',
  platform_favicon: 'https://example.com/favicon.ico',
  platform_language: 'fr-fr',
  platform_banner_text: 'Hello',
  platform_banner_level: 'GREEN',
  platform_login_message: 'Welcome',
  platform_whitemark: true,
  platform_theme: 'theme-internal-id',
  platform_providers: ['secret'],
};

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getSettingsFromDatabase).mockResolvedValue(storedSettings as never);
  vi.mocked(getPlatformDefaultTheme).mockResolvedValue(undefined as never);
});

describe('settings export', () => {
  it('exports the platform fields and the default theme by standard id, nothing else of the Settings', async () => {
    vi.mocked(getPlatformDefaultTheme).mockResolvedValue({ standard_id: CUSTOM_THEME_ID, name: 'Custom', built_in: false } as never);
    const configuration = await getPlatformConfigPresetConfiguration(context, user);
    expect(configuration).toEqual({
      platform_title: 'My platform',
      platform_favicon: 'https://example.com/favicon.ico',
      platform_language: 'fr-fr',
      default_theme: { standard_id: CUSTOM_THEME_ID, name: 'Custom' },
    });
  });

  it('uses the default theme it is given, and null for none, without reading the platform default', async () => {
    expect((await getPlatformConfigPresetConfiguration(context, user, { standard_id: CUSTOM_THEME_ID, name: 'Given' })).default_theme).toEqual({ standard_id: CUSTOM_THEME_ID, name: 'Given' });
    expect((await getPlatformConfigPresetConfiguration(context, user, null)).default_theme).toBeNull();
    expect(getPlatformDefaultTheme).not.toHaveBeenCalled();
  });

  it('gives a field that is not set as null, so the configuration always has the same keys', async () => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ platform_title: 'Only a title' } as never);
    expect(await getPlatformConfigPresetConfiguration(context, user)).toEqual({ platform_title: 'Only a title', platform_favicon: null, platform_language: null, default_theme: null });
    expect(await getMessagesConfigPresetConfigurations(context)).toEqual({
      banner: { platform_banner_text: null, platform_banner_level: null },
      login: { platform_login_message: null },
      consent: { platform_consent_message: null, platform_consent_confirm_text: null },
      noAccess: { platform_no_access_message: null },
    });
  });

  it('is accepted by the strict import validation, as it is', async () => {
    expect(platformConfigurationSchema.safeParse(await getPlatformConfigPresetConfiguration(context, user)).success).toBe(true);
    const messages = await getMessagesConfigPresetConfigurations(context);
    Object.entries(messages).forEach(([id, configuration]) => {
      expect(messageConfigurationSchemas[id as keyof typeof messageConfigurationSchemas].safeParse(configuration).success).toBe(true);
    });
  });
});
