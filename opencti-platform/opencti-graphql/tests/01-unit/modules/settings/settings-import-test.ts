import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/domain/settings', () => ({
  getSettings: vi.fn(),
  settingsEditField: vi.fn(),
}));
vi.mock('../../../../src/modules/theme/theme-domain', () => ({ findById: vi.fn() }));

import { getSettings, settingsEditField } from '../../../../src/domain/settings';
import { findById } from '../../../../src/modules/theme/theme-domain';
import { importMessage, importPlatformConfiguration, importWhitemark } from '../../../../src/modules/settings/settings-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { CUSTOM_THEME_ID } from '../../../utils/configPresetBundle';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite };
const dryRun = { mode: ConfigImportMode.Overwrite, dryRun: true };

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getSettings).mockResolvedValue({ id: 'settings-id' } as never);
  vi.mocked(findById).mockResolvedValue(undefined as never);
});

describe('importWhitemark', () => {
  it('writes the whitemark, and a dry run decides the same without writing', async () => {
    expect(await importWhitemark(context, user, { platform_whitemark: true }, dryRun)).toMatchObject({ status: 'overwritten', exists: true });
    expect(settingsEditField).not.toHaveBeenCalled();
    expect(await importWhitemark(context, user, { platform_whitemark: false }, overwrite)).toMatchObject({ status: 'overwritten' });
    expect(settingsEditField).toHaveBeenCalledWith(context, user, 'settings-id', [{ key: 'platform_whitemark', value: [false] }]);
  });

  it('leaves the whitemark as it is when there is nothing to import', async () => {
    expect(await importWhitemark(context, user, {}, overwrite)).toMatchObject({ status: 'skipped', code: 'nothing_to_import', reason: 'Nothing to import' });
    expect(await importWhitemark(context, user, { platform_whitemark: null }, overwrite)).toMatchObject({ status: 'skipped' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('has no copy and no add: any mode but overwrite leaves it as it is', async () => {
    const results = await Promise.all([ConfigImportMode.Copy, ConfigImportMode.Add].map((mode) => importWhitemark(context, user, { platform_whitemark: true }, { mode })));
    results.forEach((result) => expect(result).toMatchObject({ status: 'skipped', code: 'not_overwrite', reason: 'Already exists', exists: true }));
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('refuses an invalid configuration with its reason, without writing', async () => {
    expect(await importWhitemark(context, user, { platform_whitemark: 'yes' }, overwrite)).toMatchObject({ status: 'failed', code: 'invalid', reason: expect.stringContaining('platform_whitemark') });
    expect(await importWhitemark(context, user, { platform_whitemark: true, extra: 1 }, overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });
});

describe('importMessage', () => {
  it('writes the fields that are set, null meaning untouched', async () => {
    const result = await importMessage(context, user, 'banner', { platform_banner_text: 'Hello', platform_banner_level: null }, overwrite);
    expect(result).toMatchObject({ status: 'overwritten', configuration: { platform_banner_text: 'Hello', platform_banner_level: null } });
    expect(settingsEditField).toHaveBeenCalledWith(context, user, 'settings-id', [{ key: 'platform_banner_text', value: ['Hello'] }]);
  });

  it('does not write on a dry run', async () => {
    expect(await importMessage(context, user, 'consent', { platform_consent_message: 'Agree' }, dryRun)).toMatchObject({ status: 'overwritten' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('skips a message with only null values', async () => {
    expect(await importMessage(context, user, 'login', { platform_login_message: null }, overwrite)).toMatchObject({ status: 'skipped', code: 'nothing_to_import' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('fails on an unknown message, before reading the configuration', async () => {
    expect(await importMessage(context, user, 'other', {}, overwrite)).toMatchObject({ status: 'failed', code: 'unknown_message', reason: 'Unknown message', configuration: undefined });
  });

  it.each([
    ['an unknown key', 'banner', { platform_banner_text: 'x', extra: 1 }],
    ['an invalid level', 'banner', { platform_banner_text: 'x', platform_banner_level: 'PURPLE' }],
    ['a text that is too long', 'login', { platform_login_message: 'x'.repeat(6000) }],
  ])('refuses %s without writing', async (_, id, configuration) => {
    expect(await importMessage(context, user, id, configuration, overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });
});

describe('importPlatformConfiguration', () => {
  const defaultTheme = { standard_id: CUSTOM_THEME_ID, name: 'Custom' };

  it('writes the values that are set, and the default theme by its internal id on this platform', async () => {
    vi.mocked(findById).mockResolvedValue({ id: 'theme-internal-id' } as never);
    const result = await importPlatformConfiguration(context, user, { platform_title: 'Title', platform_favicon: null, default_theme: defaultTheme }, overwrite);
    expect(result).toMatchObject({ status: 'overwritten', exists: true });
    expect(findById).toHaveBeenCalledWith(context, user, CUSTOM_THEME_ID);
    expect(settingsEditField).toHaveBeenCalledWith(context, user, 'settings-id', [
      { key: 'platform_title', value: ['Title'] },
      { key: 'platform_theme', value: ['theme-internal-id'] },
    ]);
  });

  it('sets a default theme alone', async () => {
    vi.mocked(findById).mockResolvedValue({ id: 'theme-internal-id' } as never);
    await importPlatformConfiguration(context, user, { default_theme: defaultTheme }, overwrite);
    expect(settingsEditField).toHaveBeenCalledWith(context, user, 'settings-id', [{ key: 'platform_theme', value: ['theme-internal-id'] }]);
  });

  it('skips a configuration with nothing to import and no default theme', async () => {
    expect(await importPlatformConfiguration(context, user, { platform_title: null, default_theme: null }, overwrite)).toMatchObject({ status: 'skipped', code: 'nothing_to_import' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('fails when the default theme is not on the platform, unless a dry run is told the import creates it', async () => {
    const configuration = { platform_title: 'Title', default_theme: defaultTheme };
    expect(await importPlatformConfiguration(context, user, configuration, dryRun)).toMatchObject({
      status: 'failed',
      code: 'default_theme_missing',
      reason: 'Default theme Custom could not be imported',
      configuration,
    });
    const isThemeCreated = (standardId: string) => standardId === CUSTOM_THEME_ID;
    expect(await importPlatformConfiguration(context, user, configuration, { ...dryRun, isThemeCreated })).toMatchObject({ status: 'overwritten' });
    // A real import cannot set a theme that is not there, even when the plan said it would be created
    expect(await importPlatformConfiguration(context, user, configuration, { ...overwrite, isThemeCreated })).toMatchObject({ status: 'failed', code: 'default_theme_missing' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('has no copy: any mode but overwrite leaves it as it is', async () => {
    expect(await importPlatformConfiguration(context, user, { platform_title: 'Title' }, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'skipped', code: 'not_overwrite', reason: 'Already exists' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('refuses an invalid configuration, without writing', async () => {
    expect(await importPlatformConfiguration(context, user, { platform_favicon: '/favicon.ico' }, overwrite)).toMatchObject({ status: 'failed', code: 'invalid', reason: expect.stringContaining('platform_favicon') });
    expect(settingsEditField).not.toHaveBeenCalled();
  });
});
