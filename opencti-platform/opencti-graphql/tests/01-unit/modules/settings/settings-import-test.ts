import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/domain/settings', () => ({
  getSettings: vi.fn(),
  getSettingsFromDatabase: vi.fn(),
  settingsEditField: vi.fn(),
}));
vi.mock('../../../../src/modules/theme/theme-domain', () => ({ findById: vi.fn() }));
vi.mock('../../../../src/database/middleware-loader', () => ({ storeLoadById: vi.fn() }));
vi.mock('../../../../src/enterprise-edition/ee', () => ({ isEnterpriseEdition: vi.fn() }));
vi.mock('../../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/user/user-domain')>()),
  propagatePasswordValidityChange: vi.fn(),
}));
vi.mock('../../../../src/modules/user/sensitive-config-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/user/sensitive-config-import')>()),
  isConfigImportSensitiveChangeAllowed: vi.fn(),
}));
vi.mock('../../../../src/domain/setting-auth', () => ({ setPasswordHistoryCount: vi.fn() }));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => true),
}));

import { getSettings, getSettingsFromDatabase, settingsEditField } from '../../../../src/domain/settings';
import { findById } from '../../../../src/modules/theme/theme-domain';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { isEnterpriseEdition } from '../../../../src/enterprise-edition/ee';
import { propagatePasswordValidityChange } from '../../../../src/modules/user/user-domain';
import { importMessage, importPlatformConfiguration, importPolicies, importWhitemark } from '../../../../src/modules/settings/settings-import';
import { isConfigImportSensitiveChangeAllowed } from '../../../../src/modules/user/sensitive-config-import';
import { setPasswordHistoryCount } from '../../../../src/domain/setting-auth';
import { isFeatureEnabled } from '../../../../src/config/conf';
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
  vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id' } as never);
  vi.mocked(findById).mockResolvedValue(undefined as never);
  vi.mocked(isFeatureEnabled).mockReturnValue(true);
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

  it('skips a whitemark the platform already has, and one that is off on a platform where it is not set', async () => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', platform_whitemark: true } as never);
    expect(await importWhitemark(context, user, { platform_whitemark: true }, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id' } as never);
    expect(await importWhitemark(context, user, { platform_whitemark: false }, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('writes a whitemark that differs from the one of the platform', async () => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', platform_whitemark: true } as never);
    expect(await importWhitemark(context, user, { platform_whitemark: false }, overwrite)).toMatchObject({ status: 'overwritten' });
    expect(settingsEditField).toHaveBeenCalledTimes(1);
  });

  it('has no copy and no add: any mode but overwrite leaves it as it is', async () => {
    const results = await Promise.all([ConfigImportMode.Copy, ConfigImportMode.Add].map((mode) => importMessage(context, user, 'banner', { platform_banner_text: 'Hello' }, { mode })));
    results.forEach((result) => expect(result).toMatchObject({ status: 'skipped', code: 'not_overwrite', reason: 'Already exists', exists: true }));
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

describe('importWhitemark', () => {
  it('writes the whitemark, whether it is on or off', async () => {
    expect(await importWhitemark(context, user, { platform_whitemark: true }, overwrite)).toMatchObject({ status: 'overwritten', exists: true });
    expect(settingsEditField).toHaveBeenLastCalledWith(context, user, 'settings-id', [{ key: 'platform_whitemark', value: [true] }]);
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', platform_whitemark: true } as never);
    await importWhitemark(context, user, { platform_whitemark: false }, overwrite);
    expect(settingsEditField).toHaveBeenLastCalledWith(context, user, 'settings-id', [{ key: 'platform_whitemark', value: [false] }]);
  });

  it('does not write on a dry run', async () => {
    expect(await importWhitemark(context, user, { platform_whitemark: true }, dryRun)).toMatchObject({ status: 'overwritten' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('skips a whitemark that is not set', async () => {
    expect(await importWhitemark(context, user, { platform_whitemark: null }, overwrite)).toMatchObject({ status: 'skipped', code: 'nothing_to_import' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('has no copy and no add: any mode but overwrite leaves it as it is', async () => {
    const results = await Promise.all([ConfigImportMode.Copy, ConfigImportMode.Add].map((mode) => importWhitemark(context, user, { platform_whitemark: true }, { mode })));
    results.forEach((result) => expect(result).toMatchObject({ status: 'skipped', code: 'not_overwrite' }));
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it.each([
    ['an unknown key', { platform_whitemark: true, extra: 1 }],
    ['a value that is not a boolean', { platform_whitemark: 'yes' }],
  ])('refuses %s without writing', async (_, configuration) => {
    expect(await importWhitemark(context, user, configuration, overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
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

  it('skips a configuration the platform already has, theme included', async () => {
    vi.mocked(findById).mockResolvedValue({ id: 'theme-internal-id' } as never);
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', platform_title: 'Title', platform_theme: 'theme-internal-id' } as never);
    expect(await importPlatformConfiguration(context, user, { platform_title: 'Title', default_theme: defaultTheme }, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(await importPlatformConfiguration(context, user, { platform_title: 'Other', default_theme: defaultTheme }, overwrite)).toMatchObject({ status: 'overwritten' });
    expect(settingsEditField).toHaveBeenCalledTimes(1);
  });

  it('does not take a default theme that the import creates for a theme the platform has', async () => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', platform_title: 'Title' } as never);
    const isThemeCreated = () => true;
    expect(await importPlatformConfiguration(context, user, { platform_title: 'Title', default_theme: defaultTheme }, { ...dryRun, isThemeCreated })).toMatchObject({ status: 'overwritten' });
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

describe('importPolicies', () => {
  const organization = { standard_id: 'identity--11111111-2222-4333-8444-555555555555', name: 'Filigran' };
  const policies = (overrides: Record<string, unknown> = {}) => ({
    view_all_users: false,
    password_policy_min_length: 12,
    password_policy_max_length: 0,
    password_policy_min_symbols: 1,
    password_policy_min_numbers: 1,
    password_policy_min_words: 0,
    password_policy_min_lowercase: 1,
    password_policy_min_uppercase: 1,
    password_policy_validity_days: 90,
    platform_organization: organization,
    ...overrides,
  });

  beforeEach(() => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_validity_days: 90 } as never);
    vi.mocked(isEnterpriseEdition).mockResolvedValue(true);
    vi.mocked(isConfigImportSensitiveChangeAllowed).mockResolvedValue(true);
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'organization-id', ...organization } as never);
  });

  it('writes the policies and the main organization of this platform, by internal id, with one call', async () => {
    const result = await importPolicies(context, user, policies(), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', exists: true });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, organization.standard_id, 'Organization');
    expect(settingsEditField).toHaveBeenCalledTimes(1);
    expect(settingsEditField).toHaveBeenCalledWith(context, user, 'settings-id', expect.arrayContaining([
      { key: 'view_all_users', value: [false] },
      { key: 'password_policy_min_length', value: [12] },
      { key: 'password_policy_validity_days', value: [90] },
      { key: 'platform_organization', value: ['organization-id'] },
    ]));
  });

  it('moves the expiration date of the users when the validity of the passwords changes, the policy being disabled included', async () => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_validity_days: 30 } as never);
    await importPolicies(context, user, policies(), overwrite);
    expect(propagatePasswordValidityChange).toHaveBeenCalledWith(context, 30, 90);
    await importPolicies(context, user, policies({ password_policy_validity_days: 0 }), overwrite);
    expect(propagatePasswordValidityChange).toHaveBeenCalledWith(context, 30, 0);
  });

  it('leaves the expiration dates of the users untouched when the validity does not change or is not set', async () => {
    await importPolicies(context, user, policies(), overwrite);
    await importPolicies(context, user, policies({ password_policy_validity_days: null }), overwrite);
    // A default policy imported on a platform that has the default one too
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id' } as never);
    await importPolicies(context, user, policies({ password_policy_validity_days: 0 }), overwrite);
    expect(propagatePasswordValidityChange).not.toHaveBeenCalled();
  });

  it('says in the preview that it sets the main organization and changes the expiration date of the passwords', async () => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_validity_days: 30 } as never);
    const result = await importPolicies(context, user, policies(), dryRun);
    expect(result.reason).toEqual("Sets the main organization: Filigran\nThe expiration date of the users' passwords changes");
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_validity_days: 90, platform_organization: 'organization-id' } as never);
    expect((await importPolicies(context, user, policies(), dryRun)).reason).toBeUndefined();
  });

  it('names the main organization it sets as this platform does, never as the bundle says', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'organization-id', ...organization, name: 'Filigran SAS' } as never);
    const result = await importPolicies(context, user, policies({ platform_organization: { ...organization, name: 'Another organization' } }), dryRun);
    expect(result.reason).toEqual('Sets the main organization: Filigran SAS');
  });

  it('refuses a password policy that no password can satisfy, alone or with the values of the platform, without writing', async () => {
    const contradictory = await importPolicies(context, user, policies({ password_policy_min_length: 20, password_policy_max_length: 5 }), overwrite);
    expect(contradictory).toMatchObject({ status: 'failed', code: 'invalid', reason: 'The password policy cannot be satisfied: its maximum length is below what its other rules require' });
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_max_length: 8 } as never);
    const withPlatform = await importPolicies(context, user, policies({ password_policy_max_length: null }), overwrite);
    expect(withPlatform).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('leaves out and reports a main organization that is not on this platform, and never creates it', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);
    const result = await importPolicies(context, user, policies(), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', reason: 'Main organization not found: Filigran' });
    expect(vi.mocked(settingsEditField).mock.calls[0][3]).not.toContainEqual(expect.objectContaining({ key: 'platform_organization' }));
  });

  it('leaves out and reports the main organization on a platform that is not Enterprise Edition', async () => {
    vi.mocked(isEnterpriseEdition).mockResolvedValue(false);
    const result = await importPolicies(context, user, policies(), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', reason: 'The main organization requires the Enterprise Edition' });
    expect(storeLoadById).not.toHaveBeenCalled();
    expect(vi.mocked(settingsEditField).mock.calls[0][3]).not.toContainEqual(expect.objectContaining({ key: 'platform_organization' }));
  });

  it('leaves out and reports the main organization to a user who cannot manage the sensitive configuration, and writes the rest', async () => {
    vi.mocked(isConfigImportSensitiveChangeAllowed).mockResolvedValue(false);
    const result = await importPolicies(context, user, policies(), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', reason: 'Requires the right to manage the sensitive configuration' });
    expect(isConfigImportSensitiveChangeAllowed).toHaveBeenCalledWith(context, user, 'platform_organization');
    expect(storeLoadById).not.toHaveBeenCalled();
    const input = vi.mocked(settingsEditField).mock.calls[0][3];
    expect(input).not.toContainEqual(expect.objectContaining({ key: 'platform_organization' }));
    expect(input).toContainEqual({ key: 'password_policy_min_length', value: [12] });
  });

  it('skips policies the platform has as they are, without writing nor moving the expiration dates', async () => {
    const { platform_organization: _, ...fields } = policies();
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', ...fields, platform_organization: 'organization-id' } as never);
    expect(await importPolicies(context, user, policies(), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    expect(settingsEditField).not.toHaveBeenCalled();
    expect(propagatePasswordValidityChange).not.toHaveBeenCalled();
  });

  it('skips the default policy on a platform that never stored its fields, without writing', async () => {
    const defaults = policies({ password_policy_min_length: 0, password_policy_min_symbols: 0, password_policy_min_numbers: 0, password_policy_min_lowercase: 0,
      password_policy_min_uppercase: 0, password_policy_validity_days: 0, platform_organization: null });
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id' } as never);
    expect(await importPolicies(context, user, defaults, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    expect(settingsEditField).not.toHaveBeenCalled();
    expect(propagatePasswordValidityChange).not.toHaveBeenCalled();
  });

  it('skips policies the platform has as they are when only the main organization is left out, and says why it is', async () => {
    const { platform_organization: _, ...fields } = policies();
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', ...fields } as never);
    vi.mocked(isEnterpriseEdition).mockResolvedValue(false);
    const result = await importPolicies(context, user, policies(), overwrite);
    expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date\nThe main organization requires the Enterprise Edition' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('says in the preview that the passwords no longer expire, and that users can view the users of other organizations', async () => {
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_validity_days: 30, platform_organization: 'organization-id' } as never);
    const result = await importPolicies(context, user, policies({ password_policy_validity_days: 0, view_all_users: true }), dryRun);
    expect(result.reason).toEqual("The users' passwords no longer expire\nUsers can view the users of other organizations");
    vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_validity_days: 0, view_all_users: true, platform_organization: 'organization-id' } as never);
    expect((await importPolicies(context, user, policies({ password_policy_validity_days: 0, view_all_users: true }), dryRun)).reason).toBeUndefined();
  });

  it('does not write on a dry run', async () => {
    expect(await importPolicies(context, user, policies(), dryRun)).toMatchObject({ status: 'overwritten' });
    expect(settingsEditField).not.toHaveBeenCalled();
    expect(propagatePasswordValidityChange).not.toHaveBeenCalled();
  });

  it.each([
    ['an unknown key', { otp_mandatory: true }],
    ['a negative length', { password_policy_min_length: -1 }],
    ['a length that is not an integer', { password_policy_min_length: 1.5 }],
  ])('refuses %s, without writing', async (_, overrides) => {
    expect(await importPolicies(context, user, policies(overrides), overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
    expect(settingsEditField).not.toHaveBeenCalled();
  });

  it('skips policies with only null values, and any mode but overwrite', async () => {
    const empty = Object.fromEntries(Object.keys(policies({ password_policy_history_count: 3 })).map((key) => [key, null]));
    expect(await importPolicies(context, user, empty, overwrite)).toMatchObject({ status: 'skipped', code: 'nothing_to_import' });
    expect(await importPolicies(context, user, policies(), { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'skipped', code: 'not_overwrite' });
    expect(settingsEditField).not.toHaveBeenCalled();
    expect(setPasswordHistoryCount).not.toHaveBeenCalled();
  });

  describe('password history count', () => {
    const { platform_organization: _, ...fields } = policies();
    // The platform has the policy of the bundle, the main organization included: only the count can differ
    const platformWith = (historyCount?: number) => {
      vi.mocked(getSettingsFromDatabase).mockResolvedValue({
        id: 'settings-id', ...fields, platform_organization: 'organization-id', ...(historyCount !== undefined && { password_policy_history_count: historyCount }),
      } as never);
    };

    it('sets the count apart from the other fields, which settingsEditField would refuse it with', async () => {
      vi.mocked(getSettingsFromDatabase).mockResolvedValue({ id: 'settings-id', password_policy_history_count: 2 } as never);
      expect(await importPolicies(context, user, policies({ password_policy_history_count: 5 }), overwrite)).toMatchObject({ status: 'overwritten' });
      expect(vi.mocked(settingsEditField).mock.calls[0][3]).not.toContainEqual(expect.objectContaining({ key: 'password_policy_history_count' }));
      expect(setPasswordHistoryCount).toHaveBeenCalledWith(context, user, 5);
    });

    it('imports a count that is the only change, without rewriting the other fields', async () => {
      platformWith(2);
      expect(await importPolicies(context, user, { password_policy_history_count: 5 }, overwrite)).toMatchObject({ status: 'overwritten' });
      expect(settingsEditField).not.toHaveBeenCalled();
      expect(setPasswordHistoryCount).toHaveBeenCalledWith(context, user, 5);
    });

    it('skips a count the platform already has, 0 on a platform that never stored one included', async () => {
      platformWith(5);
      expect(await importPolicies(context, user, policies({ password_policy_history_count: 5 }), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
      platformWith();
      expect(await importPolicies(context, user, policies({ password_policy_history_count: 0 }), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(settingsEditField).not.toHaveBeenCalled();
      expect(setPasswordHistoryCount).not.toHaveBeenCalled();
    });

    it('says in the preview that the stored histories are trimmed or deleted when the count goes down, and nothing when it goes up', async () => {
      platformWith(5);
      expect((await importPolicies(context, user, policies({ password_policy_history_count: 2 }), dryRun)).reason).toEqual('Fewer recent passwords are kept: users can reuse the oldest ones');
      expect((await importPolicies(context, user, policies({ password_policy_history_count: 0 }), dryRun)).reason).toEqual('Recent passwords are no longer kept: users can reuse them');
      const higher = await importPolicies(context, user, policies({ password_policy_history_count: 8 }), dryRun);
      expect(higher).toMatchObject({ status: 'overwritten' });
      expect(higher.reason).toBeUndefined();
      expect(setPasswordHistoryCount).not.toHaveBeenCalled();
      expect(settingsEditField).not.toHaveBeenCalled();
    });

    it('treats an unusable stored count as 0, as the password history does', async () => {
      platformWith(99);
      expect(await importPolicies(context, user, policies({ password_policy_history_count: 0 }), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(setPasswordHistoryCount).not.toHaveBeenCalled();
    });

    it('without the feature, leaves out and reports a count other than 0, and still writes the rest of the policy', async () => {
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      const result = await importPolicies(context, user, policies({ password_policy_history_count: 5 }), overwrite);
      expect(result).toMatchObject({ status: 'overwritten', reason: expect.stringContaining('The reuse of recent passwords cannot be blocked on this platform') });
      expect(settingsEditField).toHaveBeenCalledTimes(1);
      expect(setPasswordHistoryCount).not.toHaveBeenCalled();
    });

    it('without the feature, finds the policy up to date when only the count differs, and says why the count is left out', async () => {
      vi.mocked(isFeatureEnabled).mockReturnValue(false);
      platformWith();
      const result = await importPolicies(context, user, policies({ password_policy_history_count: 5 }), overwrite);
      expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date\nThe reuse of recent passwords cannot be blocked on this platform' });
      expect((await importPolicies(context, user, policies({ password_policy_history_count: 0 }), overwrite)).reason).toEqual('Already up to date');
      expect(setPasswordHistoryCount).not.toHaveBeenCalled();
    });

    it.each([
      ['above the maximum', 25],
      ['negative', -1],
      ['not an integer', 2.5],
      ['not a number', '5'],
    ])('refuses a count %s, without writing', async (_, value) => {
      expect(await importPolicies(context, user, policies({ password_policy_history_count: value }), overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
      expect(settingsEditField).not.toHaveBeenCalled();
      expect(setPasswordHistoryCount).not.toHaveBeenCalled();
    });
  });
});
