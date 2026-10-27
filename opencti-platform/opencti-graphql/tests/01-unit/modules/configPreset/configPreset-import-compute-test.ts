import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/theme/theme-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/theme/theme-domain')>()),
  findById: vi.fn(),
  checkExistingTheme: vi.fn(),
}));

import { findById, checkExistingTheme } from '../../../../src/modules/theme/theme-domain';
import { CONFIG_PRESET_FAMILIES } from '../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetImportPlan } from '../../../../src/modules/configPreset/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { BUILT_IN_THEME_STANDARD_IDS } from '../../../../src/modules/theme/theme-constants';
import { CUSTOM_THEME_ID, themeConfiguration } from '../../../utils/configPresetBundle';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;

const compute = (type: string, id: string, configuration: Record<string, unknown>, plan: ConfigPresetImportPlan = { created: new Set() }) => {
  const family = CONFIG_PRESET_FAMILIES.find((candidate) => candidate.id === type)!;
  const item: ConfigPresetBundleItem = { type, id, path: `${id}.json`, configuration };
  return family.importer!.compute(context, user, item, plan);
};

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(findById).mockResolvedValue(undefined as never);
  vi.mocked(checkExistingTheme).mockResolvedValue(false);
});

describe('Messages import (compute)', () => {
  it('overwrites a message and previews every field of it, null meaning untouched', async () => {
    const result = await compute('messages', 'banner', { platform_banner_text: 'Hello', platform_banner_level: null });
    expect(result).toMatchObject({ status: 'overwritten', exists: true });
    expect(result.fields).toEqual([
      { key: 'platform_banner_text', value: 'Hello', external_host: false },
      { key: 'platform_banner_level', value: null, external_host: false },
    ]);
  });

  it('skips an item with only null values', async () => {
    expect(await compute('messages', 'consent', { platform_consent_message: null, platform_consent_confirm_text: null })).toMatchObject({ status: 'skipped', reason: 'Nothing to import' });
    expect(await compute('messages', 'login', {})).toMatchObject({ status: 'skipped' });
  });

  it('fails with the reason on an unknown key, an invalid level, a text too long or an unknown message', async () => {
    expect(await compute('messages', 'banner', { platform_banner_text: 'x', extra: 1 })).toMatchObject({ status: 'failed' });
    expect(await compute('messages', 'banner', { platform_banner_text: 'x', platform_banner_level: 'PURPLE' })).toMatchObject({ status: 'failed', reason: expect.stringContaining('platform_banner_level') });
    expect(await compute('messages', 'login', { platform_login_message: 'x'.repeat(6000) })).toMatchObject({ status: 'failed' });
    expect(await compute('messages', 'other', {})).toMatchObject({ status: 'failed', reason: 'Unknown message' });
  });
});

describe('Platform import (compute)', () => {
  const platform = (overrides: Record<string, unknown> = {}) => ({ platform_title: 'Title', platform_favicon: null, platform_language: 'en-us', default_theme: null, ...overrides });

  it('overwrites the platform and previews the title and the favicon', async () => {
    const result = await compute('platform', 'platform', platform({ platform_favicon: 'https://example.com/favicon.ico' }));
    expect(result.status).toEqual('overwritten');
    expect(result.fields).toEqual([
      { key: 'platform_title', value: 'Title', external_host: false },
      { key: 'platform_favicon', value: 'https://example.com/favicon.ico', external_host: true },
    ]);
  });

  it('does not fail on a null default theme, and skips an item with only null values', async () => {
    expect(await compute('platform', 'platform', platform())).toMatchObject({ status: 'overwritten' });
    expect(await compute('platform', 'platform', { platform_title: null, platform_favicon: null, platform_language: null, default_theme: null })).toMatchObject({ status: 'skipped' });
  });

  it('fails on a favicon that is not an http(s) URL, an invalid language and an unknown key', async () => {
    expect(await compute('platform', 'platform', platform({ platform_favicon: 'javascript:alert(1)' }))).toMatchObject({ status: 'failed' });
    expect(await compute('platform', 'platform', platform({ platform_language: 'klingon' }))).toMatchObject({ status: 'failed' });
    expect(await compute('platform', 'platform', platform({ platform_theme: 'x' }))).toMatchObject({ status: 'failed' });
  });

  it('resolves the default theme on the platform or among the themes the import creates', async () => {
    const defaultTheme = { default_theme: { standard_id: CUSTOM_THEME_ID, name: 'Mine' } };
    expect(await compute('platform', 'platform', platform(defaultTheme))).toMatchObject({ status: 'failed', reason: 'Default theme Mine could not be imported' });
    vi.mocked(findById).mockResolvedValueOnce({ id: 'internal' } as never);
    expect(await compute('platform', 'platform', platform(defaultTheme))).toMatchObject({ status: 'overwritten' });
    expect(await compute('platform', 'platform', platform(defaultTheme), { created: new Set([`branding/${CUSTOM_THEME_ID}`]) })).toMatchObject({ status: 'overwritten' });
  });
});

describe('Branding import (compute)', () => {
  it('skips a built-in theme without looking it up', async () => {
    const [standardId] = Object.values(BUILT_IN_THEME_STANDARD_IDS);
    expect(await compute('branding', standardId, { standard_id: standardId, name: 'Filigran Dark' })).toMatchObject({ status: 'skipped', exists: true });
    expect(findById).not.toHaveBeenCalled();
  });

  it('creates a custom theme that is absent with a free name, and records it in the plan', async () => {
    const plan = { created: new Set<string>() };
    const result = await compute('branding', CUSTOM_THEME_ID, themeConfiguration(), plan);
    expect(result).toMatchObject({ status: 'created', exists: false, label: 'Import test theme' });
    expect(plan.created.has(`branding/${CUSTOM_THEME_ID}`)).toBe(true);
  });

  it('overwrites a custom theme whose standard id exists, never reports it created', async () => {
    vi.mocked(findById).mockResolvedValue({ id: 'internal', built_in: false } as never);
    expect(await compute('branding', CUSTOM_THEME_ID, themeConfiguration())).toMatchObject({ status: 'overwritten', exists: true });
  });

  it('fails when the name is already used by another theme', async () => {
    vi.mocked(checkExistingTheme).mockResolvedValue(true);
    const plan = { created: new Set<string>() };
    expect(await compute('branding', CUSTOM_THEME_ID, themeConfiguration(), plan)).toMatchObject({ status: 'failed', reason: 'Theme name already exists' });
    expect(plan.created.size).toBe(0);
  });

  it('fails on a standard id that differs from the id or is badly formed', async () => {
    expect(await compute('branding', CUSTOM_THEME_ID, themeConfiguration({ standard_id: 'theme--other' }))).toMatchObject({ status: 'failed' });
    expect(await compute('branding', 'theme--NOT-LOWER', themeConfiguration({ standard_id: 'theme--NOT-LOWER' }))).toMatchObject({ status: 'failed' });
  });

  it('fails on a bad colour, an image URL with a forbidden character and an unknown key', async () => {
    expect(await compute('branding', CUSTOM_THEME_ID, themeConfiguration({ theme_primary: 'red; background: url(x)' }))).toMatchObject({ status: 'failed' });
    expect(await compute('branding', CUSTOM_THEME_ID, themeConfiguration({ theme_logo: 'https://example.com/a.png);color:red' }))).toMatchObject({ status: 'failed' });
    expect(await compute('branding', CUSTOM_THEME_ID, themeConfiguration({ built_in: true }))).toMatchObject({ status: 'failed' });
    expect(await compute('branding', CUSTOM_THEME_ID, themeConfiguration({ theme_logo: 'http://example.com/a.png' }))).toMatchObject({ status: 'failed' });
  });

  it('previews the URL and image fields only, flags an external host and shows a data image as type and size', async () => {
    const dataImage = `data:image/png;base64,${'A'.repeat(2048)}`;
    const result = await compute('branding', CUSTOM_THEME_ID, themeConfiguration({ theme_logo_collapsed: dataImage }));
    expect(result.fields.map(({ key }) => key)).toEqual(['theme_logo', 'theme_logo_collapsed', 'theme_logo_login', 'theme_login_aside_image']);
    expect(result.fields[0]).toEqual({ key: 'theme_logo', value: 'https://example.com/logo.png', external_host: true });
    expect(result.fields[1]).toEqual({ key: 'theme_logo_collapsed', value: 'image/png (2 KB)', external_host: false });
    expect(result.fields[2].value).toBeNull();
  });

  it('overwrites the whitemark, skips a null value and fails on an invalid one', async () => {
    expect(await compute('branding', 'whitemark', { platform_whitemark: true })).toMatchObject({ status: 'overwritten' });
    expect(await compute('branding', 'whitemark', { platform_whitemark: null })).toMatchObject({ status: 'skipped' });
    expect(await compute('branding', 'whitemark', { platform_whitemark: 'yes' })).toMatchObject({ status: 'failed' });
  });
});
