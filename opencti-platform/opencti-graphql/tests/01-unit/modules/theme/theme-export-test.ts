import { describe, expect, it } from 'vitest';
import { getThemeConfigPresetConfiguration, getThemeExportConfiguration, themeExport } from '../../../../src/modules/theme/theme-export';
import { themeImportSchema } from '../../../../src/modules/theme/theme-import-schema';
import type { BasicStoreEntityTheme } from '../../../../src/modules/theme/theme-types';
import { CUSTOM_THEME_ID, themeConfiguration } from '../../../utils/configPresetBundle';

// What the store holds: the import fields, the identity of the theme, and fields that are never exported
const storedTheme = (overrides: Record<string, unknown> = {}) => ({
  ...themeConfiguration(),
  id: 'internal-id',
  standard_id: CUSTOM_THEME_ID,
  entity_type: 'Theme',
  built_in: false,
  ...overrides,
}) as unknown as BasicStoreEntityTheme;

describe('themeExport', () => {
  it('exports the fields the import accepts, without the standard id nor the fields of the store', () => {
    const file = JSON.parse(themeExport(storedTheme()));
    expect(file).toEqual(themeConfiguration({ standard_id: undefined }));
    expect(file).not.toHaveProperty('standard_id');
    expect(file).not.toHaveProperty('built_in');
    expect(file).not.toHaveProperty('id');
  });

  it('leaves out a value that is null or absent', () => {
    const file = JSON.parse(themeExport(storedTheme({ theme_logo: null, theme_logo_collapsed: undefined, theme_login_aside_image: null })));
    expect(Object.keys(file)).not.toContain('theme_logo');
    expect(Object.keys(file)).not.toContain('theme_logo_collapsed');
    expect(Object.keys(file)).not.toContain('theme_login_aside_image');
  });

  it('keeps an empty string, which the import accepts', () => {
    expect(JSON.parse(themeExport(storedTheme({ theme_logo: '' }))).theme_logo).toBe('');
  });

  it('is a file the strict import validation accepts, as it is', () => {
    const optionalFields = {
      theme_logo_collapsed: 'https://example.com/collapsed.png',
      theme_logo_login: 'https://example.com/login.png',
      theme_login_aside_color: '#112233',
      theme_login_aside_gradient_start: '#223344',
      theme_login_aside_gradient_end: '#334455',
      theme_login_aside_image: 'https://example.com/aside.png',
    };
    [storedTheme(), storedTheme(optionalFields), storedTheme({ theme_logo: null })].forEach((theme) => {
      expect(themeImportSchema.safeParse(JSON.parse(themeExport(theme))).success).toBe(true);
    });
  });
});

describe('getThemeConfigPresetConfiguration', () => {
  it('is the exported theme with its standard id first', () => {
    const configuration = getThemeConfigPresetConfiguration(storedTheme());
    expect(Object.keys(configuration)[0]).toBe('standard_id');
    expect(configuration).toEqual({ standard_id: CUSTOM_THEME_ID, ...getThemeExportConfiguration(storedTheme()) });
    expect(themeImportSchema.safeParse(configuration).success).toBe(true);
  });
});
