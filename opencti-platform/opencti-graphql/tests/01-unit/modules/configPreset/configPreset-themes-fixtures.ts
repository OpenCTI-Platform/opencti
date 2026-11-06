import type { BasicStoreEntityTheme } from '../../../../src/modules/theme/theme-types';

const colors = {
  theme_background: '#070d19',
  theme_paper: '#09101e',
  theme_nav: '#070d19',
  theme_primary: '#0fbcff',
  theme_secondary: '#00f1bd',
  theme_accent: '#0f1e38',
  theme_text_color: '#ffffff',
};

// A custom theme with, next to the import format fields, attributes that must never be exported
export const customTheme = {
  id: 'custom-theme-id',
  internal_id: 'custom-theme-id',
  standard_id: 'theme--3f1e0f0a-2a5c-4e1f-9a1d-7d1c6f0b9e21',
  entity_type: 'Theme',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'SOC night',
  built_in: false,
  ...colors,
  theme_logo: 'data:image/png;base64,AAAA',
  theme_logo_collapsed: '',
  theme_logo_login: 'https://example.com/logo.png',
  theme_login_aside_color: '#000000',
  theme_login_aside_gradient_start: null,
  theme_login_aside_gradient_end: null,
  theme_login_aside_image: null,
} as unknown as BasicStoreEntityTheme;

export const otherCustomTheme = {
  ...customTheme,
  id: 'other-theme-id',
  internal_id: 'other-theme-id',
  standard_id: 'theme--8b0d3c1e-5f4a-4a2b-8c3d-1e2f3a4b5c6d',
  name: 'Customer ACME',
} as unknown as BasicStoreEntityTheme;

export const builtInTheme = {
  ...customTheme,
  id: 'dark-theme-id',
  internal_id: 'dark-theme-id',
  standard_id: 'theme--0d8a3f0e-1c2b-4d5e-8f9a-0b1c2d3e4f5a',
  name: 'Filigran Dark',
  built_in: true,
} as unknown as BasicStoreEntityTheme;

export const ALL_THEMES = [builtInTheme, customTheme, otherCustomTheme];

// The theme import format (themeImportSchema), plus the standard id
export const THEME_FILE_FIELDS = [
  'standard_id',
  'name',
  'theme_background',
  'theme_paper',
  'theme_nav',
  'theme_primary',
  'theme_secondary',
  'theme_accent',
  'theme_text_color',
  'theme_logo',
  'theme_logo_collapsed',
  'theme_logo_login',
  'theme_login_aside_color',
  'theme_login_aside_gradient_start',
  'theme_login_aside_gradient_end',
  'theme_login_aside_image',
];
