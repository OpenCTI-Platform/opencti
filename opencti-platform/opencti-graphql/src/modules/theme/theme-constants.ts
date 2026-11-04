export const FILIGRAN_DARK_THEME_NAME = 'Filigran Dark';
export const FILIGRAN_LIGHT_THEME_NAME = 'Filigran Light';

// Fixed standard ids of the built-in themes, identical on every platform so that a
// configuration bundle can reference them. Frozen values of
// idGenFromData(ENTITY_TYPE_THEME, { name }): never change them.
// Custom themes keep a random standard id (theme.ts identifier).
export const BUILT_IN_THEME_STANDARD_IDS: Record<string, string> = {
  [FILIGRAN_DARK_THEME_NAME]: 'theme--d2685d62-9005-5d3c-9d77-b6b633599648',
  [FILIGRAN_LIGHT_THEME_NAME]: 'theme--29754579-d178-5457-801d-92f9a1129174',
};

// Default values for Dark theme
// Kept in sync with THEME_DARK_DEFAULT_* in opencti-front/src/components/ThemeDark.ts
// (FDS bridge, fds-migration/TOKEN-MAPPING.md §1) so brand-new environments seed
// built_in theme rows with the same values the frontend falls back to.
export const DARK_DEFAULTS = {
  theme_background: '#070d18',
  theme_paper: '#0d172b',
  theme_nav: '#070d18',
  theme_primary: '#42caff',
  theme_secondary: '#00f0bc',
  theme_accent: '#1f3965',
  theme_text_color: '#f2f2f3',
  theme_logo: '',
  theme_logo_collapsed: '',
  theme_logo_login: '',
  theme_login_aside_color: '',
  theme_login_aside_gradient_start: '',
  theme_login_aside_gradient_end: '',
  theme_login_aside_image: '',
};

// Default values for Light theme
// Kept in sync with THEME_LIGHT_DEFAULT_* in opencti-front/src/components/ThemeLight.ts
// (FDS bridge, fds-migration/TOKEN-MAPPING.md §1) so brand-new environments seed
// built_in theme rows with the same values the frontend falls back to.
export const LIGHT_DEFAULTS = {
  theme_background: '#f2f2f3',
  theme_paper: '#ffffff',
  theme_nav: '#f2f2f3',
  theme_primary: '#0015a8',
  theme_secondary: '#009474',
  theme_accent: '#e4e5e7',
  theme_text_color: '#18191b',
  theme_logo: '',
  theme_logo_collapsed: '',
  theme_logo_login: '',
  theme_login_aside_color: '',
  theme_login_aside_gradient_start: '',
  theme_login_aside_gradient_end: '',
  theme_login_aside_image: '',
};
