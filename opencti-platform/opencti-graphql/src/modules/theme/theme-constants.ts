// Default values for Dark theme
// Kept in sync with THEME_DARK_DEFAULT_* in opencti-front/src/components/ThemeDark.ts
// (FDS bridge, fds-migration/TOKEN-MAPPING.md §1) so brand-new environments seed
// built_in theme rows with the same values the frontend falls back to.
export const DARK_DEFAULTS = {
  theme_background: '#070d18',
  theme_paper: '#0d172b',
  theme_nav: '#070d18',
  theme_primary: '#0fbcff',
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
  theme_secondary: '#00f0bc',
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
