import type { BasicStoreEntity, StoreEntity } from '../../types/store';

// region Database types
export interface BasicStoreEntityTheme extends BasicStoreEntity {
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo: string;
  theme_logo_collapsed: string;
  theme_logo_login: string;
  theme_text_color: string;
  theme_login_aside_color: string;
  theme_login_aside_gradient_start: string;
  theme_login_aside_gradient_end: string;
  theme_login_aside_image: string;
  built_in: boolean;
}

export interface StoreEntityTheme extends StoreEntity {
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo: string;
  theme_logo_collapsed: string;
  theme_logo_login: string;
  theme_text_color: string;
  theme_login_aside_color: string;
  theme_login_aside_gradient_start: string;
  theme_login_aside_gradient_end: string;
  theme_login_aside_image: string;
  built_in: boolean;
}
// endregion
