interface ThemeType {
  id: string;
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo?: string | null;
  theme_logo_collapsed?: string | null;
  theme_logo_login?: string | null;
  theme_text_color: string;
  theme_login_aside_type?: string | null;
  theme_login_aside_color?: string | null;
  theme_login_aside_gradient_end?: string | null;
  theme_login_aside_gradient_start?: string | null;
  theme_login_aside_image?: string | null;
  system_default?: boolean | null;
}

export default ThemeType;
