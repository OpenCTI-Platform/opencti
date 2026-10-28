import { z } from 'zod';

// The rules of a theme to import, whatever the source (a theme file, a configuration preset): strict, unknown keys are rejected,
// because the values reach CSS and url() on the login page, and the platform does not check them elsewhere.
export const THEME_NAME_MAX_LENGTH = 255;
const MAX_URL_LENGTH = 2048;
const MAX_DATA_IMAGE_LENGTH = 1_000_000;

export const THEME_STANDARD_ID_PATTERN = /^theme--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// An absolute http(s) URL, as the theme form accepts. It reaches CSS (url()) on the login page: none of ()'";{} or \ or whitespace
const imageUrl = z.string().max(MAX_URL_LENGTH).regex(/^https?:\/\/[^\s()'";{}\\]+$/, 'Must be an http(s) URL');
const imageValue = z.union([
  z.literal(''),
  imageUrl,
  z.string().max(MAX_DATA_IMAGE_LENGTH).regex(/^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/, 'Must be an image data URL'),
]);
const colorValue = z.string().regex(/^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/, 'Must be a hex color');
const optionalColor = z.union([z.literal(''), colorValue]).nullable().optional();

export const themeImportSchema = z.strictObject({
  // Absent in a theme file: the platform gives the theme its own
  standard_id: z.string().regex(THEME_STANDARD_ID_PATTERN, 'Must be a theme standard id').optional(),
  name: z.string().min(1, 'Theme name is required').max(THEME_NAME_MAX_LENGTH),
  theme_background: colorValue,
  theme_paper: colorValue,
  theme_nav: colorValue,
  theme_primary: colorValue,
  theme_secondary: colorValue,
  theme_accent: colorValue,
  theme_text_color: colorValue,
  theme_logo: imageValue.optional(),
  theme_logo_collapsed: imageValue.optional(),
  theme_logo_login: imageValue.optional(),
  theme_login_aside_color: optionalColor,
  theme_login_aside_gradient_start: optionalColor,
  theme_login_aside_gradient_end: optionalColor,
  theme_login_aside_image: imageValue.nullable().optional(),
});

export type ThemeImportConfiguration = z.infer<typeof themeImportSchema>;

export const THEME_URL_KEYS = ['theme_logo', 'theme_logo_collapsed', 'theme_logo_login', 'theme_login_aside_image'];
