import { z } from 'zod';
import { AVAILABLE_LANGUAGES } from '../../user/user-domain';

// Strict schemas of the configuration of each item: unknown keys are rejected, values are checked
// because settingsEditField validates none of them, and the theme values reach CSS and url().
const MAX_TEXT_LENGTH = 5000;
const MAX_SHORT_LENGTH = 255;
const MAX_URL_LENGTH = 2048;
const MAX_DATA_IMAGE_LENGTH = 1_000_000;
const BANNER_LEVELS = ['', 'GREEN', 'RED', 'YELLOW'];

const text = z.string().max(MAX_TEXT_LENGTH).nullish();
const httpUrl = z.string().max(MAX_URL_LENGTH).regex(/^https?:\/\/[^\s()'";{}\\]+$/, 'Must be an http(s) URL');
// Used in CSS: none of ()'";{} or \ or whitespace
const imageValue = z.union([
  z.literal(''),
  z.string().max(MAX_URL_LENGTH).regex(/^https:\/\/[^\s()'";{}\\]+$/, 'Must be an https URL'),
  z.string().max(MAX_DATA_IMAGE_LENGTH).regex(/^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/, 'Must be an image data URL'),
]);
const colorValue = z.string().regex(/^(#[0-9a-fA-F]{3,8}|rgba?\([0-9.,%\s/]+\))$/, 'Must be a color');
const optionalColor = z.union([z.literal(''), colorValue]).nullable().optional();
export const THEME_STANDARD_ID_PATTERN = /^theme--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const platformConfigurationSchema = z.strictObject({
  platform_title: z.string().max(MAX_SHORT_LENGTH).nullish(),
  platform_favicon: httpUrl.nullish(),
  platform_language: z.enum(AVAILABLE_LANGUAGES as [string, ...string[]]).nullish(),
  default_theme: z.strictObject({ standard_id: z.string(), name: z.string().max(MAX_SHORT_LENGTH) }).nullish(),
});

export const messageConfigurationSchemas = {
  banner: z.strictObject({ platform_banner_text: text, platform_banner_level: z.enum(BANNER_LEVELS).nullish() }),
  login: z.strictObject({ platform_login_message: text }),
  consent: z.strictObject({ platform_consent_message: text, platform_consent_confirm_text: text }),
  noAccess: z.strictObject({ platform_no_access_message: text }),
};

export const whitemarkConfigurationSchema = z.strictObject({ platform_whitemark: z.boolean().nullish() });

export const themeConfigurationSchema = z.strictObject({
  standard_id: z.string().regex(THEME_STANDARD_ID_PATTERN, 'Must be a theme standard id'),
  name: z.string().min(1).max(MAX_SHORT_LENGTH),
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

export const THEME_URL_KEYS = ['theme_logo', 'theme_logo_collapsed', 'theme_logo_login', 'theme_login_aside_image'];
