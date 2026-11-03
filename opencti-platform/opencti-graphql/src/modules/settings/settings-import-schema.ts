import { z } from 'zod';
import { AVAILABLE_LANGUAGES } from '../user/user-types';
import { THEME_STANDARD_ID_PATTERN } from '../theme/theme-import-schema';

// Strict schemas of the settings a configuration can set (the platform, the messages): unknown keys are rejected,
// values are checked because settingsEditField validates none of them. The themes have their own rules, in the theme module.
const MAX_TEXT_LENGTH = 5000;
const MAX_SHORT_LENGTH = 255;
const MAX_URL_LENGTH = 2048;
const BANNER_LEVELS = ['', 'GREEN', 'RED', 'YELLOW'];

const text = z.string().max(MAX_TEXT_LENGTH).nullish();
const httpUrl = z.string().max(MAX_URL_LENGTH).regex(/^https?:\/\/[^\s()'";{}\\]+$/i, 'Must be an http(s) URL');

export const platformConfigurationSchema = z.strictObject({
  platform_title: z.string().max(MAX_SHORT_LENGTH).nullish(),
  // '' is a favicon that was cleared in the settings, and is exported as it is
  platform_favicon: z.union([z.literal(''), httpUrl]).nullish(),
  platform_language: z.enum(AVAILABLE_LANGUAGES as [string, ...string[]]).nullish(),
  default_theme: z.strictObject({ standard_id: z.string().regex(THEME_STANDARD_ID_PATTERN, 'Must be a theme standard id'), name: z.string().max(MAX_SHORT_LENGTH) }).nullish(),
});

export const whitemarkConfigurationSchema = z.strictObject({
  platform_whitemark: z.boolean().nullish(),
});

export const messageConfigurationSchemas = {
  banner: z.strictObject({ platform_banner_text: text, platform_banner_level: z.enum(BANNER_LEVELS).nullish() }),
  login: z.strictObject({ platform_login_message: text }),
  consent: z.strictObject({ platform_consent_message: text, platform_consent_confirm_text: text }),
  noAccess: z.strictObject({ platform_no_access_message: text }),
};
