import { logMigration } from '../config/conf';
import { getEntityFromCache } from '../database/cache';
import { addTheme } from '../modules/theme/theme-domain';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';

import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Creating default themes and replacing platform_theme with Theme ID';

const DARK_DEFAULTS = {
  theme_background: '#070d19',
  theme_paper: '#09101e',
  theme_nav: '#070d19',
  theme_primary: '#0fbcff',
  theme_secondary: '#00f1bd',
  theme_accent: '#0f1e38',
  theme_text_color: '#ffffff',
  theme_logo: '',
  theme_logo_collapsed: '',
  theme_logo_login: '',
};

// Default values for Light theme
const LIGHT_DEFAULTS = {
  theme_background: '#f8f8f8',
  theme_paper: '#ffffff',
  theme_nav: '#ffffff',
  theme_primary: '#001bda',
  theme_secondary: '#0c7e69',
  theme_accent: '#dfdfdf',
  theme_text_color: '#000000',
  theme_logo: '',
  theme_logo_collapsed: '',
  theme_logo_login: '',
};

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const settings = await getEntityFromCache(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_SETTINGS,
  );
  //
  // Create Dark theme with user customizations or defaults
  const darkThemeInput = {
    name: 'Dark',
    theme_background: settings.platform_theme_dark_background || DARK_DEFAULTS.theme_background,
    theme_paper: settings.platform_theme_dark_paper || DARK_DEFAULTS.theme_paper,
    theme_nav: settings.platform_theme_dark_nav || DARK_DEFAULTS.theme_nav,
    theme_primary: settings.platform_theme_dark_primary || DARK_DEFAULTS.theme_primary,
    theme_secondary: settings.platform_theme_dark_secondary || DARK_DEFAULTS.theme_secondary,
    theme_accent: settings.platform_theme_dark_accent || DARK_DEFAULTS.theme_accent,
    theme_text_color: DARK_DEFAULTS.theme_text_color,
    theme_logo: settings.platform_theme_dark_logo || DARK_DEFAULTS.theme_logo,
    theme_logo_collapsed: settings.platform_theme_dark_logo_collapsed || DARK_DEFAULTS.theme_logo_collapsed,
    theme_logo_login: settings.platform_theme_dark_logo_login || DARK_DEFAULTS.theme_logo_login,
    system_default: true
  };

  const darkTheme = await addTheme(context, SYSTEM_USER, darkThemeInput);
  logMigration.info(`${message} > Created Dark theme with ID: ${darkTheme.id}`);

  // Create Light theme with user customizations or defaults
  const lightThemeInput = {
    name: 'Light',
    theme_background: settings.platform_theme_light_background || LIGHT_DEFAULTS.theme_background,
    theme_paper: settings.platform_theme_light_paper || LIGHT_DEFAULTS.theme_paper,
    theme_nav: settings.platform_theme_light_nav || LIGHT_DEFAULTS.theme_nav,
    theme_primary: settings.platform_theme_light_primary || LIGHT_DEFAULTS.theme_primary,
    theme_secondary: settings.platform_theme_light_secondary || LIGHT_DEFAULTS.theme_secondary,
    theme_accent: settings.platform_theme_light_accent || LIGHT_DEFAULTS.theme_accent,
    theme_text_color: LIGHT_DEFAULTS.theme_text_color,
    theme_logo: settings.platform_theme_light_logo || LIGHT_DEFAULTS.theme_logo,
    theme_logo_collapsed: settings.platform_theme_light_logo_collapsed || LIGHT_DEFAULTS.theme_logo_collapsed,
    theme_logo_login: settings.platform_theme_light_logo_login || LIGHT_DEFAULTS.theme_logo_login,
    system_default: true
  };

  const lightTheme = await addTheme(context, SYSTEM_USER, lightThemeInput);
  logMigration.info(`${message} > Created Light theme with ID: ${lightTheme.id}`);

  // Determine which theme ID to use based on old platform_theme setting
  let themeId;
  switch (settings.platform_theme?.toLowerCase()) {
    case 'dark':
      themeId = darkTheme.id;
      break;
    case 'light':
      themeId = lightTheme.id;
      break;
    default:
      // Default to dark if no valid theme specified
      themeId = darkTheme.id;
      break;
  }

  // Update Settings to use the new theme ID
  logMigration.info(`${message} > Changing platform_theme from "${settings.platform_theme}" to ${themeId}`);
  const updateQuery = {
    query: {
      match: {
        'entity_type.keyword': 'Settings'
      }
    },
    script: {
      source: `ctx._source.platform_theme = '${themeId}'`,
      lang: 'painless'
    }
  };

  await elUpdateByQueryForMigration(
    message,
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery,
  );

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  // Optionally: delete created themes and revert platform_theme to 'dark' or 'light'
  next();
};
