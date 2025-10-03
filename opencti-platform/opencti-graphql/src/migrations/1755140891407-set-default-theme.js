import { logMigration } from '../config/conf';
import { getEntityFromCache } from '../database/cache';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, toBase64 } from '../database/utils';
import { editTheme, findAll } from '../modules/theme/theme-domain';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Replacing platform theme with Theme ID';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const {
    platform_theme,
    platform_theme_dark_background,
    platform_theme_dark_paper,
    platform_theme_dark_nav,
    platform_theme_dark_primary,
    platform_theme_dark_secondary,
    platform_theme_dark_accent,
    platform_theme_dark_logo,
    platform_theme_dark_logo_collapsed,
    platform_theme_dark_logo_login,
    platform_theme_light_background,
    platform_theme_light_paper,
    platform_theme_light_nav,
    platform_theme_light_primary,
    platform_theme_light_secondary,
    platform_theme_light_accent,
    platform_theme_light_logo,
    platform_theme_light_logo_collapsed,
    platform_theme_light_logo_login,
  } = await getEntityFromCache(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_SETTINGS,
  );
  // findAll creates Dark and Light themes when no custom themes exist
  //   const themes = await findAll(context, {});
  //   const darkThemeId = themes.edges.find(({ node }) => node?.name === 'Dark')?.node.id;
  //   const lightThemeId = themes.edges.find(({ node }) => node?.name === 'Light')?.node.id;
  //
  //   // Update base Dark and Light themes with existing platform modifications
  //   const darkThemeManifest = toBase64(JSON.stringify({
  //     theme_background: platform_theme_dark_background ?? '#070d19',
  //     theme_paper: platform_theme_dark_paper ?? '#09101e',
  //     theme_nav: platform_theme_dark_nav ?? '#070d19',
  //     theme_primary: platform_theme_dark_primary ?? '#0fbcff',
  //     theme_secondary: platform_theme_dark_secondary ?? '#00f1bd',
  //     theme_accent: platform_theme_dark_accent ?? '#0f1e38',
  //     theme_logo: platform_theme_dark_logo ?? '',
  //     theme_logo_collapsed: platform_theme_dark_logo_collapsed ?? '',
  //     theme_logo_login: platform_theme_dark_logo_login ?? '',
  //     theme_text_color: '#ffffff',
  //     system_default: true,
  //   }));
  //   await editTheme(context, SYSTEM_USER, darkThemeId, [{
  //     key: 'manifest',
  //     value: [darkThemeManifest],
  //   }]);
  //   const lightThemeManifest = toBase64(JSON.stringify({
  //     theme_background: platform_theme_light_background ?? '#f8f8f8',
  //     theme_paper: platform_theme_light_paper ?? '#ffffff',
  //     theme_nav: platform_theme_light_nav ?? '#ffffff',
  //     theme_primary: platform_theme_light_primary ?? '#001bda',
  //     theme_secondary: platform_theme_light_secondary ?? '#0c7e69',
  //     theme_accent: platform_theme_light_accent ?? '#eeeeee',
  //     theme_logo: platform_theme_light_logo ?? '',
  //     theme_logo_collapsed: platform_theme_light_logo_collapsed ?? '',
  //     theme_logo_login: platform_theme_light_logo_login ?? '',
  //     theme_text_color: '#000000',
  //     system_default: true,
  //   }));
  //   await editTheme(context, SYSTEM_USER, lightThemeId, [{
  //     key: 'manifest',
  //     value: [lightThemeManifest],
  //   }]);
  //
  //   let themeId;
  //   switch (platform_theme) {
  //     case 'dark':
  //     case 'Dark':
  //       themeId = darkThemeId;
  //       break;
  //     case 'light':
  //     case 'Light':
  //       themeId = lightThemeId;
  //       break;
  //     default:
  //       break;
  //   }
  //
  //   if (themeId) {
  //     logMigration.info(`${message} > changing platform theme from ${platform_theme} to ${themeId}`);
  //     const updateQuery = {
  //       query: {
  //         match: {
  //           'entity_type.keyword': 'Settings'
  //         }
  //       },
  //       script: {
  //         source: `ctx._source.platform_theme = '${themeId}'`,
  //         lang: 'painless'
  //       }
  //     };
  //     await elUpdateByQueryForMigration(
  //       message,
  //       [READ_INDEX_INTERNAL_OBJECTS],
  //       updateQuery,
  //     );
  //   }
  //
  //   logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
