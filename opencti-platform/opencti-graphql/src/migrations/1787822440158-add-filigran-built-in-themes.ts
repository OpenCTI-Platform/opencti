import { logMigration } from '../config/conf';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addTheme, fieldPatchTheme, findThemePaginated } from '../modules/theme/theme-domain';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';
import type { BasicStoreEntityTheme } from '../modules/theme/theme-types';
import type { AuthContext } from '../types/user';

const message = '[MIGRATION] Add Filigran built-in themes';

type ThemeDefaultComparable = Pick<BasicStoreEntityTheme,
  | 'theme_background'
  | 'theme_paper'
  | 'theme_nav'
  | 'theme_primary'
  | 'theme_secondary'
  | 'theme_accent'
  | 'theme_text_color'
  | 'theme_logo'
  | 'theme_logo_collapsed'
  | 'theme_logo_login'
  | 'theme_login_aside_color'
  | 'theme_login_aside_gradient_start'
  | 'theme_login_aside_gradient_end'
  | 'theme_login_aside_image'
  | 'built_in'
>;

const defaultDarkThemeValues = {
  theme_background: DARK_DEFAULTS.theme_background,
  theme_paper: DARK_DEFAULTS.theme_paper,
  theme_nav: DARK_DEFAULTS.theme_nav,
  theme_primary: DARK_DEFAULTS.theme_primary,
  theme_secondary: DARK_DEFAULTS.theme_secondary,
  theme_accent: DARK_DEFAULTS.theme_accent,
  theme_text_color: DARK_DEFAULTS.theme_text_color,
  theme_logo: DARK_DEFAULTS.theme_logo,
  theme_logo_collapsed: DARK_DEFAULTS.theme_logo_collapsed,
  theme_logo_login: DARK_DEFAULTS.theme_logo_login,
  theme_login_aside_color: DARK_DEFAULTS.theme_login_aside_color,
  theme_login_aside_gradient_start: DARK_DEFAULTS.theme_login_aside_gradient_start,
  theme_login_aside_gradient_end: DARK_DEFAULTS.theme_login_aside_gradient_end,
  theme_login_aside_image: DARK_DEFAULTS.theme_login_aside_image,
  built_in: true,
};

const defaultLightThemeValues = {
  theme_background: LIGHT_DEFAULTS.theme_background,
  theme_paper: LIGHT_DEFAULTS.theme_paper,
  theme_nav: LIGHT_DEFAULTS.theme_nav,
  theme_primary: LIGHT_DEFAULTS.theme_primary,
  theme_secondary: LIGHT_DEFAULTS.theme_secondary,
  theme_accent: LIGHT_DEFAULTS.theme_accent,
  theme_text_color: LIGHT_DEFAULTS.theme_text_color,
  theme_logo: LIGHT_DEFAULTS.theme_logo,
  theme_logo_collapsed: LIGHT_DEFAULTS.theme_logo_collapsed,
  theme_logo_login: LIGHT_DEFAULTS.theme_logo_login,
  theme_login_aside_color: LIGHT_DEFAULTS.theme_login_aside_color,
  theme_login_aside_gradient_start: LIGHT_DEFAULTS.theme_login_aside_gradient_start,
  theme_login_aside_gradient_end: LIGHT_DEFAULTS.theme_login_aside_gradient_end,
  theme_login_aside_image: LIGHT_DEFAULTS.theme_login_aside_image,
  built_in: true,
};

/**
 * Checks whether a theme matches the expected default-related fields.
 *
 * @param theme Theme entity to compare.
 * @param expectedValues Subset of expected default values.
 * @returns True when all expected keys exist on the theme and values are strictly equal.
 */
const isThemeDefaultLike = (
  theme: BasicStoreEntityTheme | undefined,
  expectedValues: ThemeDefaultComparable,
) => !!theme
  && (Object.entries(expectedValues)).every(([key, value]) => (
    Object.prototype.hasOwnProperty.call(theme, key)
    && theme[key as keyof ThemeDefaultComparable] === value
  ));

/**
 * Refactors a legacy default theme to the Filigran default theme.
 *
 * - If the existing theme still matches default values, it is renamed to the Filigran name.
 * - If it was modified, a new Filigran built-in theme is created and the legacy theme is marked as non built-in.
 * - If a theme already uses the Filigran name, it is first renamed to "<name> - custom" so the built-in name stays free.
 *
 * @param context Migration execution context.
 * @param theme Existing legacy theme (Dark/Light) if present.
 * @param defaultThemeValues Expected default values for the target built-in theme.
 * @param defaultThemeName Target Filigran theme name (Filigran Dark / Filigran Light).
 */
const refactorTheme = async (
  context: AuthContext,
  theme: BasicStoreEntityTheme | undefined,
  defaultThemeValues: ThemeDefaultComparable,
  defaultThemeName: string,
) => {
  if (theme && isThemeDefaultLike(theme, defaultThemeValues)) {
    // rename theme
    const input = [{ key: 'name', value: [defaultThemeName] }];
    await fieldPatchTheme(context, SYSTEM_USER, theme.id, input);
    logMigration.info(`[MIGRATION] ${theme.name} theme renamed in ${defaultThemeName}`);
  } else {
    // if a theme already uses the target name, rename it to free up the Filigran built-in name
    const existingThemes = await findThemePaginated(context, SYSTEM_USER, {
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['name'], values: [defaultThemeName], operator: FilterOperator.Eq }],
        filterGroups: [],
      },
    });
    const conflictingTheme = existingThemes.edges.map((e) => e.node).find((t) => t.name === defaultThemeName);
    if (conflictingTheme) {
      const newName = `${defaultThemeName} - custom`;
      const renameInput = [{ key: 'name', value: [newName] }];
      await fieldPatchTheme(context, SYSTEM_USER, conflictingTheme.id, renameInput);
      logMigration.info(`[MIGRATION] Existing ${defaultThemeName} theme renamed in ${newName}`);
    }
    // add Filigran theme
    await addTheme(context, SYSTEM_USER, { name: defaultThemeName, ...defaultThemeValues });
    logMigration.info(`[MIGRATION] ${defaultThemeName} theme added`);
    if (theme) {
      // put theme as non-built-in
      const input = [{ key: 'built_in', value: [false] }];
      await fieldPatchTheme(context, SYSTEM_USER, theme.id, input);
    }
  }
};

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);

  // Fetch Dark and Light themes
  const context = executionContext('migration');
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['name'], values: ['Light', 'Dark'], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  const themes = await findThemePaginated(context, SYSTEM_USER, { filters });
  const themesList = themes.edges.map((e) => e.node);
  const darkTheme = themesList.find((theme) => theme.name === 'Dark');
  const lightTheme = themesList.find((theme) => theme.name === 'Light');

  // Apply the refactor for dark and light themes
  await refactorTheme(context, darkTheme, defaultDarkThemeValues, 'Filigran Dark');
  await refactorTheme(context, lightTheme, defaultLightThemeValues, 'Filigran Light');

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
