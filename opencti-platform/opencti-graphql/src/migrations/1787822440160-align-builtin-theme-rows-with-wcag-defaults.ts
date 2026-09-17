import { logMigration } from '../config/conf';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fieldPatchTheme, findThemePaginated } from '../modules/theme/theme-domain';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { FunctionalError } from '../config/errors';

const message = '[MIGRATION] Align Filigran built-in theme with the WCAG defaults';

type ThemeDefaultField = keyof typeof DARK_DEFAULTS;
type BuiltInThemeName = 'Filigran Dark' | 'Filigran Light';

const MODIFIED_DEFAULT_THEME_FIELDS: Record<BuiltInThemeName, ThemeDefaultField[]> = {
  'Filigran Dark': [
    'theme_background',
    'theme_paper',
    'theme_nav',
    'theme_primary',
    'theme_secondary',
    'theme_accent',
    'theme_text_color',
  ],
  'Filigran Light': [
    'theme_background',
    'theme_nav',
    'theme_secondary',
    'theme_accent',
    'theme_text_color',
  ],
};

const CURRENT_DEFAULT_THEME_FIELDS: Record<BuiltInThemeName, Record<ThemeDefaultField, string>> = {
  'Filigran Dark': DARK_DEFAULTS,
  'Filigran Light': LIGHT_DEFAULTS,
};

const patchesForTheme = (
  themeName: BuiltInThemeName,
): { key: string; value: string[] }[] => {
  return MODIFIED_DEFAULT_THEME_FIELDS[themeName]
    .map((key) => ({ key, value: [CURRENT_DEFAULT_THEME_FIELDS[themeName][key]] }));
};

export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['name'], values: ['Filigran Light', 'Filigran Dark'], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  const themes = await findThemePaginated(context, SYSTEM_USER, { filters });
  const themesList = themes.edges.map((e) => e.node);
  const darkTheme = themesList.find((theme) => theme.name === 'Filigran Dark');
  const lightTheme = themesList.find((theme) => theme.name === 'Filigran Light');
  if (!darkTheme) {
    throw FunctionalError('Missing Filigran Dark default theme');
  }
  if (!lightTheme) {
    throw FunctionalError('Missing Filigran Light default theme');
  }
  for (const filigranTheme of [darkTheme, lightTheme]) {
    const themeName = filigranTheme.name as BuiltInThemeName;
    const themeId = filigranTheme.id;
    const inputs = patchesForTheme(themeName);
    await fieldPatchTheme(context, SYSTEM_USER, themeId, inputs);
    logMigration.info(`${message} > ${themeName} theme updated`);
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
