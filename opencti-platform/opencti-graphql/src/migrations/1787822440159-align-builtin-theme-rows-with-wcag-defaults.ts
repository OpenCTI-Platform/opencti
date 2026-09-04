import { logMigration } from '../config/conf';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fieldPatchTheme, findThemePaginated } from '../modules/theme/theme-domain';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Align Filigran built-in theme with the WCAG defaults';

export const SUPERSEDED = {
  Dark: {
    theme_background: ['#070d19'],
    theme_paper: ['#09101e'],
    theme_nav: ['#070d19'],
    theme_primary: ['#0fbcff'],
    theme_secondary: ['#00f18d'],
    theme_accent: ['#0f1e38'],
    theme_text_color: ['#F2F2F3'],
  },
  Light: {
    theme_background: ['#ececf2'],
    theme_nav: ['#ffffff'],
    theme_secondary: ['#00BD94', '#00f0bc'],
    theme_accent: ['#dfdfdf'],
    theme_text_color: ['#18191B'],
  },
} as const;

export type BuiltInThemeName = keyof typeof SUPERSEDED;

const CURRENT = { Dark: DARK_DEFAULTS, Light: LIGHT_DEFAULTS } as const;

export const patchesForTheme = (
  themeName: BuiltInThemeName,
  row: Record<string, string | undefined>,
): { key: string; value: string[] }[] => {
  return Object.keys(SUPERSEDED[themeName])
    .map((key) => ({ key, value: [CURRENT[themeName][key as keyof typeof DARK_DEFAULTS]] }))
    .filter(({ key, value }) => row[key] !== value[0]);
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
  for (const edge of themes.edges) {
    const filigranTheme = edge.node as unknown as Record<string, string>;
    const name = filigranTheme.name as BuiltInThemeName;
    const id = filigranTheme.id;
    const inputs = patchesForTheme(name, filigranTheme);
    await fieldPatchTheme(context, SYSTEM_USER, id, inputs);
    logMigration.info(`${message} > ${name} theme updated`);
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
