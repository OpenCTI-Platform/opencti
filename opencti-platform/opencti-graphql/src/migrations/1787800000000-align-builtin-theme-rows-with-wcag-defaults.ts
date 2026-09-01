import { logMigration } from '../config/conf';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fieldPatchTheme, findThemePaginated } from '../modules/theme/theme-domain';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] align built-in theme rows with the WCAG defaults';

/**
 * Runs BEFORE `1787822440159-add-filigran-built-in-themes`, deliberately: aligning the
 * seeded defaults first makes that migration's strict comparison succeed, so it renames
 * the row instead of seeding a second one. A row with any unrecognised value is skipped
 * ENTIRELY. Full rationale: fds-migration/MIGRATION-DECISIONS.md#builtin-theme-migration-order
 */
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

const COMPARED_FIELDS = [
  'theme_background', 'theme_paper', 'theme_nav', 'theme_primary', 'theme_secondary',
  'theme_accent', 'theme_text_color', 'theme_logo', 'theme_logo_collapsed', 'theme_logo_login',
  'theme_login_aside_color', 'theme_login_aside_gradient_start', 'theme_login_aside_gradient_end',
  'theme_login_aside_image',
] as const;

const knownValues = (themeName: BuiltInThemeName, key: string): string[] => [
  CURRENT[themeName][key as keyof typeof DARK_DEFAULTS],
  ...((SUPERSEDED[themeName] as Record<string, readonly string[]>)[key] ?? []),
];

export const isRowOnDefaults = (
  themeName: BuiltInThemeName,
  row: Record<string, string | undefined>,
): boolean => COMPARED_FIELDS.every((key) => {
  const value = row[key];
  if (value === undefined) return false;
  return knownValues(themeName, key).some((known) => known.toLowerCase() === value.toLowerCase());
});

export const patchesForTheme = (
  themeName: BuiltInThemeName,
  row: Record<string, string | undefined>,
): { key: string; value: string[] }[] => {
  if (!isRowOnDefaults(themeName, row)) return [];
  return Object.keys(SUPERSEDED[themeName])
    .map((key) => ({ key, value: [CURRENT[themeName][key as keyof typeof DARK_DEFAULTS]] }))
    .filter(({ key, value }) => row[key] !== value[0]);
};

export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['name'], values: ['Light', 'Dark'], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  const themes = await findThemePaginated(context, SYSTEM_USER, { filters });
  for (const edge of themes.edges) {
    const name = edge.node.name as BuiltInThemeName;
    if (name !== 'Dark' && name !== 'Light') continue;
    const patches = patchesForTheme(name, edge.node as unknown as Record<string, string>);
    if (patches.length > 0) {
      await fieldPatchTheme(context, SYSTEM_USER, edge.node.id, patches);
      logMigration.info(`${message} > ${name}: ${patches.map((p) => p.key).join(', ')}`);
    } else {
      const why = isRowOnDefaults(name, edge.node as unknown as Record<string, string>)
        ? 'already aligned' : 'customised';
      logMigration.info(`${message} > ${name}: ${why}, left untouched`);
    }
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
