import { logMigration } from '../config/conf';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fieldPatchTheme, findThemePaginated } from '../modules/theme/theme-domain';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] align built-in theme rows with the WCAG defaults';

/**
 * Runs BEFORE `1787822440159-add-filigran-built-in-themes`, and deliberately so.
 *
 * That migration compares each built-in row against the constants field by field, with a
 * strict `===`. When they match it simply renames the row to `Filigran Dark` / `Filigran
 * Light`; when they do not, it seeds a second built-in row and demotes the original. The
 * design-system bridge moved these seeded defaults, so without this pass every existing
 * installation would take the second branch and end up with four themes, the WCAG values
 * never reaching the users who stay on the original one.
 *
 * Aligning first makes the comparison succeed, so the rename is clean and the WCAG values
 * travel with the row. The rows are still named `Dark` / `Light` at this point.
 *
 * The row is judged AS A WHOLE before anything is written (product ruling): every field the
 * downstream migration compares must still hold a value we recognise as a default — the
 * current one, or one of the historical ones it has carried. One unrecognised value anywhere
 * marks the row as customised and it is skipped ENTIRELY, including the fields that are
 * still on defaults. A half-aligned theme is not a state anyone asked for, and such a row is
 * exactly what the next migration is meant to preserve and demote.
 *
 * Only the fields whose SEEDED default moved need rewriting — the logo and login-aside
 * defaults did not move. Each records EVERY historical default it has carried, because some
 * moved more than once: `theme_secondary` on Light was seeded as `#00BD94` and later as
 * `#00f0bc`, and installations exist on both. `theme_text_color` moved by letter case alone;
 * rewriting it normalises the row so the strict comparison downstream succeeds.
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

/**
 * The fields `1787822440159-add-filigran-built-in-themes` compares (`ThemeDefaultComparable`).
 * The judgement below spans exactly that set: a row this pass declares clean is a row that
 * migration will then recognise.
 */
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

/**
 * True when every compared field still holds a value we shipped. A missing field counts as
 * unrecognised: we cannot vouch for it, and the downstream comparison would reject the row
 * anyway.
 */
export const isRowOnDefaults = (
  themeName: BuiltInThemeName,
  row: Record<string, string | undefined>,
): boolean => COMPARED_FIELDS.every((key) => {
  const value = row[key];
  if (value === undefined) return false;
  return knownValues(themeName, key).some((known) => known.toLowerCase() === value.toLowerCase());
});

/**
 * Pure part of the migration, so the guard is testable without a database.
 * Returns the field patches to apply — empty when the row shows any customisation.
 */
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
