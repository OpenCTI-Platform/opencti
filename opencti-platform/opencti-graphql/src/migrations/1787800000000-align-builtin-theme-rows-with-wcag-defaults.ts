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
 * Only the fields whose SEEDED default moved are listed — the logo and login-aside defaults
 * did not move, so they already match. Each field records EVERY historical default it has
 * carried, because some moved more than once: `theme_secondary` on Light was seeded as
 * `#00BD94` and later as `#00f0bc`, and installations exist on both. A row is rewritten only
 * when it still holds one of them, so an administrator colour is never overwritten and such
 * a row is correctly left to the next migration to preserve and demote. `theme_text_color`
 * moved by letter case alone; rewriting it normalises the row so the strict comparison
 * downstream succeeds.
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
 * Pure part of the migration, so the guard is testable without a database.
 * Returns the field patches to apply — empty when the row was customised.
 */
export const patchesForTheme = (
  themeName: BuiltInThemeName,
  row: Record<string, string | undefined>,
): { key: string; value: string[] }[] => Object.entries(SUPERSEDED[themeName])
  .filter(([key, superseded]) => (superseded as readonly string[])
    .some((v) => row[key]?.toLowerCase() === v.toLowerCase()))
  .map(([key]) => ({ key, value: [CURRENT[themeName][key as keyof typeof DARK_DEFAULTS]] }))
  .filter(({ key, value }) => row[key] !== value[0]);

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
      logMigration.info(`${message} > ${name}: already aligned or customised, left untouched`);
    }
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
