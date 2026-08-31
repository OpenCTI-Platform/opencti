import { logMigration } from '../config/conf';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fieldPatchTheme, findThemePaginated } from '../modules/theme/theme-domain';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] align the Filigran built-in theme rows with the WCAG defaults';

/**
 * Runs after `1787822440159-add-filigran-built-in-themes`, and targets the rows that
 * migration leaves behind: `Filigran Dark` and `Filigran Light`.
 *
 * That migration seeds a built-in row whenever the legacy one no longer matches the
 * constants — which is the case on every existing installation, because the design-system
 * bridge moved these values. Whether the row it produces already carries them depends on
 * which side of the merge the constants came from, so this migration states the outcome
 * instead of assuming it: every value the bridge moved is written explicitly.
 *
 * Only the fields whose SEEDED default moved are listed. For each one the historical value
 * is recorded, and the row is rewritten only when it still carries that exact value — an
 * administrator colour is never overwritten. `theme_text_color` moved by letter case alone;
 * rewriting it normalises the row so a later strict comparison against the constants
 * succeeds.
 */
export const SUPERSEDED = {
  'Filigran Dark': {
    theme_background: '#070d19',
    theme_paper: '#09101e',
    theme_nav: '#070d19',
    theme_primary: '#0fbcff',
    theme_secondary: '#00f18d',
    theme_accent: '#0f1e38',
    theme_text_color: '#F2F2F3',
  },
  'Filigran Light': {
    theme_background: '#ececf2',
    theme_nav: '#ffffff',
    theme_secondary: '#00BD94',
    theme_accent: '#dfdfdf',
    theme_text_color: '#18191B',
  },
} as const;

export type FiligranThemeName = keyof typeof SUPERSEDED;

const CURRENT = {
  'Filigran Dark': DARK_DEFAULTS,
  'Filigran Light': LIGHT_DEFAULTS,
} as const;

/**
 * Pure part of the migration, so the guard is testable without a database.
 * Returns the field patches to apply — empty when the row was customised.
 */
export const patchesForTheme = (
  themeName: FiligranThemeName,
  row: Record<string, string | undefined>,
): { key: string; value: string[] }[] => Object.entries(SUPERSEDED[themeName])
  .filter(([key, superseded]) => row[key]?.toLowerCase() === superseded.toLowerCase())
  .map(([key]) => ({ key, value: [CURRENT[themeName][key as keyof typeof DARK_DEFAULTS]] }))
  .filter(({ key, value }) => row[key] !== value[0]);

export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const names = Object.keys(SUPERSEDED) as FiligranThemeName[];
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['name'], values: [...names], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  const themes = await findThemePaginated(context, SYSTEM_USER, { filters });
  for (const edge of themes.edges) {
    const name = edge.node.name as FiligranThemeName;
    if (!names.includes(name)) continue;
    const patches = patchesForTheme(name, edge.node as unknown as Record<string, string>);
    if (patches.length > 0) {
      // SYSTEM_USER on purpose: built-in themes reject every other writer.
      // eslint-disable-next-line no-await-in-loop
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
