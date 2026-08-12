import { logMigration } from '../config/conf';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fieldPatchTheme, findThemePaginated } from '../modules/theme/theme-domain';
import { DARK_DEFAULTS, LIGHT_DEFAULTS } from '../modules/theme/theme-constants';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] align built-in theme rows with the WCAG defaults';

/**
 * The two fields whose seeded default moved when the design-system token bridge
 * was regenerated (library PR #62, WCAG 2.1 AA contrast remediation). A row is
 * only rewritten when it still carries the superseded value: anything else is an
 * administrator's own colour and must survive untouched.
 */
export const SUPERSEDED = {
  Dark: { theme_primary: '#0fbcff' },
  Light: { theme_secondary: '#00f0bc' },
} as const;

const CURRENT = { Dark: DARK_DEFAULTS, Light: LIGHT_DEFAULTS } as const;

/**
 * Pure part of the migration, so the guard is testable without a database.
 * Returns the field patches to apply — empty when the row was customised.
 */
export const patchesForTheme = (
  themeName: 'Dark' | 'Light',
  row: Record<string, string | undefined>,
): { key: string; value: string[] }[] => Object.entries(SUPERSEDED[themeName])
  .filter(([key, superseded]) => row[key]?.toLowerCase() === superseded.toLowerCase())
  .map(([key]) => ({ key, value: [CURRENT[themeName][key as keyof typeof DARK_DEFAULTS]] }));

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
    const name = edge.node.name as 'Dark' | 'Light';
    if (name !== 'Dark' && name !== 'Light') continue;
    const patches = patchesForTheme(name, edge.node as unknown as Record<string, string>);
    if (patches.length > 0) {
      // eslint-disable-next-line no-await-in-loop
      await fieldPatchTheme(context, SYSTEM_USER, edge.node.id, patches);
      logMigration.info(`${message} > ${name}: ${patches.map((p) => p.key).join(', ')}`);
    } else {
      logMigration.info(`${message} > ${name}: customised, left untouched`);
    }
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
