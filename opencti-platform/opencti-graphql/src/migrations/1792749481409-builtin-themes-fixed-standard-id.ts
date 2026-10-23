import { logApp, logMigration } from '../config/conf';
import { elReplace } from '../database/engine';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { findThemePaginated } from '../modules/theme/theme-domain';
import { BUILT_IN_THEME_STANDARD_IDS } from '../modules/theme/theme-constants';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Give the built-in themes their fixed standard id';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const builtInNames = Object.keys(BUILT_IN_THEME_STANDARD_IDS);
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['name'], values: builtInNames, operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  const themes = await findThemePaginated(context, SYSTEM_USER, { filters });
  for (const themeName of builtInNames) {
    const fixedStandardId = BUILT_IN_THEME_STANDARD_IDS[themeName];
    const theme = themes.edges.map((e) => e.node).find((t) => t.name === themeName && t.built_in);
    if (!theme) {
      logApp.warn(`${message} > ${themeName} built-in theme not found, skipped`);
    } else if (theme.standard_id === fixedStandardId) {
      logMigration.info(`${message} > ${themeName} already has its fixed standard id`);
    } else {
      // standard_id is not updatable through updateAttribute (update: false): write the document directly.
      await elReplace(context, theme._index, theme.internal_id, { doc: { standard_id: fixedStandardId } });
      logMigration.info(`${message} > ${themeName} standard id updated`);
    }
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
