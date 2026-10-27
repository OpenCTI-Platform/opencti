import { logApp, logMigration } from '../../config/conf';
import { elReplace } from '../../database/engine';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { findThemePaginated } from '../theme/theme-domain';
import { BUILT_IN_THEME_STANDARD_IDS } from '../theme/theme-constants';

const message = '[MIGRATION] Config preset standard ids';

// The built-in themes get the standard id the same on every platform, so that a bundle can reference them
export const migrateBuiltInThemesStandardIds = async (context: AuthContext) => {
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
};

// Single entry point of the standard id migrations of the types a bundle exports: each type adds its step here.
// Not called yet: one migration will call it once every type is ready, instead of one migration per type.
export const migrateStandardIdsForConfigPreset = async (context: AuthContext) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  await migrateBuiltInThemesStandardIds(context);
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
};
