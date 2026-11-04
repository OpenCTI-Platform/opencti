import type { BasicStoreEntityTheme } from './theme-types';
import { themeImportSchema } from './theme-import-schema';

// The fields of a theme file: the ones the import accepts, without the standard id (the platform gives the theme its own)
const THEME_EXPORT_FIELDS = Object.keys(themeImportSchema.shape).filter((field) => field !== 'standard_id') as (keyof BasicStoreEntityTheme)[];

// A theme in the import format, without its standard id. A missing value is left out: the import format gives it its default
export const getThemeExportConfiguration = (theme: BasicStoreEntityTheme) => {
  const presentFields = THEME_EXPORT_FIELDS.filter((field) => (theme[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, theme[field]]));
};

// A theme in the import format with its standard id, so a configuration preset theme can be imported back and matched
export const getThemeConfigPresetConfiguration = (theme: BasicStoreEntityTheme) => {
  return { standard_id: theme.standard_id, ...getThemeExportConfiguration(theme) };
};

// The export of a theme file: the theme file import takes it back as is, and creates a new theme
export const themeExport = (theme: BasicStoreEntityTheme) => {
  return JSON.stringify(getThemeExportConfiguration(theme), null, 2);
};
