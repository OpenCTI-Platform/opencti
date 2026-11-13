import type { BasicStoreEntityTheme } from './theme-types';
import { themeImportSchema } from './theme-import-schema';

// The fields of an exported theme: the ones the import accepts, the standard id first
const THEME_EXPORT_FIELDS = Object.keys(themeImportSchema.shape) as (keyof BasicStoreEntityTheme)[];

// The one export of a theme, the same for a theme file and for a configuration preset: the import takes it back as is.
// The standard id is always exported: it identifies the theme on every platform it is imported to. The import keeps it optional,
// for the theme files exported before it was added, and checks it where it is needed: to overwrite a theme, and in a bundle,
// where it must be the id of the item. A missing value is left out: the import format gives it its default.
export const exportTheme = (theme: BasicStoreEntityTheme) => {
  const presentFields = THEME_EXPORT_FIELDS.filter((field) => (theme[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, theme[field]]));
};
