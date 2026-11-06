import type { BasicStoreEntityLabel } from './label-types';
import { labelImportSchema } from './label-import-schema';

// The fields of a label in the configuration: the ones the import accepts, so the import takes the export back as is
const LABEL_EXPORT_FIELDS = labelImportSchema.keyof().options;

// A label in the import format. A missing value is left out: the import gives it its default
export const exportLabel = (label: BasicStoreEntityLabel) => {
  const presentFields = LABEL_EXPORT_FIELDS.filter((field) => (label[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, label[field]]));
};
