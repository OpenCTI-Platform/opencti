import type { BasicStoreEntityExclusionList } from './exclusionList-types';
import { exclusionListImportSchema } from './exclusionList-import-schema';

// The fields of an exclusion list in the configuration: the ones the import accepts, so the import takes the export back as is.
// The values are not in it: they are the file of the list, written next to it.
const EXCLUSION_LIST_EXPORT_FIELDS = exclusionListImportSchema.keyof().options;

// A missing field is left out: the import gives it its default
export const exportExclusionList = (exclusionList: BasicStoreEntityExclusionList) => {
  const presentFields = EXCLUSION_LIST_EXPORT_FIELDS.filter((field) => (exclusionList[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, exclusionList[field]]));
};
