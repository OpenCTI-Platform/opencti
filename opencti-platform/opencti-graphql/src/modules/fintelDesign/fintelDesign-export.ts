import type { BasicStoreEntityFintelDesign } from './fintelDesign-types';
import { fintelDesignImportSchema } from './fintelDesign-import-schema';

// The fields of an exported fintel design: the ones the import accepts, the standard id first
const FINTEL_DESIGN_EXPORT_FIELDS = Object.keys(fintelDesignImportSchema.shape) as (keyof BasicStoreEntityFintelDesign)[];

// The export of a fintel design, which the import takes back as is. The standard id identifies the design on every platform it is
// imported to. A missing value is left out, and `default` is always written: the import makes the default design the default again.
// The logo is not here: it is a file written next to the JSON (see fintelDesign-logo).
export const exportFintelDesign = (design: BasicStoreEntityFintelDesign): Record<string, unknown> => {
  const presentFields = FINTEL_DESIGN_EXPORT_FIELDS.filter((field) => field !== 'default' && (design[field] ?? null) !== null);
  return { ...Object.fromEntries(presentFields.map((field) => [field, design[field]])), default: design.default === true };
};
