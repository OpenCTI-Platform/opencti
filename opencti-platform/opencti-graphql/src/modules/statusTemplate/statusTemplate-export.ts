import type { BasicStoreEntityStatusTemplate } from './statusTemplate-types';
import { statusTemplateImportSchema } from './statusTemplate-import-schema';

// The fields of a status template in the configuration: the ones the import accepts, so the import takes the export back as is
const STATUS_TEMPLATE_EXPORT_FIELDS = Object.keys(statusTemplateImportSchema.shape) as (keyof BasicStoreEntityStatusTemplate)[];

// A status template in the import format. Its usages (the workflows it is in) are not part of it
export const exportStatusTemplate = (template: BasicStoreEntityStatusTemplate) => {
  return Object.fromEntries(STATUS_TEMPLATE_EXPORT_FIELDS.map((field) => [field, template[field]]));
};
