import { z } from 'zod';

// The rules of a status template to import, whatever the source: strict, unknown keys are rejected.
// The color reaches CSS in the chips of the statuses: a hex color, the only one the status template form saves. The API takes any string, so a
// template created through it with another value (`red`) is exported but refused here, on purpose: the import does not widen what is stored.
const colorValue = z.string().regex(/^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/, 'Must be a hex color');

export const statusTemplateImportSchema = z.strictObject({
  // The standard id of a status template is derived from its name, without its case: it is not part of the configuration
  // The minimum of the status template form (StatusTemplateAddInput): the import must not store a name the platform refuses
  name: z.string().trim().min(2, 'Status template name must be at least 2 characters'),
  color: colorValue,
});

export type StatusTemplateImportConfiguration = z.infer<typeof statusTemplateImportSchema>;
