import { z } from 'zod';

// The rules of a status template to import, whatever the source (a configuration preset): strict, unknown keys are rejected.
// The color reaches CSS in the chips of the statuses: a hex color, the only one the status template form saves.
const colorValue = z.string().regex(/^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/, 'Must be a hex color');

export const statusTemplateImportSchema = z.strictObject({
  // The standard id of a status template is derived from its name, without its case: it is not part of the configuration
  name: z.string().trim().min(1, 'Status template name is required'),
  color: colorValue,
});

export type StatusTemplateImportConfiguration = z.infer<typeof statusTemplateImportSchema>;
