import { z } from 'zod';

// The rules of a label to import, whatever the source (a configuration preset): strict, unknown keys are rejected.
// The color reaches CSS in the chips of the labels: a hex color, the only one the label form saves.
const colorValue = z.string().regex(/^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/, 'Must be a hex color');

export const labelImportSchema = z.strictObject({
  // The standard id of a label is derived from its value: it is not part of the configuration
  value: z.string().trim().min(1, 'Label value is required'),
  // Absent: the platform gives a new label a color of its own, and leaves the color of an existing one untouched
  color: colorValue.nullable().optional(),
});

export type LabelImportConfiguration = z.infer<typeof labelImportSchema>;
