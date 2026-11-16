import { z } from 'zod';

export const markingImportSchema = z.strictObject({
  definition_type: z.string().trim().min(1, 'Marking type is required'),
  definition: z.string().trim().min(1, 'Marking definition is required'),
  x_opencti_color: z.string().min(1, 'Marking color is required').nullable().optional(),
  x_opencti_order: z.number().int().nullable().optional(),
});

export type MarkingImportConfiguration = z.infer<typeof markingImportSchema>;
