import { z } from 'zod';

// The rules of a fintel design to import: strict, unknown keys are rejected. The colors reach the style of the generated documents.
// The logo is not part of the configuration: it is a file of the bundle, next to the JSON of the design.
export const FINTEL_DESIGN_NAME_MAX_LENGTH = 255;

export const FINTEL_DESIGN_STANDARD_ID_PATTERN = /^finteldesign--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const optionalColor = z.union([z.literal(''), z.string().regex(/^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/, 'Must be a hex color')]).nullable().optional();

export const fintelDesignImportSchema = z.strictObject({
  // The identity of the design on every platform it is imported to: required, a design is found by it
  standard_id: z.string().regex(FINTEL_DESIGN_STANDARD_ID_PATTERN, 'Must be a fintel design standard id'),
  name: z.string().max(FINTEL_DESIGN_NAME_MAX_LENGTH).refine((name) => name.trim() !== '', 'Fintel design name is required'),
  description: z.string().nullable().optional(),
  gradiantFromColor: optionalColor,
  gradiantToColor: optionalColor,
  textColor: optionalColor,
  // The default design of the platform it was exported from: it becomes the default of the platform it is imported to
  default: z.boolean().optional(),
});

export type FintelDesignImportConfiguration = z.infer<typeof fintelDesignImportSchema>;
