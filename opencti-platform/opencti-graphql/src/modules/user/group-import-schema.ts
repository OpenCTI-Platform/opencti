import { z } from 'zod';

const entityReference = z.strictObject({
  standard_id: z.string().min(1),
  name: z.string(),
});

const markingReference = z.strictObject({
  standard_id: z.string().min(1),
  definition_type: z.string(),
  definition: z.string(),
});

const confidence = z.number().int().min(0).max(100);

export const groupImportSchema = z.strictObject({
  name: z.string().trim().min(2, 'Group name must be at least 2 characters'),
  description: z.string().nullable().optional(),
  default_assignation: z.boolean().nullable().optional(),
  auto_integration_assignation: z.array(z.string()).nullable().optional(),
  no_creators: z.boolean().nullable().optional(),
  restrict_delete: z.boolean().nullable().optional(),
  auto_new_marking: z.boolean().nullable().optional(),
  group_confidence_level: z.strictObject({
    max_confidence: confidence,
    overrides: z.array(z.strictObject({ entity_type: z.string(), max_confidence: confidence })),
  }).nullable().optional(),
  default_hidden_types: z.array(z.string()).nullable().optional(),
  default_dashboard: entityReference.nullable().optional(),
  roles: z.array(entityReference),
  allowed_markings: z.array(markingReference),
  default_marking: z.array(z.strictObject({ entity_type: z.string(), values: z.array(markingReference) })),
  max_shareable_markings: z.array(z.strictObject({ type: z.string(), value: z.union([z.literal('none'), markingReference]) })),
});

export type GroupImportConfiguration = z.infer<typeof groupImportSchema>;
export type GroupMarkingReference = z.infer<typeof markingReference>;
