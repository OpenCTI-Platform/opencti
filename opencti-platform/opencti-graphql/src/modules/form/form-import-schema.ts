import { z } from 'zod';

// The shortest name of a form intake: the rule of its creation, which the import goes through
export const FORM_INTAKE_NAME_MIN_LENGTH = 2;

// The rules of a form intake to import, whatever the source (a configuration preset): strict, unknown keys are rejected.
// The schema of the form is an object, validated against the schema of the forms by the import.
export const formIntakeImportSchema = z.strictObject({
  // The standard id of a form is random: a form is found by its name and its main entity type
  name: z.string().trim().min(FORM_INTAKE_NAME_MIN_LENGTH, `Form intake name must have at least ${FORM_INTAKE_NAME_MIN_LENGTH} characters`),
  // Absent or null: the description of an existing form is left untouched
  // Trimmed as the platform stores it, or an untrimmed description would differ from the stored one on every import
  description: z.string().trim().nullable().optional(),
  form_schema: z.record(z.string(), z.unknown()),
  // The state of the exported form. Not used: a form is imported inactive, and an overwritten one is set inactive
  active: z.boolean().optional(),
});

export type FormIntakeImportConfiguration = z.infer<typeof formIntakeImportSchema>;
