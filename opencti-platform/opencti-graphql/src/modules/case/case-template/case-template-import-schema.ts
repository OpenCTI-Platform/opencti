import { z } from 'zod';

// The rules of a case template to import, whatever the source: strict, unknown keys are rejected.
// A case template is found by its name on the platform (its standard id is random), and so is each of its tasks (a task template).
const taskSchema = z.strictObject({
  // The minimum of the task template form (TaskTemplateAddInput): the import must not store a name the platform refuses
  name: z.string().trim().min(2, 'Task name must be at least 2 characters'),
  // Absent or null: a new task is given no description, and an existing one is left untouched
  description: z.string().nullable().optional(),
});

export const caseTemplateImportSchema = z.strictObject({
  // The minimum of the case template form (CaseTemplateAddInput)
  name: z.string().trim().min(2, 'Case template name must be at least 2 characters'),
  // Absent or null: a new template is given none, and an existing one is left untouched
  description: z.string().nullable().optional(),
  // Absent or null: an existing template keeps its tasks. A list replaces them as a whole, an empty one included.
  tasks: z.array(taskSchema).nullable().optional().refine(
    (tasks) => !tasks || new Set(tasks.map(({ name }) => name.toLowerCase())).size === tasks.length,
    'Task names must be unique',
  ),
});

export type CaseTemplateImportConfiguration = z.infer<typeof caseTemplateImportSchema>;
