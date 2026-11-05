import { z } from 'zod';

// The rules of a case template to import, whatever the source (a configuration preset): strict, unknown keys are rejected.
// A case template is found by its name on the platform (its standard id is random), and so is each of its tasks (a task template).
const taskSchema = z.strictObject({
  name: z.string().trim().min(1, 'Task name is required'),
  // Absent or null: a new task is given no description, and an existing one is left untouched
  description: z.string().nullable().optional(),
});

export const caseTemplateImportSchema = z.strictObject({
  name: z.string().trim().min(1, 'Case template name is required'),
  // Absent or null: a new template is given none, and an existing one is left untouched
  description: z.string().nullable().optional(),
  // Absent or null: an existing template keeps its tasks. A list replaces them as a whole, an empty one included.
  tasks: z.array(taskSchema).nullable().optional().refine(
    (tasks) => !tasks || new Set(tasks.map(({ name }) => name.toLowerCase())).size === tasks.length,
    'Task names must be unique',
  ),
});

export type CaseTemplateImportConfiguration = z.infer<typeof caseTemplateImportSchema>;
