import { z } from 'zod';

const isPlaybookDefinition = (value: string) => {
  try {
    const definition = JSON.parse(value);
    return !!definition && Array.isArray(definition.nodes) && Array.isArray(definition.links);
  } catch {
    return false;
  }
};

export const playbookImportSchema = z.strictObject({
  name: z.string().trim().min(1),
  description: z.string().nullish(),
  playbook_start: z.string().nullish(),
  playbook_definition: z.string().refine(isPlaybookDefinition, 'Invalid playbook definition'),
});

export type PlaybookImportConfiguration = z.infer<typeof playbookImportSchema>;
