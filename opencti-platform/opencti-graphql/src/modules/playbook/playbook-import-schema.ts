import { z } from 'zod';

const isNodeConfiguration = (value: string) => {
  try {
    const configuration = JSON.parse(value);
    return !!configuration && typeof configuration === 'object' && !Array.isArray(configuration);
  } catch {
    return false;
  }
};

const playbookDefinitionSchema = z.object({
  nodes: z.array(z.object({
    id: z.string(),
    name: z.string(),
    position: z.object({ x: z.number(), y: z.number() }),
    component_id: z.string(),
    configuration: z.string().refine(isNodeConfiguration),
    description: z.string().nullish(),
  })),
  links: z.array(z.object({
    id: z.string(),
    from: z.object({ id: z.string(), port: z.string() }),
    to: z.object({ id: z.string() }),
  })),
});

const isPlaybookDefinition = (value: string) => {
  try {
    return playbookDefinitionSchema.safeParse(JSON.parse(value)).success;
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
