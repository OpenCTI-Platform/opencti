import { z } from 'zod';

export const ruleImportSchema = z.strictObject({
  active: z.boolean(),
});

export type RuleImportConfiguration = z.infer<typeof ruleImportSchema>;
