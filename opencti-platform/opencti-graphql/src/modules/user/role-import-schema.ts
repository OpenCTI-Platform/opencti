import { z } from 'zod';

export const roleImportSchema = z.strictObject({
  name: z.string().trim().min(2, 'Role name must be at least 2 characters'),
  description: z.string().nullable().optional(),
  can_manage_sensitive_config: z.boolean().nullable().optional(),
  capabilities: z.array(z.string()),
  capabilities_in_draft: z.array(z.string()),
});

export type RoleImportConfiguration = z.infer<typeof roleImportSchema>;
