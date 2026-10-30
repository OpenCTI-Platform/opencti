import { z } from 'zod';

// The rules of a role to import, whatever the source: strict, unknown keys are rejected.
// The capabilities are referenced by their name, the same on every platform: they are built-in, never created by a user.
export const roleImportSchema = z.strictObject({
  // The name is the identity of a role: its standard id is computed from it
  name: z.string().trim().min(2, 'Role name must be at least 2 characters'),
  description: z.string().nullable().optional(),
  can_manage_sensitive_config: z.boolean().nullable().optional(),
  capabilities: z.array(z.string()),
  capabilities_in_draft: z.array(z.string()),
});

export type RoleImportConfiguration = z.infer<typeof roleImportSchema>;
