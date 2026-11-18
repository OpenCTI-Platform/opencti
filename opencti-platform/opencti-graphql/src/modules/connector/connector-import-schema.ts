import { z } from 'zod';

export const connectorImportSchema = z.strictObject({
  name: z.string().trim().min(2, 'Connector name must be at least 2 characters'),
  catalog_id: z.string().min(1),
  manager_contract_image: z.string().min(1),
  confidence_level: z.number().int().min(0).max(100).nullable().optional(),
  manager_contract_configuration: z.array(z.strictObject({ key: z.string().min(1), value: z.string() })),
  required_at_import: z.array(z.string()),
});

export type ConnectorImportConfiguration = z.infer<typeof connectorImportSchema>;
