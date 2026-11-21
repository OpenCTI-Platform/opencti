import { z } from 'zod';

// The rules of a kill chain phase to import, whatever the source (a configuration preset): strict, unknown keys are rejected.
// A phase is its kill chain name and its phase name: the platform derives its standard id from them, and does not change their case.
export const killChainPhaseImportSchema = z.strictObject({
  kill_chain_name: z.string().trim().min(1, 'Kill chain name is required'),
  phase_name: z.string().trim().min(1, 'Phase name is required'),
  // Absent: a new phase is given the order 0, and the order of an existing one is left untouched
  x_opencti_order: z.number().int().nullable().optional(),
});

export type KillChainPhaseImportConfiguration = z.infer<typeof killChainPhaseImportSchema>;
