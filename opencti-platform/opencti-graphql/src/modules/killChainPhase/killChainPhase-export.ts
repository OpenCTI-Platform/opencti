import type { BasicStoreEntityKillChainPhase } from './killChainPhase-types';
import { killChainPhaseImportSchema } from './killChainPhase-import-schema';

// The fields of a kill chain phase in the configuration: the ones the import accepts, so the import takes the export back as is
const KILL_CHAIN_PHASE_EXPORT_FIELDS = killChainPhaseImportSchema.keyof().options;

// A kill chain phase in the import format. A missing value is left out: the import gives it its default
export const exportKillChainPhase = (phase: BasicStoreEntityKillChainPhase) => {
  const presentFields = KILL_CHAIN_PHASE_EXPORT_FIELDS.filter((field) => (phase[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, phase[field]]));
};
