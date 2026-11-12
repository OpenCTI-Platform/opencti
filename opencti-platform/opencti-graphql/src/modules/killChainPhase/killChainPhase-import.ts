import { storeLoadById } from '../../database/middleware-loader';
import { addKillChainPhase, killChainPhaseEditField } from '../../domain/killChainPhase';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../schema/stixMetaObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportRefusal, configImportValidationReason } from '../configImport/configImport-utils';
import { type KillChainPhaseImportConfiguration, killChainPhaseImportSchema } from './killChainPhase-import-schema';
import type { BasicStoreEntityKillChainPhase } from './killChainPhase-types';

export type KillChainPhaseImportCode = 'invalid' | 'exists' | 'copy_unsupported' | 'unchanged';

export type KillChainPhaseImportResult = ConfigImportResult<KillChainPhaseImportConfiguration, KillChainPhaseImportCode>;

// The standard id of a phase is derived from its phase name and its kill chain name, as they are (surrounding spaces do not count):
// the same on every platform
export const getKillChainPhaseStandardId = ({ kill_chain_name: killChainName, phase_name: phaseName }: { kill_chain_name: string; phase_name: string }) => {
  return generateStandardId(ENTITY_TYPE_KILL_CHAIN_PHASE, { kill_chain_name: killChainName, phase_name: phaseName });
};

const refused = configImportRefusal<KillChainPhaseImportConfiguration, KillChainPhaseImportCode>;

// The one place where a kill chain phase is imported: validates, finds the phase by its kill chain name and phase name and writes it.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// add: the phase must not exist yet. overwrite: a phase of the same kill chain and name is given the order of the configuration, else it
// is created; an order that is null or absent leaves the phase untouched. A phase is its names: it has no copy.
export const importKillChainPhase = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<KillChainPhaseImportResult> => {
  const parsed = killChainPhaseImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { kill_chain_name: killChainName, phase_name: phaseName, x_opencti_order: order } = parsed.data;
  const existing = await storeLoadById<BasicStoreEntityKillChainPhase>(context, user, getKillChainPhaseStandardId(parsed.data), ENTITY_TYPE_KILL_CHAIN_PHASE);
  if (mode === ConfigImportMode.Copy) {
    return refused('failed', 'copy_unsupported', 'A kill chain phase has no copy', !!existing, parsed.data);
  }
  if (!existing) {
    if (!dryRun) {
      await addKillChainPhase(context, user, { kill_chain_name: killChainName, phase_name: phaseName, x_opencti_order: order ?? 0 });
    }
    return { status: 'created', exists: false, configuration: parsed.data };
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Kill chain phase already exists', true, parsed.data);
  }
  // 0 is an order: only null and absent leave it untouched
  if (order === null || order === undefined || order === existing.x_opencti_order) {
    return refused('skipped', 'unchanged', 'Already up to date', true, parsed.data);
  }
  if (!dryRun) {
    await killChainPhaseEditField(context, user, existing.id, [{ key: 'x_opencti_order', value: [order] }]);
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
