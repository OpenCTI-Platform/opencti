import type { AuthContext } from '../../types/user';
import { fullEntitiesList, fullRelationsList } from '../../database/middleware-loader';
import { createEntity, deleteElementById, patchAttribute } from '../../database/middleware';
import { logMigration } from '../../config/conf';
import { SYSTEM_USER } from '../../utils/access';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { type BasicStoreEntityPir, type BasicStoreRelationPir, ENTITY_TYPE_PIR } from '../pir/pir-types';
import { updatePirInformationOnEntity } from '../pir/pir-utils';
import { unregisterConnector } from '../connector/connector-rabbitmq';
import { type BasicStoreEntityPlaybook, ENTITY_TYPE_PLAYBOOK } from '../playbook/playbook-types';
import { rewritePlaybookDefinition } from './intelligenceRequirement-pirPlaybook';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT } from './intelligenceRequirement-types';
import { ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH } from './intelligenceRequirementMatch-types';
import { invalidateInRequirementEntityIds, listMatchesForEntities } from './intelligenceRequirementMatch-domain';
import { entityDisplayName } from './intelligenceRequirementItem-domain';
import { checkInPirParity, inPirRelationToMatch, linkPirToRequirement, type PirParityMismatch } from './intelligenceRequirement-pirLink';

// Full replacement of the PIR engine (opencti #20278): every Pir becomes an intelligence requirement, then the Pir is deleted.
// Called by the migration 1795536000000 only, which runs before the managers start (no engine reads the stream meanwhile).
//
// Per Pir, in order, each step safe to run again:
// 1. link: the requirement built from the Pir (criteria, filters, weights, rescan window, authorized members), ir_pir_id = the Pir;
// 2. parity: every in-pir flag projects back to the same score and explanations, else the Pir is kept and reported;
// 3. seed: each flag becomes an entity of the requirement (status auto, its proofs, its score); an entity already there is kept;
// 4. activate the requirement at the stream position of the Pir (no event read twice, none skipped);
// 5. clear pir_information of the flagged entities, drop the Pir queue, delete the Pir and its in-pir flags.
// A Pir that fails any step is logged, kept (never deleted) and listed in the report; the next run of the migration retries it.
// Then every playbook that starts on "Listen PIR events" is rewritten to "Listen intelligence requirement events",
// its Pir ids replaced by the ids of their requirements (read from ir_pir_id, so a resumed run finds Pirs deleted by the last one).

export type PirConversion =
  | { pir_id: string; name: string; converted: true; requirement_id: string; flags: number; seeded: number }
  | { pir_id: string; name: string; converted: false; reason: string; mismatches?: PirParityMismatch[] };

export interface PirMigrationReport {
  pirs: number;
  converted: number;
  failed: PirConversion[];
  playbooks: number;
  playbooks_rewritten: number;
  playbooks_kept: { playbook_id: string; reason: string }[];
}

const reasonOf = (err: unknown) => (err instanceof Error ? err.message : String(err));

/**
 * Convert one Pir into its intelligence requirement, then delete the Pir. Never deletes a Pir whose flags would change.
 */
export const convertPirToRequirement = async (context: AuthContext, pir: BasicStoreEntityPir): Promise<PirConversion> => {
  const requirementId = await linkPirToRequirement(context, pir);
  const relations = await fullRelationsList<BasicStoreRelationPir>(context, SYSTEM_USER, RELATION_IN_PIR, { toId: pir.id });
  const at = new Date().toISOString();
  const mismatches = relations.map((relation) => checkInPirParity(pir, relation, at)).filter((m): m is PirParityMismatch => m !== null);
  if (mismatches.length > 0) {
    return { pir_id: pir.id, name: pir.name, converted: false, reason: `${mismatches.length} flag(s) would change score or explanations`, mismatches: mismatches.slice(0, 20) };
  }
  const existing = await listMatchesForEntities(context, SYSTEM_USER, requirementId, relations.map((r) => r.fromId));
  const known = new Set(existing.map((m) => m.match_entity_id));
  let seeded = 0;
  for (let i = 0; i < relations.length; i += 1) {
    const relation = relations[i];
    if (!known.has(relation.fromId)) {
      const now = new Date();
      await createEntity(context, SYSTEM_USER, {
        ir_id: requirementId,
        match_entity_id: relation.fromId,
        match_entity_type: relation.fromType,
        match_entity_name: await entityDisplayName(context, SYSTEM_USER, relation.fromId),
        match_status: 'auto',
        ...inPirRelationToMatch(pir, relation, at),
        match_score_breakdown: '[]',
        match_excluded: false,
        match_last_fact_at: now,
        created_at: now,
        updated_at: now,
      }, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH);
      known.add(relation.fromId);
      seeded += 1;
    }
  }
  invalidateInRequirementEntityIds(requirementId);
  await patchAttribute(context, SYSTEM_USER, requirementId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, {
    ir_status: 'active',
    lastEventId: pir.lastEventId,
    ir_processing: JSON.stringify({ catchup_from: pir.lastEventId }),
  });
  // The flags live on the requirement now: the legacy traces on the entities go, then the Pir with its in-pir relationships
  for (let i = 0; i < relations.length; i += 1) {
    await updatePirInformationOnEntity(context, SYSTEM_USER, relations[i].fromId, pir.id, 0);
  }
  try {
    await unregisterConnector(pir.id);
  } catch (err) {
    logMigration.warn(`[MIGRATION] Pir ${pir.id}: queue not removed (${reasonOf(err)})`);
  }
  await deleteElementById(context, SYSTEM_USER, pir.id, ENTITY_TYPE_PIR);
  return { pir_id: pir.id, name: pir.name, converted: true, requirement_id: requirementId, flags: relations.length, seeded };
};

/**
 * Pir id to requirement id, read from the requirements (ir_pir_id): it survives the deletion of the Pir, so a resumed
 * migration still rewrites the playbooks of the Pirs a previous run deleted.
 */
export const loadRequirementOfPirMap = async (context: AuthContext) => {
  const requirements = await fullEntitiesList<BasicStoreEntityIntelligenceRequirement>(context, SYSTEM_USER, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT]);
  const map = new Map<string, string>();
  requirements.forEach((requirement) => {
    if (requirement.ir_pir_id) map.set(requirement.ir_pir_id, requirement.internal_id);
  });
  return map;
};

export const rewritePirPlaybooks = async (context: AuthContext, requirementOfPir: Map<string, string>) => {
  const playbooks = await fullEntitiesList<BasicStoreEntityPlaybook>(context, SYSTEM_USER, [ENTITY_TYPE_PLAYBOOK]);
  let rewritten = 0;
  const kept: { playbook_id: string; reason: string }[] = [];
  for (let i = 0; i < playbooks.length; i += 1) {
    const playbook = playbooks[i];
    const rewrite = rewritePlaybookDefinition(playbook.playbook_definition ?? '', requirementOfPir);
    if (rewrite.unmapped.length > 0) {
      kept.push({ playbook_id: playbook.id, reason: `Pir(s) not converted: ${rewrite.unmapped.join(', ')}` });
    } else if (rewrite.changed) {
      try {
        await patchAttribute(context, SYSTEM_USER, playbook.id, ENTITY_TYPE_PLAYBOOK, { playbook_definition: rewrite.definition });
        rewritten += 1;
      } catch (err) {
        kept.push({ playbook_id: playbook.id, reason: reasonOf(err) });
      }
    }
  }
  return { playbooks: playbooks.length, rewritten, kept };
};

/**
 * The whole migration: every Pir, then every playbook. One Pir failing never stops the others.
 */
export const migratePirsToRequirements = async (context: AuthContext): Promise<PirMigrationReport> => {
  const pirs = await fullEntitiesList<BasicStoreEntityPir>(context, SYSTEM_USER, [ENTITY_TYPE_PIR]);
  const failed: PirConversion[] = [];
  let converted = 0;
  for (let i = 0; i < pirs.length; i += 1) {
    const pir = pirs[i];
    try {
      const conversion = await convertPirToRequirement(context, pir);
      if (conversion.converted) converted += 1;
      else failed.push(conversion);
    } catch (err) {
      failed.push({ pir_id: pir.id, name: pir.name, converted: false, reason: reasonOf(err) });
    }
  }
  const playbooks = await rewritePirPlaybooks(context, await loadRequirementOfPirMap(context));
  return { pirs: pirs.length, converted, failed, playbooks: playbooks.playbooks, playbooks_rewritten: playbooks.rewritten, playbooks_kept: playbooks.kept };
};
