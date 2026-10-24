import conf, { booleanConf, INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent } from '../types/event';
import { fullEntitiesList } from '../database/middleware-loader';
import { fetchStreamEventsRangeFromEventId } from '../database/stream/stream-handler';
import { EVENT_TYPE_CREATE, EVENT_TYPE_UPDATE } from '../database/utils';
import { addFilter } from '../utils/filtering/filtering-utils';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT } from '../modules/intelligenceRequirement/intelligenceRequirement-types';
import { parseIntelligenceRequirement } from '../modules/intelligenceRequirement/intelligenceRequirement-config';
import { buildEngineState, evaluateEntity, evaluateRelationship } from '../modules/intelligenceRequirement/intelligenceRequirement-engine';
import { listMatches, upsertMatch } from '../modules/intelligenceRequirement/intelligenceRequirementMatch-domain';
import { handleUpsertResult, processMatchChange, rescoreRequirement } from '../modules/intelligenceRequirement/intelligenceRequirement-pipeline';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { IR_MATCH_IN_STATUSES } from '../modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import { updateIntelligenceRequirementLastEventId } from '../modules/intelligenceRequirement/intelligenceRequirement-domain';

// Proof of concept: stream engine of the generic intelligence requirements (scope criteria → entities of the requirement).
// It is fully independent from the PIR manager.

const IR_MANAGER_ID = 'INTELLIGENCE_REQUIREMENT_MANAGER';
const IR_MANAGER_CONTEXT = 'intelligence_requirement_manager';
const IR_MANAGER_ENABLED = booleanConf('intelligence_requirement_manager:enabled', true);
const IR_MANAGER_LOCK_KEY = conf.get('intelligence_requirement_manager:lock_key') || 'intelligence_requirement_manager_lock';
const IR_MANAGER_INTERVAL = conf.get('intelligence_requirement_manager:interval') || 10000;
const IR_MANAGER_STREAM_BATCH_SIZE = conf.get('intelligence_requirement_manager:stream_batch_size') || 2000;

const processEventsForRequirement = (context: AuthContext, ir: BasicStoreEntityIntelligenceRequirement) => {
  const parsed = parseIntelligenceRequirement(ir);
  // Relationship types that can change the result of a path condition of a relevance rule
  const pathRelationshipTypes = new Set(parsed.ir_relevance_rules
    .filter((r) => r.enabled && r.path_condition)
    .flatMap((r) => [r.path_condition!.target_relationship_type, ...r.path_condition!.relationship_types]));
  return async (streamEvents: Array<SseEvent<DataEvent>>) => {
    const state = await buildEngineState(context, SYSTEM_USER, parsed);
    const matches = await listMatches(context, SYSTEM_USER, ir.id);
    const matchByEntity = new Map(matches.map((m) => [m.match_entity_id, m]));
    let entered = 0;
    let updated = 0;
    let rescored = 0;
    let rescoreAll = false;
    for (let i = 0; i < streamEvents.length; i += 1) {
      const event = streamEvents[i].data;
      if (event.type !== EVENT_TYPE_CREATE && event.type !== EVENT_TYPE_UPDATE) continue;
      const stix = event.data as any;
      if (stix.type === STIX_TYPE_SIGHTING) continue;
      const isRelationship = stix.type === STIX_TYPE_RELATION;
      try {
        // 1. Scope: entities entering the requirement (or getting a new proof)
        const touched = new Set<string>();
        const candidates = isRelationship
          ? await evaluateRelationship(context, SYSTEM_USER, state, stix)
          : await evaluateEntity(context, SYSTEM_USER, state, stix);
        for (let j = 0; j < candidates.length; j += 1) {
          const candidate = candidates[j];
          const result = await upsertMatch(context, SYSTEM_USER, ir.id, candidate.entity, candidate.criterion, candidate.explanation);
          if (result) {
            touched.add(candidate.entity.id);
            matchByEntity.set(candidate.entity.id, result.match);
            if (result.created) {
              entered += 1;
            } else {
              updated += 1;
            }
            // Keep the content of the requirement up to date for the "second hop" criteria of the next events
            if (IR_MATCH_IN_STATUSES.includes(result.match.match_status)) state.inRequirement.add(candidate.entity.id);
            // 2. Inbox (proposed / entered) and relevance (score, thresholds)
            await handleUpsertResult(context, SYSTEM_USER, parsed, result, candidate.criterion.id);
          }
        }
        // 3. Relevance: a new fact on an entity already in the requirement (e.g. it entered CISA KEV)
        const ext = stix.extensions?.[STIX_EXT_OCTI] ?? {};
        const factIds: string[] = isRelationship ? [ext.source_ref, ext.target_ref] : [ext.id];
        for (let k = 0; k < factIds.length; k += 1) {
          const match = matchByEntity.get(factIds[k]);
          if (match && !touched.has(factIds[k]) && match.match_status !== 'rejected' && match.match_status !== 'removed') {
            await processMatchChange(context, SYSTEM_USER, parsed, match);
            rescored += 1;
          }
        }
        if (isRelationship && pathRelationshipTypes.has(stix.relationship_type)) rescoreAll = true;
      } catch (err) {
        logApp.warn('[OPENCTI-MODULE] Intelligence requirement event evaluation error', { cause: err, manager: IR_MANAGER_ID, requirement: ir.id });
      }
    }
    // A relationship used by a path condition changed: the score of any entity may change
    if (rescoreAll) {
      rescored += await rescoreRequirement(context, SYSTEM_USER, parsed);
    }
    if (entered > 0 || updated > 0 || rescored > 0) {
      logApp.info('[OPENCTI-MODULE] Intelligence requirement processed', { manager: IR_MANAGER_ID, requirement: ir.name, entered, updated, rescored, events: streamEvents.length });
    }
  };
};

export const intelligenceRequirementManagerHandler = async () => {
  const context = executionContext(IR_MANAGER_CONTEXT);
  const requirements = await fullEntitiesList<BasicStoreEntityIntelligenceRequirement>(context, SYSTEM_USER, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT], {
    filters: addFilter(undefined, 'ir_status', 'active'),
  });
  for (let i = 0; i < requirements.length; i += 1) {
    const ir = requirements[i];
    try {
      const { lastEventId } = await fetchStreamEventsRangeFromEventId(
        ir.lastEventId,
        processEventsForRequirement(context, ir),
        { streamBatchSize: IR_MANAGER_STREAM_BATCH_SIZE },
      );
      if (lastEventId && lastEventId !== ir.lastEventId) {
        await updateIntelligenceRequirementLastEventId(context, SYSTEM_USER, ir.id, lastEventId);
      }
    } catch (err) {
      logApp.error('[OPENCTI-MODULE] Intelligence requirement processing error', { cause: err, manager: IR_MANAGER_ID, requirement: ir.id });
    }
  }
};

const INTELLIGENCE_REQUIREMENT_MANAGER_DEFINITION: ManagerDefinition = {
  id: IR_MANAGER_ID,
  label: 'Intelligence requirement manager',
  executionContext: IR_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: intelligenceRequirementManagerHandler,
    interval: IR_MANAGER_INTERVAL,
    lockKey: IR_MANAGER_LOCK_KEY,
  },
  enabledByConfig: IR_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

if (isFeatureEnabled(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG)) {
  registerManager(INTELLIGENCE_REQUIREMENT_MANAGER_DEFINITION);
}
