import conf, { booleanConf, INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { type ManagerDefinition, registerManager } from './managerModule';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent } from '../types/event';
import type { BasicStoreRelation } from '../types/store';
import { fullEntitiesList, fullRelationsList } from '../database/middleware-loader';
import { fetchStreamEventsRangeFromEventId } from '../database/stream/stream-handler';
import { EVENT_TYPE_CREATE, EVENT_TYPE_UPDATE } from '../database/utils';
import { addFilter } from '../utils/filtering/filtering-utils';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import {
  type BasicStoreEntityIntelligenceRequirement,
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT,
  type StoreIrBatchStats,
  type StoreIrProcessing,
} from '../modules/intelligenceRequirement/intelligenceRequirement-types';
import { parseIntelligenceRequirement } from '../modules/intelligenceRequirement/intelligenceRequirement-config';
import {
  buildEngineState,
  conditionedCriteriaFor,
  evaluateCandidate,
  evaluateEntity,
  evaluateRelationship,
  IR_CONTAINS_RELATIONSHIP,
  type IrCandidate,
  type IrEngineState,
  isTypeMatching,
} from '../modules/intelligenceRequirement/intelligenceRequirement-engine';
import { backfillMatchEntityNames, listMatchesForEntities } from '../modules/intelligenceRequirement/intelligenceRequirementMatch-domain';
import { createMatchWriter } from '../modules/intelligenceRequirement/intelligenceRequirement-scoring';
import {
  backfillEnteredEntities,
  handleUpsertResult,
  processMatchChange,
  purgeNotEligibleMatches,
  rescoreRequirement,
  upsertCandidate,
} from '../modules/intelligenceRequirement/intelligenceRequirement-pipeline';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { type BasicStoreEntityIntelligenceRequirementMatch, isInRequirement } from '../modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import { isRequirementDeleted, isRescanSince } from '../modules/intelligenceRequirement/intelligenceRequirement-lifecycle';
import { parseRequirementProcessing, updateIntelligenceRequirementLastEventId } from '../modules/intelligenceRequirement/intelligenceRequirement-domain';
import { checkRequirementHealth } from '../modules/intelligenceRequirement/intelligenceRequirement-health';
import { generateRequirementBrief, isBriefDue, markBriefStarted } from '../modules/intelligenceRequirement/intelligenceRequirement-brief';

// Proof of concept: stream engine of the generic intelligence requirements (scope criteria → entities of the requirement).
// It is fully independent from the PIR manager.

const IR_MANAGER_ID = 'INTELLIGENCE_REQUIREMENT_MANAGER';
const IR_MANAGER_CONTEXT = 'intelligence_requirement_manager';
const IR_MANAGER_ENABLED = booleanConf('intelligence_requirement_manager:enabled', true);
const IR_MANAGER_LOCK_KEY = conf.get('intelligence_requirement_manager:lock_key') || 'intelligence_requirement_manager_lock';
const IR_MANAGER_INTERVAL = conf.get('intelligence_requirement_manager:interval') || 10000;
const IR_HEALTH_INTERVAL = conf.get('intelligence_requirement_manager:health_interval') || 3600000;
// Last health check per requirement (this node): the checks run at most once per interval
const lastHealthCheck = new Map<string, number>();
// Briefs being generated (this node): an agent call takes about a minute, it must not block the stream processing
const briefsInFlight = new Set<string>();
// Requirements whose match names were backfilled and not eligible entities purged (this node, once per start)
const namesBackfilled = new Set<string>();
const IR_MANAGER_STREAM_BATCH_SIZE = conf.get('intelligence_requirement_manager:stream_batch_size') || 2000;
// Entities reached by the second hop of a path condition of the scope, evaluated again per new relationship
const PATH_CANDIDATES_MAX = 200;

// Date of a stream event, from its id (<milliseconds>-<sequence>)
const eventDate = (eventId: string) => {
  const ms = Number.parseInt(eventId.split('-')[0], 10);
  return Number.isNaN(ms) ? new Date().toISOString() : new Date(ms).toISOString();
};

// What a fact event changed on an entity of the requirement, as recorded in its history
const factTrigger = (event: DataEvent, stix: any) => {
  if (stix.type === STIX_TYPE_RELATION) return `${event.type === EVENT_TYPE_CREATE ? 'New' : 'Updated'} ${stix.relationship_type} relationship`;
  if (event.type === EVENT_TYPE_CREATE) return 'Entity created';
  const patch = ((event as any).context?.patch ?? []) as { path?: string }[];
  const fields = Array.from(new Set(patch.map((op) => (op.path ?? '').split('/')[1]).filter((f) => f && !f.startsWith('updated_at') && f !== 'modified')));
  return fields.length > 0 ? `Updated: ${fields.slice(0, 4).join(', ')}` : 'Entity updated';
};

// Statistics of one batch of a requirement, shown in its Processing tab
interface BatchStats extends StoreIrBatchStats {
  lastError?: { at: string; message: string; event_id?: string };
}
const emptyStats = (): BatchStats => ({ events: 0, entered: 0, updated: 0, rescored: 0, backfilled: 0, skipped: 0, errors: 0 });

const processEventsForRequirement = (context: AuthContext, ir: BasicStoreEntityIntelligenceRequirement, stats: BatchStats = emptyStats()) => {
  const parsed = parseIntelligenceRequirement(ir);
  // Relationship types of the second hop of a path condition (rule or scope condition): a new one can change the result
  // for any entity of the requirement. The first hop always touches the entity itself, which is rescored as a fact below.
  const pathConditions = [
    ...parsed.ir_relevance_rules.filter((r) => r.enabled && r.path_condition).map((r) => r.path_condition!),
    ...parsed.ir_scope_criteria.flatMap((c) => (c.conditions ?? []).filter((cond) => cond.path_condition).map((cond) => cond.path_condition!)),
  ];
  const pathRelationshipTypes = new Set(pathConditions.map((p) => p.target_relationship_type));
  // On-demand eligibility: the relationships that the conditions of the scope read. A new one on an entity that is not stored
  // (its candidacy was refused, or it was never a candidate) makes it evaluated again, from its own side.
  const scopeConditions = parsed.ir_scope_criteria.filter((c) => c.mode !== 'off').flatMap((c) => c.conditions ?? []);
  const conditionRelationshipTypes = new Set(scopeConditions.flatMap((cond) => [
    ...(cond.link?.relationship_types ?? []).filter((r) => r !== IR_CONTAINS_RELATIONSHIP),
    ...(cond.path_condition?.relationship_types ?? []),
  ]));
  // Second hop of a path condition of the scope: a new (linked) —target relationship→ (target) reaches the entities linked to it
  const scopePathConditions = scopeConditions.filter((cond) => cond.path_condition).map((cond) => cond.path_condition!);
  const criteriaByType = new Map<string, ReturnType<typeof conditionedCriteriaFor>>();
  const conditionedFor = (type: string) => {
    if (!criteriaByType.has(type)) criteriaByType.set(type, conditionedCriteriaFor(parsed, type));
    return criteriaByType.get(type)!;
  };
  // An update of the entity itself matters to a graph criterion whose conditions read its attributes or its content
  const readsEntity = (type: string) => conditionedFor(type).some((c) => c.kind === 'graph' && (c.conditions ?? [])
    .some((cond) => isTypeMatching(type, cond.applies_to_types ?? []) && (cond.filters || (cond.link?.relationship_types ?? []).includes(IR_CONTAINS_RELATIONSHIP))));
  return async (streamEvents: Array<SseEvent<DataEvent>>) => {
    // Only creations and updates of knowledge count: a batch without any costs nothing (no state, no read of the matches)
    const relevant = streamEvents.filter((e) => (e.data.type === EVENT_TYPE_CREATE || e.data.type === EVENT_TYPE_UPDATE)
      && (e.data.data as any)?.type !== STIX_TYPE_SIGHTING);
    if (relevant.length === 0) {
      stats.events += streamEvents.length;
      return;
    }
    const state = await buildEngineState(context, SYSTEM_USER, parsed);
    // The stored matches of the entities this batch touches, not every match of the requirement
    const matchByEntity = new Map<string, BasicStoreEntityIntelligenceRequirementMatch>();
    const lookedUp = new Set<string>();
    const lookUp = async (ids: string[]) => {
      const missing = Array.from(new Set(ids.filter((id) => id && !lookedUp.has(id))));
      if (missing.length === 0) return;
      missing.forEach((id) => lookedUp.add(id));
      const found = await listMatchesForEntities(context, SYSTEM_USER, ir.id, missing);
      found.forEach((m) => {
        if (!matchByEntity.has(m.match_entity_id)) matchByEntity.set(m.match_entity_id, m);
      });
    };
    await lookUp(relevant.flatMap((e) => {
      const ext = (e.data.data as any)?.extensions?.[STIX_EXT_OCTI] ?? {};
      return (e.data.data as any)?.type === STIX_TYPE_RELATION ? [ext.source_ref, ext.target_ref] : [ext.id];
    }));
    // Score and history writes of the batch, sent together at its end
    const writer = createMatchWriter();
    let entered = 0;
    let updated = 0;
    let rescored = 0;
    let backfilled = 0;
    let skipped = 0;
    const onSkipped = () => {
      skipped += 1;
    };
    let rescoreAll = false;
    let lastEventAt: string | undefined;
    // New facts on entities of the requirement, re-evaluated once each at the end of the batch
    // (a batch often holds many relationships of the same entity: one evaluation instead of one per relationship)
    const pendingFacts = new Map<string, { match: BasicStoreEntityIntelligenceRequirementMatch; at: string; trigger: string }>();
    // Entities that are not stored and received a fact a condition reads, evaluated once each at the end of the batch
    const pendingCandidates = new Map<string, { entity: { id: string; type: string }; at: string }>();
    const considerCandidate = (id: string | undefined, type: string | undefined, at: string) => {
      if (!id || !type || matchByEntity.has(id) || conditionedFor(type).length === 0) return;
      pendingCandidates.set(id, { entity: { id, type }, at });
    };
    // Candidates of the scope: stored if they meet the conditions, then eligibility, inbox, relevance and second hop backfill
    const admitCandidates = async (engineState: IrEngineState, candidates: IrCandidate[], at: string, touched?: Set<string>, suffix = '') => {
      for (let j = 0; j < candidates.length; j += 1) {
        const candidate = candidates[j];
        const result = await upsertCandidate(context, SYSTEM_USER, parsed, candidate, onSkipped);
        if (result) {
          touched?.add(candidate.entity.id);
          pendingFacts.delete(candidate.entity.id); // just evaluated by its upsert
          pendingCandidates.delete(candidate.entity.id);
          matchByEntity.set(candidate.entity.id, result.match);
          if (result.created) {
            entered += 1;
          } else {
            updated += 1;
          }
          const trigger = `${result.created ? 'Entered' : 'New proof'} through "${candidate.criterion.name}"${suffix}`;
          const { becameVisible, dropped } = await handleUpsertResult(context, SYSTEM_USER, parsed, result, candidate.criterion.id, false, { at, trigger }, writer);
          if (dropped) {
            matchByEntity.delete(candidate.entity.id);
            engineState.inRequirement.delete(candidate.entity.id);
          } else if (isInRequirement(result.match)) {
            // Keep the content of the requirement up to date for the "second hop" criteria of the next events
            engineState.inRequirement.add(candidate.entity.id);
          }
          // Backfill: what the entity already reaches through the second hop criteria
          if (becameVisible) {
            backfilled += await backfillEnteredEntities(context, SYSTEM_USER, parsed, engineState, [candidate.entity], at, onSkipped, writer);
          }
        }
      }
    };
    for (let i = 0; i < streamEvents.length; i += 1) {
      // Deleted while this batch was in progress: stop writing into it
      if (isRequirementDeleted(ir.id)) return;
      const event = streamEvents[i].data;
      if (event.type !== EVENT_TYPE_CREATE && event.type !== EVENT_TYPE_UPDATE) continue;
      const stix = event.data as any;
      if (stix.type === STIX_TYPE_SIGHTING) continue;
      const isRelationship = stix.type === STIX_TYPE_RELATION;
      // The history of the entities is dated with the event (a replayed event keeps its own date)
      const at = eventDate(streamEvents[i].id);
      lastEventAt = at;
      try {
        // 1. Scope: entities entering the requirement (or getting a new proof)
        const touched = new Set<string>();
        const candidates = isRelationship
          ? await evaluateRelationship(context, SYSTEM_USER, state, stix)
          : await evaluateEntity(context, SYSTEM_USER, state, stix);
        // 2. Stored if they meet the conditions of the scope; inbox (proposed / entered) and relevance (score, thresholds)
        await admitCandidates(state, candidates, at, touched);
        // 3. Relevance: a new fact on an entity already in the requirement (e.g. it entered CISA KEV)
        const ext = stix.extensions?.[STIX_EXT_OCTI] ?? {};
        const factIds: string[] = isRelationship ? [ext.source_ref, ext.target_ref] : [ext.id];
        for (let k = 0; k < factIds.length; k += 1) {
          const match = matchByEntity.get(factIds[k]);
          if (match && !touched.has(factIds[k]) && match.match_status !== 'rejected' && match.match_status !== 'removed') {
            pendingFacts.set(factIds[k], { match, at, trigger: factTrigger(event, stix) });
          }
        }
        if (isRelationship && pathRelationshipTypes.has(stix.relationship_type)) rescoreAll = true;
        // 4. On-demand eligibility: a fact a condition reads, on an entity that is not stored
        if (isRelationship && conditionRelationshipTypes.has(stix.relationship_type)) {
          considerCandidate(ext.source_ref, ext.source_type, at);
          considerCandidate(ext.target_ref, ext.target_type, at);
        } else if (!isRelationship && !touched.has(ext.id) && readsEntity(ext.type)) {
          considerCandidate(ext.id, ext.type, at);
        }
        if (isRelationship) {
          const paths = scopePathConditions.filter((p) => p.target_relationship_type === stix.relationship_type);
          for (let p = 0; p < paths.length; p += 1) {
            // The source of the new relationship is the linked entity: the entities linked to it may now meet the condition
            const path = paths[p];
            const linked: { id: string; type: string }[] = [];
            if (path.direction === 'incoming' || path.direction === 'both') {
              const relations = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, path.relationship_types, { fromId: ext.source_ref });
              linked.push(...relations.map((r) => ({ id: r.toId, type: r.toType })));
            }
            if (path.direction === 'outgoing' || path.direction === 'both') {
              const relations = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, path.relationship_types, { toId: ext.source_ref });
              linked.push(...relations.map((r) => ({ id: r.fromId, type: r.fromType })));
            }
            linked.slice(0, PATH_CANDIDATES_MAX).forEach((l) => considerCandidate(l.id, l.type, at));
          }
        }
      } catch (err) {
        logApp.warn('[OPENCTI-MODULE] Intelligence requirement event evaluation error', { cause: err, manager: IR_MANAGER_ID, requirement: ir.id });
        const message = (err as Error)?.message ?? String(err);
        Object.assign(stats, { errors: stats.errors + 1, lastError: { at: new Date().toISOString(), message, event_id: streamEvents[i].id } });
      }
    }
    // 3b. The new facts of the batch, once per entity (a full rescore below covers them all)
    if (!rescoreAll) {
      const facts = Array.from(pendingFacts.values());
      for (let f = 0; f < facts.length && !isRequirementDeleted(ir.id); f += 1) {
        const { match, at, trigger } = facts[f];
        try {
          const { becameVisible, dropped } = await processMatchChange(context, SYSTEM_USER, parsed, match, { meta: { at, trigger }, writer });
          rescored += 1;
          if (dropped) matchByEntity.delete(match.match_entity_id);
          // The new fact made it meet the conditions of the scope: it now counts for the second hop
          if (!dropped && isInRequirement(match)) state.inRequirement.add(match.match_entity_id);
          else state.inRequirement.delete(match.match_entity_id);
          if (becameVisible) {
            const entity = { id: match.match_entity_id, type: match.match_entity_type };
            backfilled += await backfillEnteredEntities(context, SYSTEM_USER, parsed, state, [entity], at, onSkipped, writer);
          }
        } catch (err) {
          logApp.warn('[OPENCTI-MODULE] Intelligence requirement fact evaluation error', { cause: err, manager: IR_MANAGER_ID, requirement: ir.id });
          const message = (err as Error)?.message ?? String(err);
          Object.assign(stats, { errors: stats.errors + 1, lastError: { at: new Date().toISOString(), message } });
        }
      }
    }
    // 4b. Entities that are not stored and received a fact a condition reads: candidates again, stored if they now meet them
    const pending = Array.from(pendingCandidates.values());
    // Entities reached through a path condition were not in the events: whether they are stored is read now
    await lookUp(pending.map((p) => p.entity.id));
    for (let c = 0; c < pending.length && !isRequirementDeleted(ir.id); c += 1) {
      const { entity, at } = pending[c];
      if (matchByEntity.has(entity.id)) continue; // stored meanwhile
      try {
        const candidates = await evaluateCandidate(context, SYSTEM_USER, state, entity, conditionedFor(entity.type));
        await admitCandidates(state, candidates, at, undefined, ' (now meets the conditions of the scope)');
      } catch (err) {
        logApp.warn('[OPENCTI-MODULE] Intelligence requirement candidate evaluation error', { cause: err, manager: IR_MANAGER_ID, requirement: ir.id });
        const message = (err as Error)?.message ?? String(err);
        Object.assign(stats, { errors: stats.errors + 1, lastError: { at: new Date().toISOString(), message } });
      }
    }
    // The grouped writes of the batch (the full rescore below reads the matches again)
    if (!isRequirementDeleted(ir.id)) await writer.flush(context);
    // A relationship used by a path condition changed: the score of any entity may change
    if (rescoreAll && !isRequirementDeleted(ir.id)) {
      rescored += await rescoreRequirement(context, SYSTEM_USER, parsed, { at: lastEventAt, trigger: 'A fact used by a path condition changed' });
    }
    Object.assign(stats, {
      events: stats.events + streamEvents.length,
      entered: stats.entered + entered,
      updated: stats.updated + updated,
      rescored: stats.rescored + rescored,
      backfilled: stats.backfilled + backfilled,
      skipped: (stats.skipped ?? 0) + skipped,
    });
    if (entered > 0 || updated > 0 || rescored > 0 || backfilled > 0) {
      logApp.info('[OPENCTI-MODULE] Intelligence requirement processed', {
        manager: IR_MANAGER_ID,
        requirement: ir.name,
        entered,
        updated,
        rescored,
        backfilled,
        skipped,
        events: streamEvents.length,
      });
    }
  };
};

// The processing record of a requirement after a batch: last batch, totals, last error
const withBatch = (ir: BasicStoreEntityIntelligenceRequirement, stats: BatchStats, durationMs: number): StoreIrProcessing => {
  const previous = parseRequirementProcessing(ir);
  const { lastError, ...batch } = stats;
  const totals = previous.totals ?? emptyStats();
  return {
    ...previous,
    last_batch: { ...batch, at: new Date().toISOString(), duration_ms: durationMs },
    totals: {
      events: totals.events + batch.events,
      entered: totals.entered + batch.entered,
      updated: totals.updated + batch.updated,
      rescored: totals.rescored + batch.rescored,
      backfilled: totals.backfilled + batch.backfilled,
      skipped: (totals.skipped ?? 0) + (batch.skipped ?? 0),
      errors: totals.errors + batch.errors,
    },
    last_error: lastError ?? previous.last_error,
  };
};

// Stream positions are <milliseconds>-<sequence>
const compareEventIds = (a: string, b: string) => {
  const [aMs, aSeq] = a.split('-').map((v) => Number.parseInt(v, 10));
  const [bMs, bSeq] = b.split('-').map((v) => Number.parseInt(v, 10));
  return aMs === bMs ? (aSeq || 0) - (bSeq || 0) : aMs - bMs;
};

// One requirement, with the events of the shared read that come after its own position
const processRequirement = async (context: AuthContext, ir: BasicStoreEntityIntelligenceRequirement, events: Array<SseEvent<DataEvent>>, lastEventId: string) => {
  const stats = emptyStats();
  const startedAt = Date.now();
  try {
    await processEventsForRequirement(context, ir, stats)(events);
    if (isRequirementDeleted(ir.id)) return;
    // The scope changed during the batch: the position was moved back to the rescan window, keep it
    if (isRescanSince(ir.id, startedAt)) return;
    if (lastEventId && lastEventId !== ir.lastEventId) {
      await updateIntelligenceRequirementLastEventId(context, SYSTEM_USER, ir.id, lastEventId, withBatch(ir, stats, Date.now() - startedAt));
    }
    if (!namesBackfilled.has(ir.id)) {
      namesBackfilled.add(ir.id);
      const named = await backfillMatchEntityNames(context, SYSTEM_USER, ir.id);
      if (named > 0) logApp.info('[OPENCTI-MODULE] Intelligence requirement entity names backfilled', { manager: IR_MANAGER_ID, requirement: ir.name, named });
      const purged = await purgeNotEligibleMatches(context, SYSTEM_USER, ir.id);
      if (purged > 0) logApp.info('[OPENCTI-MODULE] Intelligence requirement not eligible entities purged', { manager: IR_MANAGER_ID, requirement: ir.name, purged });
    }
    if (Date.now() - (lastHealthCheck.get(ir.id) ?? 0) > IR_HEALTH_INTERVAL) {
      lastHealthCheck.set(ir.id, Date.now());
      const raised = await checkRequirementHealth(context, SYSTEM_USER, parseIntelligenceRequirement(ir));
      if (raised > 0) logApp.info('[OPENCTI-MODULE] Intelligence requirement health', { manager: IR_MANAGER_ID, requirement: ir.name, raised });
    }
    if (isBriefDue(ir) && !briefsInFlight.has(ir.id)) {
      briefsInFlight.add(ir.id);
      await markBriefStarted(context, SYSTEM_USER, ir.id);
      generateRequirementBrief(context, SYSTEM_USER, ir, 'scheduled')
        .then((item) => logApp.info('[OPENCTI-MODULE] Intelligence requirement brief', { manager: IR_MANAGER_ID, requirement: ir.name, delivered: !!item }))
        .catch((err) => logApp.error('[OPENCTI-MODULE] Intelligence requirement brief error', { cause: err, manager: IR_MANAGER_ID, requirement: ir.id }))
        .finally(() => briefsInFlight.delete(ir.id));
    }
  } catch (err) {
    logApp.error('[OPENCTI-MODULE] Intelligence requirement processing error', { cause: err, manager: IR_MANAGER_ID, requirement: ir.id });
    if (!isRequirementDeleted(ir.id)) {
      stats.errors += 1;
      stats.lastError = { at: new Date().toISOString(), message: (err as Error)?.message ?? String(err) };
      await updateIntelligenceRequirementLastEventId(context, SYSTEM_USER, ir.id, ir.lastEventId, withBatch(ir, stats, Date.now() - startedAt))
        .catch((e) => logApp.error('[OPENCTI-MODULE] Intelligence requirement processing record error', { cause: e, requirement: ir.id }));
    }
  }
};

/**
 * The stream is read once for the requirements whose positions fall in the same range (all the live ones, usually),
 * then each one processes the events after its own position. A requirement that catches up further behind gets its own read.
 * Each requirement advances by one batch at most per run, as before.
 */
export const intelligenceRequirementManagerHandler = async () => {
  const context = executionContext(IR_MANAGER_CONTEXT);
  const requirements = await fullEntitiesList<BasicStoreEntityIntelligenceRequirement>(context, SYSTEM_USER, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT], {
    filters: addFilter(undefined, 'ir_status', 'active'),
  });
  let pending = [...requirements].sort((a, b) => compareEventIds(a.lastEventId, b.lastEventId));
  while (pending.length > 0) {
    const from = pending[0].lastEventId;
    let events: Array<SseEvent<DataEvent>> = [];
    const { lastEventId } = await fetchStreamEventsRangeFromEventId<DataEvent>(
      from,
      (read) => {
        events = read;
      },
      { streamBatchSize: IR_MANAGER_STREAM_BATCH_SIZE },
    );
    // Served by this read: the requirements whose position is before the end of the batch (or at its start)
    const served = pending.filter((ir) => ir.lastEventId === from || compareEventIds(ir.lastEventId, lastEventId) < 0);
    pending = pending.filter((ir) => !served.includes(ir));
    for (let i = 0; i < served.length; i += 1) {
      const ir = served[i];
      await processRequirement(context, ir, events.filter((e) => compareEventIds(e.id, ir.lastEventId) > 0), lastEventId);
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
