import * as R from 'ramda';
import * as jsonpatch from 'fast-json-patch';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { logApp } from '../config/conf';
import { CURATION_MANAGER_USER, executionContext, INTERNAL_USERS } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent, StreamDataEvent, UpdateEvent } from '../types/event';
import type { BasicStoreEntity, BasicStoreRelation } from '../types/store';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { EVENT_TYPE_CREATE, EVENT_TYPE_UPDATE } from '../database/utils';
import {
  redisCurationClaimDeadLetters,
  redisCurationIncrementCounter,
  redisCurationPushDeadLetters,
  redisCurationSettleDeadLetter,
  redisCurationSwapFieldWriter,
  redisGetManagerEventState,
  redisSetManagerEventState,
} from '../database/redis';
import { fullEntitiesList, internalFindByIds } from '../database/middleware-loader';
import { getEntitiesListFromCache } from '../database/cache';
import { isEnterpriseEdition } from '../enterprise-edition/ee';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { RELATION_USES } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../schema/stixDomainObject';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { getCurationSettings, saveCurationSettings } from '../modules/curation/curation-settings';
import { runContradictionScan, runDuplicateScan, runIncrementalDuplicateDetection, runStalenessScan } from '../modules/curation/curation-scan';
import { createHealthSnapshot, deliverKnowledgeHealthDigest, findLatestHealthSnapshot, SOURCE_CONFLICTS_COUNTER } from '../modules/curation/curation-health';
import { ADJUDICATED_PROPOSAL_KINDS, adjudicateProposal, isAdjudicationAvailable } from '../modules/curation/curation-adjudication';
import { applyCurationPolicy, findEnabledPolicies } from '../modules/curation/curation-policies';
import { persistProposalDraft } from '../modules/curation/curation-proposals';
import { buildDateInversionDraft, buildProcedureConflictDraft, isDuplicateDetectionEnabled, isProcedureConflict } from '../modules/curation/curation-detectors';
import { decideFieldAuthority } from '../modules/curation/curation-field-authority';
import { CURATION_MANAGER_ENABLED, CURATION_SCAN_INTERVAL_MS, CURATION_SNAPSHOT_INTERVAL_MS, isOlderThan } from '../modules/curation/curation-schedule';
import {
  ACTION_SET_FIELD,
  AUTHORITY_SOURCE_CONNECTOR,
  type BasicStoreEntityCurationProposal,
  type CurationSettings,
  DETECTOR_CONTRADICTION,
  DETECTOR_FIELD_AUTHORITY,
  DETECTOR_RELATIONSHIP_CONFLICT,
  ENTITY_TYPE_CURATION_PROPOSAL,
  EVIDENCE_FIELD_CONFLICT,
  type FieldAuthoritySource,
  PROPOSAL_KIND_FIELD_PRECEDENCE,
  PROPOSAL_STATUS_OPEN,
  type ProposalDraft,
} from '../modules/curation/curation-types';

const CURATION_MANAGER_ID = 'CURATION_MANAGER';
const CURATION_MANAGER_LABEL = 'Curation manager';
const CURATION_MANAGER_CONTEXT = 'curation_manager';
const CURATION_STREAM_STATE = 'curation_manager';

const CURATION_MANAGER_LOCK_KEY = conf.get('curation_manager:lock_key') || 'curation_manager_lock';
const CURATION_MANAGER_STREAM_LOCK_KEY = conf.get('curation_manager:stream_lock_key') || 'curation_manager_stream_lock';
const CURATION_MANAGER_INTERVAL = Number(conf.get('curation_manager:interval') ?? 60000);
const CURATION_POLICY_INTERVAL_MS = Number(conf.get('curation_manager:policy_interval') ?? 15 * 60 * 1000);
const CURATION_ADJUDICATIONS_PER_TICK = Number(conf.get('curation_manager:adjudications_per_tick') ?? 5);
const CURATION_STREAM_MAX_ENTITIES = Number(conf.get('curation_manager:stream_max_entities_per_batch') ?? 50);
const CURATION_STREAM_MAX_ATTEMPTS = 5;
const CURATION_DEAD_LETTERS_PER_TICK = 20;
const CURATION_DEAD_LETTER_MAX_REPLAYS = 10;
const FIELD_WRITER_TTL_SECONDS = 30 * 24 * 3600;
const DIGEST_MIN_INTERVAL_MS = 6 * 24 * 3600 * 1000;

let streamStartFrom: string | undefined;
let failedBatchKey: string | undefined;
let failedBatchAttempts = 0;
let lastPolicyRun = 0;

const today = () => new Date().toISOString().slice(0, 10);

// region cron
const runScans = async (context: AuthContext, settings: CurationSettings) => {
  const startedAt = Date.now();
  const duplicates = await runDuplicateScan(context, settings);
  const contradictions = await runContradictionScan(context, settings);
  const staleness = await runStalenessScan(context, settings);
  logApp.info('[CURATION] Knowledge curation scan done', { duration_ms: Date.now() - startedAt, duplicates, contradictions, staleness });
  await saveCurationSettings(context, CURATION_MANAGER_USER, { force_scan: false, last_scan_date: new Date().toISOString() }, { auditLog: false });
};

const runSnapshotAndDigest = async (context: AuthContext, settings: CurationSettings) => {
  let latest = await findLatestHealthSnapshot(context, CURATION_MANAGER_USER);
  if (isOlderThan(settings.last_snapshot_date ?? latest?.snapshot_date, CURATION_SNAPSHOT_INTERVAL_MS)) {
    latest = await createHealthSnapshot(context, settings);
    await saveCurationSettings(context, CURATION_MANAGER_USER, { last_snapshot_date: latest.snapshot_date }, { auditLog: false });
  }
  const isDigestDay = new Date().getUTCDay() === settings.digest_day;
  const due = settings.digest_enabled && isDigestDay && isOlderThan(settings.last_digest_date, DIGEST_MIN_INTERVAL_MS);
  if (await deliverKnowledgeHealthDigest(context, settings, latest, due)) {
    await saveCurationSettings(context, CURATION_MANAGER_USER, { last_digest_date: new Date().toISOString() }, { auditLog: false });
  }
};

const runAdjudicationQueue = async (context: AuthContext, settings: CurationSettings) => {
  if (!settings.adjudication_enabled || !(await isAdjudicationAvailable(context))) return;
  const retryBefore = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const pending = await fullEntitiesList<BasicStoreEntityCurationProposal>(context, CURATION_MANAGER_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
        { key: ['in_ambiguous_band'], values: ['true'], operator: FilterOperator.Eq },
        { key: ['proposal_kind'], values: ADJUDICATED_PROPOSAL_KINDS, operator: FilterOperator.Eq },
      ],
      filterGroups: [{
        mode: FilterMode.Or,
        filters: [
          { key: ['adjudication_requested_at'], values: [], operator: FilterOperator.Nil },
          { key: ['adjudication_requested_at'], values: [retryBefore], operator: FilterOperator.Lt },
        ],
        filterGroups: [],
      }],
    },
    orderBy: 'confidence_score',
    orderMode: 'desc',
    maxSize: CURATION_ADJUDICATIONS_PER_TICK * 4,
    noFiltersChecking: true,
  } as any);
  const toAdjudicate = pending.filter((proposal) => !proposal.curation_adjudication).slice(0, CURATION_ADJUDICATIONS_PER_TICK);
  for (let index = 0; index < toAdjudicate.length; index += 1) {
    try {
      await adjudicateProposal(context, CURATION_MANAGER_USER, toAdjudicate[index], settings);
    } catch (error: any) {
      logApp.warn('[CURATION] Adjudication failed', { cause: error, proposal_id: toAdjudicate[index].internal_id });
      // Budget exhausted or XTM One unavailable: stop for this tick.
      break;
    }
  }
};

const runPolicies = async (context: AuthContext) => {
  if (Date.now() - lastPolicyRun < CURATION_POLICY_INTERVAL_MS) return;
  lastPolicyRun = Date.now();
  if (!(await isEnterpriseEdition(context))) return;
  const policies = await findEnabledPolicies(context);
  for (let index = 0; index < policies.length; index += 1) {
    try {
      const taskId = await applyCurationPolicy(context, CURATION_MANAGER_USER, policies[index]);
      if (taskId) logApp.info('[CURATION] Curation policy auto-apply scheduled', { policy: policies[index].name, task_id: taskId });
    } catch (error) {
      logApp.error('[CURATION] Curation policy auto-apply failed', { cause: error, policy_id: policies[index].internal_id });
    }
  }
};

export const curationManagerCronHandler = async () => {
  const context = executionContext(CURATION_MANAGER_CONTEXT, CURATION_MANAGER_USER);
  streamStartFrom = (await redisGetManagerEventState(CURATION_STREAM_STATE)) ?? streamStartFrom;
  const settings = await getCurationSettings(context);
  if (settings.curation_enabled && (settings.force_scan || isOlderThan(settings.last_scan_date, CURATION_SCAN_INTERVAL_MS))) {
    await runScans(context, settings);
  }
  await runSnapshotAndDigest(context, await getCurationSettings(context));
  await runAdjudicationQueue(context, settings);
  await runPolicies(context);
};
// endregion

// region stream
const TRACKED_FIELD_EXCLUSIONS = new Set(['modified', 'updated_at', 'created_at', 'refreshed_at', 'x_opencti_modified_at', 'confidence', 'revoked', 'x_opencti_files']);

const topLevelReplacements = (event: UpdateEvent) => {
  const reverse = new Map<string, unknown>();
  (event.context?.reverse_patch ?? []).forEach((operation: any) => {
    const field = typeof operation.path === 'string' ? operation.path.split('/')[1] : undefined;
    if (field && operation.path.split('/').length === 2) reverse.set(field, operation.value);
  });
  return (event.context?.patch ?? [])
    .filter((operation: any) => operation.op === 'replace' && typeof operation.path === 'string' && operation.path.split('/').length === 2)
    .map((operation: any) => ({ field: operation.path.split('/')[1] as string, value: operation.value, previous: reverse.get(operation.path.split('/')[1]) }))
    .filter((change) => !TRACKED_FIELD_EXCLUSIONS.has(change.field) && change.previous !== undefined && change.previous !== null && change.previous !== '');
};

const connectorSourcesOfUser = async (context: AuthContext, userId: string): Promise<FieldAuthoritySource[]> => {
  const connectors = await getEntitiesListFromCache<BasicStoreEntity & { connector_user_id?: string }>(context, CURATION_MANAGER_USER, ENTITY_TYPE_CONNECTOR);
  return connectors
    .filter((connector) => connector.connector_user_id === userId)
    .map((connector) => ({ source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: connector.internal_id }));
};

/**
 * Sources overwriting each other on the same field: counted for the Knowledge Health source conflict rate, and, when a
 * field authority rule says the overwritten value came from a more authoritative source, a field precedence proposal
 * suggests to restore it.
 */
const trackFieldWriters = async (
  context: AuthContext,
  settings: CurationSettings,
  event: UpdateEvent,
  eventId: string,
  entityId: string,
  entityType: string,
  drafts: ProposalDraft[],
) => {
  const writer = event.origin?.user_id;
  if (!writer || INTERNAL_USERS[writer]) return;
  const changes = topLevelReplacements(event);
  for (let index = 0; index < changes.length; index += 1) {
    const change = changes[index];
    const { previous: previousWriter, replayed } = await redisCurationSwapFieldWriter(entityId, change.field, writer, eventId, FIELD_WRITER_TTL_SECONDS);
    if (!previousWriter || previousWriter === writer || INTERNAL_USERS[previousWriter]) continue;
    if (!replayed) {
      await redisCurationIncrementCounter(SOURCE_CONFLICTS_COUNTER, today());
    }
    const rule = settings.field_authority_enabled
      ? settings.field_authority_rules.find((r) => r.entity_type === entityType && r.attribute === change.field)
      : undefined;
    if (!rule || !schemaAttributesDefinition.getAttribute(entityType, change.field)) continue;
    const decision = decideFieldAuthority(rule, await connectorSourcesOfUser(context, previousWriter), await connectorSourcesOfUser(context, writer));
    if (decision !== 'allow') continue;
    drafts.push({
      kind: PROPOSAL_KIND_FIELD_PRECEDENCE,
      detector: DETECTOR_FIELD_AUTHORITY,
      subjects: [{ id: entityId, entity_type: entityType, name: (event.data as any).name ?? entityId }],
      target_id: entityId,
      recommended_action: ACTION_SET_FIELD,
      action_payload: { element_id: entityId, key: change.field, value: change.previous, overwritten_value: change.value },
      evidence: [{
        evidence_type: EVIDENCE_FIELD_CONFLICT,
        score: 1,
        weight: 0.8,
        description: `"${change.field}" was overwritten by a less authoritative source according to the field authority rules`,
        details: JSON.stringify({ field: change.field, previous: change.previous, current: change.value, previous_writer: previousWriter, writer }),
      }],
      confidence: 0.8,
    });
  }
};

const creatorIdsOf = (stix: unknown): string[] => (stix as any)?.extensions?.[STIX_EXT_OCTI]?.creator_ids ?? [];

/** The creators of an element before an update: an upsert adds its writer to them in the same event. */
export const creatorsBeforeUpdate = (event: UpdateEvent): string[] => {
  const reversePatch = event.context?.reverse_patch ?? [];
  try {
    return creatorIdsOf(jsonpatch.applyPatch(structuredClone(event.data), reversePatch as jsonpatch.Operation[], false, false).newDocument);
  } catch {
    return creatorIdsOf(event.data);
  }
};

/**
 * The writer of a procedure is remembered from the relationship creation on and at every procedure write, so that an
 * overwrite by another source is recognised. When no writer is remembered (expired, or written before this version),
 * the writer is another source if it was not a creator of the relationship before this update.
 */
const procedureConflictDraft = async (context: AuthContext, event: StreamDataEvent, eventId: string, relationshipId: string): Promise<ProposalDraft | null> => {
  const writer = event.origin?.user_id ?? null;
  const current = (event.data as any).description as string | undefined;
  if (event.type === EVENT_TYPE_CREATE) {
    if (writer && current) await redisCurationSwapFieldWriter(relationshipId, 'description', writer, eventId, FIELD_WRITER_TTL_SECONDS);
    return null;
  }
  const update = event as UpdateEvent;
  const descriptionOperation = (update.context?.reverse_patch ?? []).find((operation: any) => operation.path === '/description') as any;
  if (!descriptionOperation) return null;
  const previous = descriptionOperation.value as string | undefined;
  const previousWriter = writer ? (await redisCurationSwapFieldWriter(relationshipId, 'description', writer, eventId, FIELD_WRITER_TTL_SECONDS)).previous : null;
  if (!isProcedureConflict(previous, current)) return null;
  const creators = creatorsBeforeUpdate(update);
  const isOtherSource = previousWriter ? previousWriter !== writer : !creators.includes(writer ?? '');
  if (!isOtherSource) return null;
  const [relationship] = await internalFindByIds(context, CURATION_MANAGER_USER, [relationshipId]) as BasicStoreRelation[];
  if (!relationship) return null;
  const record = relationship as Record<string, any>;
  return buildProcedureConflictDraft({
    relationship: {
      id: relationship.internal_id,
      name: `${record.fromName ?? relationship.fromId} uses ${record.toName ?? relationship.toId}`,
      from_id: relationship.fromId,
      from_name: record.fromName ?? relationship.fromId,
      to_id: relationship.toId,
      to_name: record.toName ?? relationship.toId,
    },
    previous: { text: previous as string, source_id: previousWriter ?? R.last(creators.filter((creator) => creator !== writer)) ?? null },
    current: { text: current as string, source_id: writer },
  });
};

const DATED_STIX_FIELDS: Array<[string, string]> = [['first_seen', 'last_seen'], ['valid_from', 'valid_until'], ['start_time', 'stop_time']];

const dateInversionDraft = (stix: Record<string, any>, entityId: string, entityType: string): ProposalDraft | null => {
  for (let index = 0; index < DATED_STIX_FIELDS.length; index += 1) {
    const [start, stop] = DATED_STIX_FIELDS[index];
    if (stix[start] && stix[stop] && new Date(stix[start]).getTime() > new Date(stix[stop]).getTime()) {
      return buildDateInversionDraft({
        internal_id: entityId,
        entity_type: entityType,
        name: stix.name ?? stix.pattern ?? entityId,
        start_field: start,
        stop_field: stop,
        start: new Date(stix[start]).toISOString(),
        stop: new Date(stix[stop]).toISOString(),
      });
    }
  }
  return null;
};

// Where a stream patch writes the names of an entity: its name, its aliases (top level, or in the OpenCTI extension for
// the types holding them in x_opencti_aliases, such as organizations and sectors) and its description.
const NAME_PATHS = ['/name', '/aliases', '/x_opencti_aliases', `/extensions/${STIX_EXT_OCTI}/aliases`, '/description'];

export const isNamePatchPath = (path: unknown) => typeof path === 'string'
  && NAME_PATHS.some((namePath) => path === namePath || path.startsWith(`${namePath}/`));

/**
 * Detections that need the event itself (previous writers, previous procedure text) are persisted event by event, so
 * that a batch replayed after a failure finds them already recorded. Entities whose names changed are collected for
 * the duplicate detection, which only needs the current graph.
 */
const processStreamEvent = async (context: AuthContext, settings: CurationSettings, streamEvent: SseEvent<DataEvent>, changedEntityIds: Set<string>) => {
  const event = streamEvent.data as any;
  const stix = event.data ?? {};
  const ext = stix.extensions?.[STIX_EXT_OCTI] ?? {};
  const entityId: string | undefined = ext.id;
  const entityType: string | undefined = ext.type;
  // The restrictions of merge records and open proposals follow their subjects in the curation records manager.
  if (!entityId || !entityType || ![EVENT_TYPE_CREATE, EVENT_TYPE_UPDATE, 'merge'].includes(event.type)) return;
  if (!settings.curation_enabled) return;
  const detectors = settings.enabled_detectors as string[];
  const drafts: ProposalDraft[] = [];
  if (settings.curated_entity_types.includes(entityType)) {
    const touchesNames = event.type !== EVENT_TYPE_UPDATE
      || (event.context?.patch ?? []).some((operation: any) => isNamePatchPath(operation.path));
    if (touchesNames && isDuplicateDetectionEnabled(settings)) changedEntityIds.add(entityId);
    if (event.type === EVENT_TYPE_UPDATE) {
      await trackFieldWriters(context, settings, event as UpdateEvent, streamEvent.id, entityId, entityType, drafts);
    }
  }
  if (detectors.includes(DETECTOR_CONTRADICTION)) {
    const inversion = dateInversionDraft(stix, entityId, entityType);
    if (inversion) drafts.push(inversion);
  }
  if (detectors.includes(DETECTOR_RELATIONSHIP_CONFLICT) && [EVENT_TYPE_CREATE, EVENT_TYPE_UPDATE].includes(event.type) && entityType === RELATION_USES
    && ext.target_type === ENTITY_TYPE_ATTACK_PATTERN) {
    const conflict = await procedureConflictDraft(context, event as StreamDataEvent, streamEvent.id, entityId);
    if (conflict) drafts.push(conflict);
  }
  const uniqueDrafts = R.uniqBy((draft) => `${draft.kind}|${draft.subjects.map((s) => s.id).join(',')}|${draft.recommended_action}`, drafts);
  for (let index = 0; index < uniqueDrafts.length; index += 1) {
    await persistProposalDraft(context, settings, uniqueDrafts[index]);
  }
};

const runIncrementalDetection = async (context: AuthContext, settings: CurationSettings, changedEntityIds: Set<string>) => {
  const batches = R.splitEvery(CURATION_STREAM_MAX_ENTITIES, [...changedEntityIds]);
  for (let index = 0; index < batches.length; index += 1) {
    await runIncrementalDuplicateDetection(context, settings, batches[index]);
  }
};

interface CurationDeadLetter {
  event: SseEvent<DataEvent>;
  replays: number;
}

/**
 * The last attempt of a failing batch processes its events one by one: an event that still fails is kept as a dead
 * letter for replay (its patch and its stream id are what the field authority and the procedure conflicts need, a
 * later scan cannot rebuild them), and the others are processed, so the batch can be checkpointed without losing any.
 */
const processBatchIsolated = async (context: AuthContext, settings: CurationSettings, streamEvents: Array<SseEvent<DataEvent>>) => {
  const changedEntityIds = new Set<string>();
  const deadLetters: CurationDeadLetter[] = [];
  for (let index = 0; index < streamEvents.length; index += 1) {
    try {
      await processStreamEvent(context, settings, streamEvents[index], changedEntityIds);
    } catch (error) {
      logApp.error('[CURATION] Stream event kept for replay', { cause: error, event_id: streamEvents[index].id, manager: CURATION_MANAGER_ID });
      deadLetters.push({ event: streamEvents[index], replays: 0 });
    }
  }
  await redisCurationPushDeadLetters(deadLetters);
  // The duplicates of the changed entities are also found by the scheduled scans, which need no event.
  try {
    await runIncrementalDetection(context, settings, changedEntityIds);
  } catch (error) {
    logApp.error('[CURATION] Live duplicate detection failed, the scheduled scan covers these entities', { cause: error, manager: CURATION_MANAGER_ID });
  }
};

/**
 * The stream position is saved only once a batch is processed. A failing batch makes the handler throw: the stream
 * processor stops and the manager restarts it from the saved position, so the batch is processed again (every step
 * is idempotent). After CURATION_STREAM_MAX_ATTEMPTS failures in a row, the batch is processed event by event and the
 * events that still fail are kept for replay, so one event that can never be processed does not block the others.
 */
export const curationManagerStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>, lastEventId: string) => {
  const context = executionContext(CURATION_MANAGER_CONTEXT, CURATION_MANAGER_USER);
  const batchKey = streamEvents[0]?.id ?? 'empty';
  const settings = await getCurationSettings(context);
  try {
    const changedEntityIds = new Set<string>();
    for (let index = 0; index < streamEvents.length; index += 1) {
      await processStreamEvent(context, settings, streamEvents[index], changedEntityIds);
    }
    await runIncrementalDetection(context, settings, changedEntityIds);
  } catch (error) {
    failedBatchAttempts = failedBatchKey === batchKey ? failedBatchAttempts + 1 : 1;
    failedBatchKey = batchKey;
    if (failedBatchAttempts < CURATION_STREAM_MAX_ATTEMPTS) {
      logApp.warn('[CURATION] Stream batch failed, it will be processed again', { cause: error, attempt: failedBatchAttempts, first_event_id: batchKey });
      throw error;
    }
    logApp.warn('[CURATION] Stream batch failed repeatedly, processing its events one by one', {
      cause: error,
      attempts: failedBatchAttempts,
      first_event_id: batchKey,
      last_event_id: lastEventId,
    });
    await processBatchIsolated(context, settings, streamEvents);
  }
  failedBatchKey = undefined;
  failedBatchAttempts = 0;
  streamStartFrom = lastEventId;
  await redisSetManagerEventState(CURATION_STREAM_STATE, lastEventId);
};

/**
 * Stream events kept after repeated failures are tried again at every manager tick; an event failing
 * CURATION_DEAD_LETTER_MAX_REPLAYS more times is dropped, with an error naming it.
 */
export const replayDeadLetters = async (context: AuthContext, settings: CurationSettings) => {
  const claimed = await redisCurationClaimDeadLetters<CurationDeadLetter>(CURATION_DEAD_LETTERS_PER_TICK);
  if (claimed.length === 0) return;
  const changedEntityIds = new Set<string>();
  for (let index = 0; index < claimed.length; index += 1) {
    const { raw, entry: deadLetter } = claimed[index];
    let kept: CurationDeadLetter | null = null;
    try {
      await processStreamEvent(context, settings, deadLetter.event, changedEntityIds);
    } catch (error) {
      const replays = deadLetter.replays + 1;
      if (replays < CURATION_DEAD_LETTER_MAX_REPLAYS) {
        kept = { ...deadLetter, replays };
      } else {
        logApp.error('[CURATION] Stream event dropped after its replays failed', { cause: error, event_id: deadLetter.event.id, replays, manager: CURATION_MANAGER_ID });
      }
    }
    // Settled only once handled: an event whose replay was interrupted is claimed again at the next tick.
    await redisCurationSettleDeadLetter(raw, kept);
  }
  await runIncrementalDetection(context, settings, changedEntityIds);
};

const curationManagerTickHandler = async () => {
  await curationManagerCronHandler();
  const context = executionContext(CURATION_MANAGER_CONTEXT, CURATION_MANAGER_USER);
  await replayDeadLetters(context, await getCurationSettings(context));
};
// endregion

const CURATION_MANAGER_DEFINITION: ManagerDefinition = {
  id: CURATION_MANAGER_ID,
  label: CURATION_MANAGER_LABEL,
  executionContext: CURATION_MANAGER_CONTEXT,
  enabledByConfig: CURATION_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  cronSchedulerHandler: {
    handler: curationManagerTickHandler,
    interval: CURATION_MANAGER_INTERVAL,
    lockKey: CURATION_MANAGER_LOCK_KEY,
    runOnStart: true,
  },
  streamSchedulerHandler: {
    handler: curationManagerStreamHandler,
    interval: CURATION_MANAGER_INTERVAL,
    lockKey: CURATION_MANAGER_STREAM_LOCK_KEY,
    streamOpts: { withInternal: false, bufferTime: 5000 },
    streamProcessorStartFrom: () => streamStartFrom ?? 'live',
  },
};

registerManager(CURATION_MANAGER_DEFINITION);
