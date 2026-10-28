import { now } from 'moment';
import type { AuthContext, AuthUser } from '../../types/user';
import { countAllThings, type EntityOptions, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, IR_MATCH_IN_STATUSES } from './intelligenceRequirementMatch-types';
import { ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM } from './intelligenceRequirementItem-types';
import { createEntity, distributionEntities, internalDeleteElementById, timeSeriesEntities } from '../../database/middleware';
import { fetchStreamInfo } from '../../database/stream/stream-handler';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG, logApp } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { deleteInternalObject, editInternalObject } from '../../domain/internalObject';
import { enforceEnableFeatureFlag, SYSTEM_USER, MEMBER_ACCESS_ALL, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_VIEW } from '../../utils/access';
import type { EditInput, IntelligenceRequirementInput } from '../../generated/graphql';
import { FunctionalError } from '../../config/errors';
import {
  type BasicStoreEntityIntelligenceRequirement,
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT,
  type StoreEntityIntelligenceRequirement,
  type StoreIrProcessing,
} from './intelligenceRequirement-types';
import { parseIntelligenceRequirement, serializeIntelligenceRequirementInput } from './intelligenceRequirement-config';
import { rescoreRequirement } from './intelligenceRequirement-pipeline';
import { checkRequirementHealth } from './intelligenceRequirement-health';
import { generateRequirementBrief, markBriefStarted } from './intelligenceRequirement-brief';
import { markRequirementDeleted, markRequirementRescan } from './intelligenceRequirement-lifecycle';
import { invalidateInRequirementEntityIds } from './intelligenceRequirementMatch-domain';

const rescanStartEventId = (rescanDays: number) => `${now() - (rescanDays * 24 * 3600 * 1000)}-0`;

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  return storeLoadById<BasicStoreEntityIntelligenceRequirement>(context, user, id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
};

export const findIntelligenceRequirementPaginated = async (context: AuthContext, user: AuthUser, opts?: EntityOptions<BasicStoreEntityIntelligenceRequirement>) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  return pageEntitiesConnection<BasicStoreEntityIntelligenceRequirement>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT], opts);
};

export const intelligenceRequirementAdd = async (context: AuthContext, user: AuthUser, input: IntelligenceRequirementInput) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  const attributes = serializeIntelligenceRequirementInput(input);
  const authorized_members = input.authorized_members ?? [
    { id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN },
    { id: MEMBER_ACCESS_ALL, access_right: MEMBER_ACCESS_RIGHT_VIEW },
  ];
  const nowDate = new Date();
  const lastEventId = rescanStartEventId(attributes.ir_rescan_days);
  const ir_processing = JSON.stringify({ catchup_from: lastEventId });
  const finalInput = { ...attributes, lastEventId, ir_processing, authorized_members, created_at: nowDate, updated_at: nowDate };
  const created = await createEntity(context, user, finalInput, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates intelligence requirement \`${created.name}\``,
    context_data: { id: created.internal_id, entity_type: ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, input: attributes },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

/**
 * Replace the whole configuration of a requirement.
 * When only the relevance changes, the stream position is kept: the stored entities are rescored.
 * When the scope changes (subjects, criteria, conditions), the entities that did not meet the former scope were never stored:
 * the stream is read again from the rescan window, so that a wider scope brings them in.
 */
export const intelligenceRequirementUpdate = async (context: AuthContext, user: AuthUser, id: string, input: IntelligenceRequirementInput) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  const existing = await findById(context, user, id);
  if (!existing) throw FunctionalError('Intelligence requirement not found', { id });
  const attributes = serializeIntelligenceRequirementInput(input);
  const editInputs: EditInput[] = Object.entries(attributes).map(([key, value]) => ({ key, value: Array.isArray(value) ? value : [value] }));
  const scopeChanged = existing.ir_scope_criteria !== attributes.ir_scope_criteria || existing.ir_subject_groups !== attributes.ir_subject_groups;
  if (scopeChanged) {
    const lastEventId = rescanStartEventId(attributes.ir_rescan_days);
    const processing = { ...parseRequirementProcessing(existing), catchup_from: lastEventId };
    editInputs.push({ key: 'lastEventId', value: [lastEventId] }, { key: 'ir_processing', value: [JSON.stringify(processing)] });
    markRequirementRescan(id);
  }
  const updated = await editInternalObject<StoreEntityIntelligenceRequirement>(context, user, id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, editInputs);
  // Relevance rules may have changed: rescore the entities of the requirement (threshold crossings create inbox items)
  await rescoreRequirement(context, SYSTEM_USER, parseIntelligenceRequirement(updated as unknown as BasicStoreEntityIntelligenceRequirement), {
    kind: 'config',
    trigger: `Configuration changed by ${user.name}`,
  });
  return updated;
};

export const intelligenceRequirementStatusUpdate = async (context: AuthContext, user: AuthUser, id: string, status: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  return editInternalObject<StoreEntityIntelligenceRequirement>(context, user, id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, [{ key: 'ir_status', value: [status] }]);
};

// Entities (whatever their status, eligible or not) and inbox items stored for a requirement
export const countRequirementStoredContent = async (context: AuthContext, user: AuthUser, irId: string) => {
  const filters = addFilter(undefined, 'ir_id', irId);
  const count = (type: string) => countAllThings(context, user, { types: [type], indices: [READ_INDEX_INTERNAL_OBJECTS], filters });
  return { entities: await count(ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH), items: await count(ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM) };
};

const deleteRequirementContent = async (context: AuthContext, id: string) => {
  const children = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM], {
    filters: addFilter(undefined, 'ir_id', id),
  });
  for (let i = 0; i < children.length; i += 1) {
    await internalDeleteElementById(context, SYSTEM_USER, children[i].id, children[i].entity_type);
  }
  return children.length;
};

const DELETE_SWEEP_DELAY = 30 * 1000;

/**
 * Permanent deletion of a requirement and of everything stored for it (entities, inbox items, briefs).
 * The engine stops writing into it at once; a second sweep removes what a batch in flight may still have written.
 */
export const intelligenceRequirementDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  markRequirementDeleted(id);
  invalidateInRequirementEntityIds(id);
  const deleted = await deleteInternalObject(context, user, id, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
  await deleteRequirementContent(context, id);
  setTimeout(() => {
    deleteRequirementContent(context, id)
      .then((swept) => (swept > 0 ? logApp.info('[OPENCTI-MODULE] Intelligence requirement content swept after deletion', { requirement: id, swept }) : null))
      .catch((err) => logApp.error('[OPENCTI-MODULE] Intelligence requirement deletion sweep error', { cause: err, requirement: id }));
  }, DELETE_SWEEP_DELAY);
  return deleted;
};

/**
 * Engine side: move the stream position of a requirement without audit log.
 */
export const updateIntelligenceRequirementLastEventId = async (context: AuthContext, user: AuthUser, id: string, lastEventId: string, processing?: StoreIrProcessing) => {
  return editInternalObject<StoreEntityIntelligenceRequirement>(
    context,
    user,
    id,
    ENTITY_TYPE_INTELLIGENCE_REQUIREMENT,
    [{ key: 'lastEventId', value: [lastEventId] }, ...(processing ? [{ key: 'ir_processing', value: [JSON.stringify(processing)] }] : [])],
    { auditLogEnabled: false },
  );
};

const LIVE_LAG_SECONDS = 120;
const eventMs = (eventId: string | undefined | null) => {
  const ms = Number.parseInt((eventId ?? '').split('-')[0], 10);
  return Number.isNaN(ms) ? null : ms;
};

/**
 * Where the requirement stands in the stream: live, catching up or paused, the progress of its catch-up,
 * its lag behind the stream (in time, and an estimate in events), its last batch and its last error.
 */
export const requirementProcessingStatus = async (context: AuthContext, user: AuthUser, ir: BasicStoreEntityIntelligenceRequirement) => {
  const processing = parseRequirementProcessing(ir);
  const stream = await fetchStreamInfo();
  const headMs = eventMs(stream.lastEventId) ?? Date.now();
  const firstMs = eventMs(stream.firstEventId) ?? headMs;
  const cursorMs = Math.min(eventMs(ir.lastEventId) ?? headMs, headMs);
  const createdMs = new Date(ir.created_at ?? Date.now()).getTime();
  const catchupFromMs = Math.max(eventMs(processing.catchup_from) ?? createdMs - (ir.ir_rescan_days ?? 30) * 24 * 3600 * 1000, firstMs);
  const span = headMs - catchupFromMs;
  const lagSeconds = Math.max(0, Math.round((headMs - cursorMs) / 1000));
  const lagEvents = headMs > firstMs ? Math.round((stream.streamSize ?? 0) * ((headMs - cursorMs) / (headMs - firstMs))) : 0;
  let state = 'catching_up';
  if (ir.ir_status !== 'active') state = 'paused';
  else if (lagSeconds <= LIVE_LAG_SECONDS) state = 'live';
  const activeRequirements = await countAllThings(context, user, {
    types: [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT],
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: addFilter(undefined, 'ir_status', 'active'),
  });
  return {
    state,
    progress: span > 0 ? Math.max(0, Math.min(100, Math.round(((cursorMs - catchupFromMs) / span) * 100))) : 100,
    cursor_at: new Date(cursorMs).toISOString(),
    stream_head_at: new Date(headMs).toISOString(),
    catchup_from_at: new Date(catchupFromMs).toISOString(),
    lag_seconds: lagSeconds,
    lag_events: lagEvents,
    stream_size: stream.streamSize ?? 0,
    active_requirements: activeRequirements,
    last_batch: processing.last_batch ?? null,
    totals: processing.totals ?? null,
    last_error: processing.last_error ?? null,
  };
};

export const parseRequirementProcessing = (ir: BasicStoreEntityIntelligenceRequirement): StoreIrProcessing => {
  try {
    return JSON.parse(ir.ir_processing || '{}');
  } catch {
    return {};
  }
};

// region list indicators (entities in the requirement, open inbox items, activity)
export const countRequirementEntities = async (context: AuthContext, user: AuthUser, irId: string) => {
  const filters = addFilter(addFilter(undefined, 'ir_id', irId), 'match_status', IR_MATCH_IN_STATUSES);
  return countAllThings(context, user, { types: [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], indices: [READ_INDEX_INTERNAL_OBJECTS], filters });
};

export const countRequirementOpenItems = async (context: AuthContext, user: AuthUser, irId: string) => {
  const filters = addFilter(addFilter(undefined, 'ir_id', irId), 'item_status', 'open');
  return countAllThings(context, user, { types: [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM], indices: [READ_INDEX_INTERNAL_OBJECTS], filters });
};

// Inbox counters for the filter buttons (open items per kind, done items)
export const countRequirementInbox = async (context: AuthContext, user: AuthUser, irId: string) => {
  const count = (status: string, kind?: string) => {
    let filters = addFilter(addFilter(undefined, 'ir_id', irId), 'item_status', status);
    if (kind) filters = addFilter(filters, 'item_kind', kind);
    return countAllThings(context, user, { types: [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM], indices: [READ_INDEX_INTERNAL_OBJECTS], filters });
  };
  const [open, proposed, entered, score, health, brief, done] = await Promise.all([
    count('open'), count('open', 'proposed'), count('open', 'entered'), count('open', 'score'), count('open', 'health'), count('open', 'brief'), count('done'),
  ]);
  return { open, proposed, entered, score, health, brief, done };
};

// Entities entering the requirement (in or proposed) per day over the last days
export const requirementActivity = async (context: AuthContext, user: AuthUser, irId: string, days: number) => {
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - Math.max(1, days) * 24 * 3600 * 1000);
  const filters = addFilter(undefined, 'ir_id', irId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], { filters, startDate, endDate, interval: 'day', field: 'created_at' } as any);
};
// endregion

// Health checks on demand (they also run periodically in the manager)
export const intelligenceRequirementHealthCheck = async (context: AuthContext, user: AuthUser, id: string) => {
  const ir = await findById(context, user, id);
  if (!ir) throw FunctionalError('Intelligence requirement not found', { id });
  return checkRequirementHealth(context, user, parseIntelligenceRequirement(ir));
};

// AI brief on demand (also generated at the frequency of the requirement by the manager)
export const intelligenceRequirementBriefGenerate = async (context: AuthContext, user: AuthUser, id: string) => {
  const ir = await findById(context, user, id);
  if (!ir) throw FunctionalError('Intelligence requirement not found', { id });
  const item = await generateRequirementBrief(context, user, ir, 'manual');
  if (!item) throw FunctionalError('The brief could not be generated: XTM One, an identity or an agent bound to the cti.pir_insight intent is missing', { id });
  await markBriefStarted(context, user, id);
  return item;
};

// Entities of the requirement per type, for the quick type filters of the entities list
export const countRequirementEntitiesByType = async (context: AuthContext, user: AuthUser, irId: string, statuses?: string[] | null, excluded?: boolean | null) => {
  let filters = addFilter(undefined, 'ir_id', irId);
  if (statuses && statuses.length > 0) filters = addFilter(filters, 'match_status', statuses);
  if (excluded !== null && excluded !== undefined) filters = addFilter(filters, 'match_excluded', String(excluded));
  const distribution = await distributionEntities(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], { field: 'match_entity_type', filters, limit: 50 });
  return distribution.map((d) => ({ entity_type: d.label, count: d.value })).sort((a, b) => b.count - a.count);
};
