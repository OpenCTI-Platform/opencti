import { v5 as uuidv5 } from 'uuid';
import conf, { BUS_TOPICS, logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreCommon, BasicStoreEntity, StoreMarkingDefinition } from '../../types/store';
import { isOrganizationUnrestricted, SYSTEM_USER, userFilterStoreElements } from '../../utils/access';
import { fullEntitiesList, internalFindByIds, internalLoadById } from '../../database/middleware-loader';
import { elIndexElements, elRawDeleteByQuery, elUpdate } from '../../database/engine';
import { INDEX_INTERNAL_OBJECTS, isNotEmptyField, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { cropNumber } from '../../utils/math';
import { BASE_TYPE_ENTITY, buildRefRelationKey, OPENCTI_NAMESPACE } from '../../schema/general';
import { getParentTypes } from '../../schema/schemaUtils';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { notify } from '../../database/redis';
import { lockResources } from '../../lock/master-lock';
import { DatabaseError, TYPE_LOCK_ERROR } from '../../config/errors';
import { FilterMode } from '../../generated/graphql';
import { now } from '../../utils/format';
import type { AuthorizedMember } from '../../utils/access';
import {
  ATTRIBUTE_TIMELINE_ANCHORS,
  ATTRIBUTE_TIMELINE_EXCHANGE,
  type BasicStoreEntityTimelineEvent,
  type BasicStoreEntityTimelineSettings,
  ENTITY_TYPE_TIMELINE_EVENT,
  ENTITY_TYPE_TIMELINE_SETTINGS,
  type StixTimelineExtensionAnnotation,
  type StixTimelineExtensionEvent,
  type StoreTimelineExchange,
  TIMELINE_CLEARABLE_ANALYST_FIELDS,
  TIMELINE_CONTAINER_TYPES,
  TIMELINE_DEFAULT_SETTINGS,
  type TimelineAnalystField,
  type TimelineAnchorBounds,
  type TimelineAnchorKey,
  type TimelineAnchors,
  type TimelineCappedAnnotatedEvent,
  type TimelineElementAccess,
  type TimelinePendingAnnotation,
  type TimelineSettingsState,
  type TimelineSourceState,
} from './timeline-types';
import { enqueueTimelineRegeneration } from './timeline-queue';
import {
  deriveTimelineEvents,
  type DerivedTimelineEvent,
  RULE_INVESTIGATION_RUN,
  RULE_TASK_CONTAINMENT,
  RULE_WORKFLOW_CLOSURE,
  TIMELINE_CORE_RULES,
  TIMELINE_SOFT_RULES,
  type TimelineRule,
} from './timeline-rules';
import {
  isContainerClosed,
  isTimelineSoftTypeAvailable,
  loadTimelineDerivationInput,
  SOFT_RELATION_DEPLOYED_ON,
  SOFT_TYPE_HUNT_RUN,
  SOFT_TYPE_INVESTIGATION_RUN,
  timelineRefIds,
} from './timeline-loader';
import { computeTimelineAnchorBounds, computeTimelineAnchors, diffTimelineAnchors } from './timeline-anchors';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { notifyTimelineAnchorsChanged } from './timeline-notification';
import { addTimelineDerivedEventCount } from '../../manager/telemetryManager';
import { resolveUserByIdFromCache } from '../user/user-domain';

export const TIMELINE_MAX_EVENTS: number = conf.get('timeline_manager:max_events') ?? 10000;
// Analyst milestones per case, added through the API or imported: kept apart from the derived events cap
export const TIMELINE_MAX_MANUAL_EVENTS: number = conf.get('timeline_manager:max_manual_events') ?? 1000;
// Bound of every full read of a timeline: both caps, with room for timelines built before the caps were lowered
export const TIMELINE_MAX_STORED_EVENTS: number = 2 * (TIMELINE_MAX_EVENTS + TIMELINE_MAX_MANUAL_EVENTS);

type AnyStoreElement = BasicStoreBase & Record<string, any>;
export type StoredTimelineEvent = BasicStoreEntityTimelineEvent & { _index: string } & Record<string, any>;

// region soft-check availability of the rules consuming types owned by other modules
const SOFT_RULE_TYPES: Record<string, string> = {
  'security-coverage-result': ENTITY_TYPE_SECURITY_COVERAGE,
  'hunt-run': SOFT_TYPE_HUNT_RUN,
  'indicator-deployment': SOFT_RELATION_DEPLOYED_ON,
  [RULE_INVESTIGATION_RUN]: SOFT_TYPE_INVESTIGATION_RUN,
};

export const getTimelineRules = (): TimelineRule[] => [
  ...TIMELINE_CORE_RULES,
  ...TIMELINE_SOFT_RULES.map((rule) => ({ ...rule, isAvailable: () => isTimelineSoftTypeAvailable(SOFT_RULE_TYPES[rule.id]) })),
];
// endregion

// region identifiers
// Derived rule ids that refine a rule family keep the identifier of their family, so that an event
// keeps its id (and its annotations) when its refinement changes (task labelled containment, final status).
const RULE_FAMILIES: Record<string, string> = {
  [RULE_TASK_CONTAINMENT]: 'task-lifecycle',
  [RULE_WORKFLOW_CLOSURE]: 'workflow-status',
};
export const timelineRuleFamily = (ruleId: string): string => RULE_FAMILIES[ruleId] ?? ruleId;

export const computeDerivedEventId = (containerId: string, ruleId: string, elementKey: string | null | undefined, kind: string): string => {
  return uuidv5(JSON.stringify([containerId, timelineRuleFamily(ruleId), elementKey ?? '', kind]), OPENCTI_NAMESPACE);
};

/**
 * A derived event another platform can recompute from the same knowledge: identified by its element and kind alone.
 * Events identified by a discriminator (history entries, files, hunt and investigation runs) depend on local ids no
 * receiving platform holds, so their analyst contributions stay on the platform.
 */
export const isPortableDerivedEvent = (containerId: string, event: Pick<StoredTimelineEvent, 'internal_id' | 'rule_id' | 'element_id' | 'kind'>): boolean => {
  return !!event.element_id && event.internal_id === computeDerivedEventId(containerId, event.rule_id ?? '', event.element_id, event.kind);
};

export const computeManualEventId = (containerId: string, externalId: string): string => {
  return uuidv5(JSON.stringify([containerId, 'manual', externalId]), OPENCTI_NAMESPACE);
};

export const timelineEventStandardId = (internalId: string) => `timeline-event--${internalId}`;

/**
 * At most `limit` tasks run at once and up to `maxWaiting` others wait for a slot, in order; beyond them a task is not
 * run and resolves to `{ started: false }`.
 */
export const createConcurrencyLimiter = (limit: number, maxWaiting: number) => {
  const slots = Math.max(1, limit);
  let running = 0;
  const waiting: Array<() => void> = [];
  const release = () => {
    const next = waiting.shift();
    // A released slot goes straight to the next waiting task
    if (next) next();
    else running -= 1;
  };
  return async <T>(task: () => Promise<T>): Promise<{ started: true; value: T } | { started: false }> => {
    if (running < slots) {
      running += 1;
    } else if (waiting.length < maxWaiting) {
      await new Promise<void>((resolve) => {
        waiting.push(resolve);
      });
    } else {
      return { started: false };
    }
    try {
      return { started: true, value: await task() };
    } finally {
      release();
    }
  };
};

const derivedEventKey = (event: DerivedTimelineEvent) => {
  return event.discriminator ? `${event.element_id ?? ''}|${event.discriminator}` : event.element_id;
};
// endregion

// region store helpers
const uniq = (values: Array<string | null | undefined>): string[] => Array.from(new Set(values.filter((v): v is string => !!v)));

export const markingsOf = (element: Record<string, any>): string[] => timelineRefIds(element, RELATION_OBJECT_MARKING);

/** Elements whose data a stored event carries besides its element, as recorded by the regeneration: each is read like the element. */
export const timelineEventSourceIds = (event: Pick<StoredTimelineEvent, 'element_access'>): string[] => {
  return (event.element_access?.sources ?? []).map((source) => source.id);
};

/** Element and sources of an event, the container aside: the user reads the event only when he can access each of them. */
export const referencedElementIds = (event: Pick<StoredTimelineEvent, 'element_id' | 'element_access'>, containerId: string): string[] => {
  return [event.element_id, ...timelineEventSourceIds(event)].filter((id): id is string => !!id && id !== containerId);
};

/** An event as the access checks read it: its element and sources, with its element type and markings for the deleted ones. */
export type TimelineReadableEvent = Pick<StoredTimelineEvent, 'internal_id' | 'element_id' | 'element_access'> & Partial<StoredTimelineEvent>;

/**
 * An element or a source of the event deleted since, as the regeneration recorded it on the event: its type and its access
 * beyond markings, the markings of the event standing for its own. Null without a record (an event never regenerated since
 * it was added, a source recorded without its type): nobody reads the event any more.
 */
export const recordedTimelineReference = (event: TimelineReadableEvent, id: string): BasicStoreCommon | null => {
  const source = id === event.element_id ? undefined : (event.element_access?.sources ?? []).find((candidate) => candidate.id === id);
  let recorded: { entity_type: string; access: { restricted_members?: AuthorizedMember[]; granted?: string[] } } | null = null;
  if (id === event.element_id) {
    recorded = event.element_type && event.element_access ? { entity_type: event.element_type, access: event.element_access } : null;
  } else if (source?.entity_type) {
    recorded = { entity_type: source.entity_type, access: source };
  }
  if (!recorded) return null;
  return {
    internal_id: id,
    entity_type: recorded.entity_type,
    [RELATION_OBJECT_MARKING]: markingsOf(event),
    restricted_members: recorded.access.restricted_members ?? [],
    [RELATION_GRANTED_TO]: recorded.access.granted ?? [],
  } as unknown as BasicStoreCommon;
};

/**
 * Of the events referencing an element or a source missing from `readable` (what the user reads), the ids of the ones
 * he reads anyway: each missing reference was deleted, and the access recorded for it lets him read it. A reference that
 * still exists is read as it is now: one he cannot read keeps the event hidden.
 */
export const findEventsReadableThroughRecords = async (
  context: AuthContext,
  user: AuthUser,
  containerId: string,
  events: TimelineReadableEvent[],
  readable: Record<string, unknown>,
): Promise<Set<string>> => {
  const missingOf = (event: TimelineReadableEvent) => referencedElementIds(event, containerId).filter((id) => !readable[id]);
  const missingIds = uniq(events.flatMap(missingOf));
  if (missingIds.length === 0) return new Set();
  const existing = await internalFindByIds(context, SYSTEM_USER, missingIds, { toMap: true, baseData: true }) as unknown as Record<string, unknown>;
  const candidates = events.flatMap((event) => {
    const missing = missingOf(event);
    if (missing.length === 0 || missing.some((id) => !!existing[id])) return [];
    const records = missing.map((id) => recordedTimelineReference(event, id));
    return records.every((record) => record !== null) ? [{ id: event.internal_id, records: records as BasicStoreCommon[] }] : [];
  });
  const records = candidates.flatMap((candidate) => candidate.records);
  const readableRecords = new Set(records.length > 0 ? await userFilterStoreElements(context, user, records) : []);
  return new Set(candidates.filter((candidate) => candidate.records.every((record) => readableRecords.has(record))).map((candidate) => candidate.id));
};

/**
 * Drop the events pointing to elements, or carrying data of sources, the user cannot see. One deleted since is read from
 * the access recorded on the event: the users who read the event still do, and can remove it.
 */
export const filterAccessibleEvents = async <T>(
  context: AuthContext,
  user: AuthUser,
  containerId: string,
  items: T[],
  getEvent: (item: T) => TimelineReadableEvent,
  opts: { fullElements?: boolean } = {},
): Promise<{ items: T[]; elements: Record<string, AnyStoreElement> }> => {
  const elementIds = Array.from(new Set(items.flatMap((item) => referencedElementIds(getEvent(item), containerId))));
  const elements = elementIds.length > 0
    ? await internalFindByIds(context, user, elementIds, { toMap: true, baseData: !opts.fullElements }) as unknown as Record<string, AnyStoreElement>
    : {};
  const isResolved = (event: TimelineReadableEvent) => referencedElementIds(event, containerId).every((id) => !!elements[id]);
  const unresolved = items.map(getEvent).filter((event) => !isResolved(event));
  const readableThroughRecords = unresolved.length > 0
    ? await findEventsReadableThroughRecords(context, user, containerId, unresolved, elements)
    : new Set<string>();
  const filtered = items.filter((item) => {
    const event = getEvent(item);
    return isResolved(event) || readableThroughRecords.has(event.internal_id);
  });
  return { items: filtered, elements };
};

/**
 * A timeline event is never less marked than its element (whatever the rule of a derived event reads), nor than its
 * container: once the element is deleted, the markings of the event stand for those of the element.
 */
export const timelineEventMarkings = (eventMarkings: string[], element: Record<string, any> | undefined, containerMarkings: string[]): string[] => {
  return uniq([...eventMarkings, ...(element ? markingsOf(element) : []), ...containerMarkings]);
};

// Every stored event of the container, page by page: events stored under higher caps than the current ones must still be
// found, to be rewritten or cleaned up
export const loadStoredTimelineEvents = async (context: AuthContext, containerId: string): Promise<StoredTimelineEvent[]> => {
  return fullEntitiesList<StoredTimelineEvent>(context, SYSTEM_USER, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: { mode: FilterMode.And, filters: [{ key: ['container_id'], values: [containerId] }], filterGroups: [] },
    noFiltersChecking: true,
    // Events are rewritten from what is loaded here: their author must come along with them
    withoutRels: false,
  } as any);
};

const TIMELINE_INITIAL_STATE: TimelineSettingsState = {
  ...TIMELINE_DEFAULT_SETTINGS,
  pending_annotations: [],
  derivation_truncated: false,
  capped_anchor_bounds: null,
  capped_annotated_events: [],
  generated_at: null,
};

const stateOf = (settings: Partial<TimelineSettingsState> | null | undefined): TimelineSettingsState => ({
  enabled_lanes: settings?.enabled_lanes ?? TIMELINE_INITIAL_STATE.enabled_lanes,
  default_grouping: settings?.default_grouping ?? TIMELINE_INITIAL_STATE.default_grouping,
  default_zoom_window: settings?.default_zoom_window ?? TIMELINE_INITIAL_STATE.default_zoom_window,
  hidden_kinds: settings?.hidden_kinds ?? TIMELINE_INITIAL_STATE.hidden_kinds,
  pending_annotations: settings?.pending_annotations ?? [],
  derivation_truncated: settings?.derivation_truncated ?? false,
  capped_anchor_bounds: settings?.capped_anchor_bounds ?? null,
  capped_annotated_events: settings?.capped_annotated_events ?? [],
  generated_at: settings?.generated_at ?? null,
});

export const loadTimelineSettings = async (context: AuthContext, containerId: string): Promise<BasicStoreEntityTimelineSettings & { _index: string } | undefined> => {
  const settings = await fullEntitiesList<BasicStoreEntityTimelineSettings & { _index: string }>(context, SYSTEM_USER, [ENTITY_TYPE_TIMELINE_SETTINGS], {
    filters: { mode: FilterMode.And, filters: [{ key: ['container_id'], values: [containerId] }], filterGroups: [] },
    noFiltersChecking: true,
    maxSize: 1,
  } as any);
  const [document] = settings;
  return document ? { ...document, ...stateOf(document.timeline_state) } : undefined;
};

const CONTENT_FIELDS = [
  'name', 'description', 'event_time', 'event_end_time', 'open_ended', 'time_precision', 'lane', 'kind', 'event_source', 'rule_id', 'element_id', 'element_type',
  'pinned', 'hidden', 'annotation', 'confidence', 'ordering_hint', 'analyst_fields', 'external_id', 'restricted_members', 'creator_id',
  'source_state', 'element_access', buildRefRelationKey(RELATION_OBJECT_MARKING), buildRefRelationKey(RELATION_CREATED_BY),
];

const normalizeForSignature = (value: unknown): unknown => {
  if (value === undefined || value === null || value === '') return null;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.length === 0 ? null : [...value].map(normalizeForSignature).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    const time = new Date(value).getTime();
    return Number.isNaN(time) ? value : new Date(time).toISOString();
  }
  return value;
};

// The events written before the open end of a window existed carry no such field: they read like closed windows
const signatureValueOf = (doc: Record<string, any>, field: string): unknown => (field === 'open_ended' ? doc.open_ended === true : doc[field]);

export const timelineEventSignature = (doc: Record<string, any>): string => {
  return JSON.stringify(CONTENT_FIELDS.map((field) => normalizeForSignature(signatureValueOf(doc, field))));
};

const ACCESS_FIELDS = ['restricted_members', 'element_access', buildRefRelationKey(RELATION_OBJECT_MARKING)];

/** Whether who may read the event changed between two versions of it (its markings, members or the access of its element). */
export const isTimelineEventAccessChanged = (previous: Record<string, any>, next: Record<string, any>): boolean => {
  return ACCESS_FIELDS.some((field) => JSON.stringify(normalizeForSignature(previous[field])) !== JSON.stringify(normalizeForSignature(next[field])));
};

/**
 * Whether the update of a regeneration goes, like a truncated one, to every reader of the case so that an open timeline
 * refreshes: an event whose access changed is no longer named to the readers who lost it, and a removed event carrying
 * data of other elements is named to nobody once one of them is deleted (a hunt run event after its run).
 */
export const isTimelineRefreshForEveryReader = (
  changed: Array<{ previous: Record<string, any> | undefined; next: Record<string, any> }>,
  removed: Array<Pick<StoredTimelineEvent, 'element_access'>>,
): boolean => {
  return changed.some(({ previous, next }) => !!previous && isTimelineEventAccessChanged(previous, next))
    || removed.some((event) => timelineEventSourceIds(event).length > 0);
};

export interface TimelineEventDocInput {
  internal_id: string;
  container_id: string;
  name: string;
  description?: string | null;
  event_time: string;
  event_end_time?: string | null;
  open_ended?: boolean | null;
  time_precision: string;
  lane: string;
  kind: string;
  event_source: 'derived' | 'manual';
  rule_id?: string | null;
  element_id?: string | null;
  element_type?: string | null;
  pinned: boolean;
  hidden: boolean;
  annotation?: string | null;
  confidence?: number | null;
  ordering_hint?: number | null;
  analyst_fields: TimelineAnalystField[];
  external_id?: string | null;
  markings: string[];
  created_by_id?: string | null;
  creator_ids: string[];
  restricted_members: AuthorizedMember[];
  source_state?: TimelineSourceState | null;
  element_access?: TimelineElementAccess | null;
}

export const buildTimelineEventDoc = (input: TimelineEventDocInput, existing?: StoredTimelineEvent | null) => {
  const timestamp = now();
  return {
    _index: existing?._index ?? INDEX_INTERNAL_OBJECTS,
    internal_id: input.internal_id,
    standard_id: existing?.standard_id ?? timelineEventStandardId(input.internal_id),
    entity_type: ENTITY_TYPE_TIMELINE_EVENT,
    base_type: BASE_TYPE_ENTITY,
    parent_types: getParentTypes(ENTITY_TYPE_TIMELINE_EVENT),
    created_at: existing?.created_at ?? timestamp,
    updated_at: timestamp,
    creator_id: input.creator_ids,
    container_id: input.container_id,
    name: input.name,
    description: input.description ?? null,
    event_time: input.event_time,
    event_end_time: input.event_end_time ?? null,
    // Always a boolean: the indexing writes a boolean attribute that is not true, an undefined one included, as false
    open_ended: input.open_ended === true,
    time_precision: input.time_precision,
    lane: input.lane,
    kind: input.kind,
    event_source: input.event_source,
    rule_id: input.rule_id ?? null,
    element_id: input.element_id ?? null,
    element_type: input.element_type ?? null,
    pinned: input.pinned,
    hidden: input.hidden,
    annotation: input.annotation ?? null,
    confidence: input.confidence ?? null,
    ordering_hint: input.ordering_hint ?? null,
    analyst_fields: input.analyst_fields,
    external_id: input.external_id ?? null,
    source_state: input.source_state ?? null,
    element_access: input.element_access ?? null,
    restricted_members: input.restricted_members,
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: uniq(input.markings),
    [buildRefRelationKey(RELATION_CREATED_BY)]: input.created_by_id ? [input.created_by_id] : [],
  };
};

export type StoredTimelineSettings = BasicStoreEntityTimelineSettings & { _index: string };

/** Create or patch the settings of a container timeline (one document per container, deterministic id). */
export const upsertTimelineSettings = async (
  context: AuthContext,
  container: AnyStoreElement,
  patch: Partial<TimelineSettingsState>,
  existingSettings?: StoredTimelineSettings | null,
): Promise<StoredTimelineSettings> => {
  const existing = existingSettings !== undefined ? existingSettings : await loadTimelineSettings(context, container.internal_id);
  const restricted_members = (container.restricted_members ?? []) as AuthorizedMember[];
  // The whole state is written: a partial update merges objects key by key and would keep stale keys otherwise
  const state: TimelineSettingsState = { ...stateOf(existing), ...patch };
  if (existing) {
    const doc = { timeline_state: state, restricted_members, updated_at: now() };
    await elUpdate(context, existing._index, existing.internal_id, { doc });
    return { ...existing, ...doc, ...state } as unknown as StoredTimelineSettings;
  }
  const internalId = uuidv5(JSON.stringify([container.internal_id, 'settings']), OPENCTI_NAMESPACE);
  const timestamp = now();
  const doc = {
    _index: INDEX_INTERNAL_OBJECTS,
    internal_id: internalId,
    standard_id: `timeline-settings--${internalId}`,
    entity_type: ENTITY_TYPE_TIMELINE_SETTINGS,
    base_type: BASE_TYPE_ENTITY,
    parent_types: getParentTypes(ENTITY_TYPE_TIMELINE_SETTINGS),
    created_at: timestamp,
    updated_at: timestamp,
    container_id: container.internal_id,
    timeline_state: state,
    restricted_members,
  };
  await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_SETTINGS, [doc]);
  return { ...doc, ...state } as unknown as StoredTimelineSettings;
};

export const deleteTimelineDocuments = async (ids: string[]) => {
  if (ids.length === 0) return;
  await elRawDeleteByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    body: { query: { terms: { 'internal_id.keyword': ids } } },
  }).catch((err: unknown) => {
    throw DatabaseError('Error deleting timeline events', { cause: err });
  });
};

export const deleteContainerTimeline = async (containerId: string) => {
  await elRawDeleteByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    body: {
      query: {
        bool: {
          must: [
            { terms: { 'entity_type.keyword': [ENTITY_TYPE_TIMELINE_EVENT, ENTITY_TYPE_TIMELINE_SETTINGS] } },
            { term: { 'container_id.keyword': containerId } },
          ],
        },
      },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Error deleting container timeline', { cause: err });
  });
};

export const containerAccessFields = (container: AnyStoreElement) => ({
  markings: markingsOf(container),
  restricted_members: (container.restricted_members ?? []) as AuthorizedMember[],
});
// endregion

// region live updates
/** An event removed by a change, with what decides who could read it (the event itself can no longer be loaded) */
export interface TimelineRemovedEvent {
  id: string;
  element_id: string | null;
  element_type: string | null;
  marking_ids: string[];
  element_access: TimelineElementAccess | null;
}

// Bound of the event ids an update names; an update about more events says so with `truncated`
export const TIMELINE_UPDATE_MAX_EVENTS = 500;

export interface TimelineUpdatePayload {
  id: string;
  container_id: string;
  update_type: 'derived' | 'manual' | 'annotation' | 'settings' | 'anchors';
  changed_event_ids: string[];
  // Resolved per subscriber into changed_event_ids, never sent as is
  removed_events?: TimelineRemovedEvent[];
  truncated?: boolean;
  updated_at: string;
  anchors?: TimelineAnchors | null;
}

export const toRemovedTimelineEvents = (events: StoredTimelineEvent[]): TimelineRemovedEvent[] => events.map((event) => ({
  id: event.internal_id,
  element_id: event.element_id ?? null,
  element_type: event.element_type ?? null,
  marking_ids: markingsOf(event),
  element_access: event.element_access ?? null,
}));

// The author of the change does not receive its own update (the subscription filters on the publishing user)
export const publishTimelineUpdate = async (payload: Omit<TimelineUpdatePayload, 'id' | 'updated_at'>, user: AuthUser = SYSTEM_USER) => {
  const event: TimelineUpdatePayload = { ...payload, id: payload.container_id, updated_at: now() };
  await notify(BUS_TOPICS[ENTITY_TYPE_TIMELINE_EVENT].EDIT_TOPIC, event, user);
};
// endregion

// region contributions (anchors and STIX exchange) refreshed from the stored events
const grantedOf = (element: Record<string, any>): string[] => timelineRefIds(element, RELATION_GRANTED_TO);

/** Access of an element beyond its markings (which its events carry), recorded on the events that point to it. */
export const timelineElementAccessOf = (element: Record<string, any>): TimelineElementAccess => ({
  restricted_members: (element.restricted_members ?? []) as AuthorizedMember[],
  granted: grantedOf(element),
});

// Who reads an element beyond its markings, by the platform access rules: its authorized members only when it has some
// (they bypass organization sharing); otherwise, under a platform organization and for a type restricted by
// organization, the platform organization and each organization it is shared with; otherwise every user. Null: no bound.
interface TimelineElementReaders {
  members: Set<string> | null;
  organizations: Set<string> | null;
}

const memberKey = (member: AuthorizedMember): string => JSON.stringify([member.id, [...(member.groups_restriction_ids ?? [])].sort()]);

const readersOf = (element: Record<string, any>, hasPlatformOrganization: boolean): TimelineElementReaders => {
  const members = (element.restricted_members ?? []) as AuthorizedMember[];
  if (members.length > 0) return { members: new Set(members.map(memberKey)), organizations: null };
  if (!hasPlatformOrganization || isOrganizationUnrestricted(element as BasicStoreCommon)) return { members: null, organizations: null };
  return { members: null, organizations: new Set(grantedOf(element)) };
};

// A reader the comparison cannot place (an authorized member against organization sharing) counts as a new one
const isReadByNoMoreThan = (next: TimelineElementReaders, previous: TimelineElementReaders): boolean => {
  const { members, organizations } = previous;
  if (members) return !!next.members && Array.from(next.members).every((key) => members.has(key));
  if (organizations) return !next.members && !!next.organizations && Array.from(next.organizations).every((id) => organizations.has(id));
  return true;
};

/**
 * Whether pointing an event of the container from its element to another one, or to none, lets users read it who could
 * not before, markings aside (the event keeps the markings of every element it pointed to). An event is read like its
 * container and its element: the change is safe when the new element, or the container itself, has no reader the
 * previous element lacks.
 */
export const isTimelineElementChangeWidening = (
  container: Record<string, any>,
  previous: Record<string, any> | null | undefined,
  next: Record<string, any> | null | undefined,
  hasPlatformOrganization: boolean,
): boolean => {
  if (!previous || previous.internal_id === next?.internal_id) return false;
  const previousReaders = readersOf(previous, hasPlatformOrganization);
  const nextReaders: TimelineElementReaders = next ? readersOf(next, hasPlatformOrganization) : { members: null, organizations: null };
  return !isReadByNoMoreThan(nextReaders, previousReaders) && !isReadByNoMoreThan(readersOf(container, hasPlatformOrganization), previousReaders);
};
const authorOf = (event: StoredTimelineEvent): string | undefined => (event[buildRefRelationKey(RELATION_CREATED_BY)] ?? [])[0];

interface ContainerVisibilityScope {
  resolved: Record<string, AnyStoreElement>;
  /** The element is readable by every reader of the container: same markings at most, no authorized members, shared with the same organizations at least */
  isElementAsVisibleAsContainer: (element: AnyStoreElement) => boolean;
  /** The event and the element it references are readable by every reader of the container */
  isEventAsVisibleAsContainer: (event: StoredTimelineEvent) => boolean;
  /** The element and sources of the event are restricted to no authorized member and shared with the organizations of the container at least, whatever their markings */
  isEventSharedAsContainer: (event: StoredTimelineEvent) => boolean;
}

/**
 * Whether every reader of a container can read a marking: the container carries it, or a marking of the same type
 * with an order at least as high (a reader allowed TLP:AMBER is allowed TLP:GREEN). An unknown marking is never covered.
 */
export const buildContainerMarkingCoverage = (containerMarkingIds: string[], markingsMap: Map<string, Pick<StoreMarkingDefinition, 'definition_type' | 'x_opencti_order'>>) => {
  const containerMarkings = new Set(containerMarkingIds);
  const maxOrderByType = new Map<string, number>();
  containerMarkingIds.forEach((id) => {
    const marking = markingsMap.get(id);
    if (!marking) return;
    const current = maxOrderByType.get(marking.definition_type);
    if (current === undefined || marking.x_opencti_order > current) maxOrderByType.set(marking.definition_type, marking.x_opencti_order);
  });
  return (markingId: string): boolean => {
    if (containerMarkings.has(markingId)) return true;
    const marking = markingsMap.get(markingId);
    if (!marking) return false;
    const maxOrder = maxOrderByType.get(marking.definition_type);
    return maxOrder !== undefined && marking.x_opencti_order <= maxOrder;
  };
};

/**
 * What is stored once on the container (anchors, STIX exchange) is served to every user who can read the container:
 * it may only derive from events, and elements they reference, exactly as visible as the container.
 */
const resolveContainerVisibilityScope = async (
  context: AuthContext,
  container: AnyStoreElement,
  events: StoredTimelineEvent[],
  // Elements already read the same way (system user, base data): only the others are read here
  preloaded: Record<string, AnyStoreElement> = {},
): Promise<ContainerVisibilityScope> => {
  const containerId = container.internal_id;
  const containerGranted = grantedOf(container);
  const elementIds = uniq(events.flatMap((e) => [e.element_id, ...timelineEventSourceIds(e)]).filter((id): id is string => !!id && id !== containerId));
  const authorIds = uniq(events.filter((e) => e.event_source === 'manual').map(authorOf).filter((id): id is string => !!id));
  const toRead = [...elementIds, ...authorIds].filter((id) => !preloaded[id]);
  // Base data carries the authorized members; markings and organization sharing come with every read as security doc values
  const read = toRead.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, toRead, { toMap: true, baseData: true }) as unknown as Record<string, AnyStoreElement>
    : {};
  const resolved = { ...preloaded, ...read };
  const markingsMap = await getEntitiesMapFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const isMarkingCoveredByContainer = buildContainerMarkingCoverage(markingsOf(container), markingsMap);
  const isElementSharedAsContainer = (element: AnyStoreElement) => {
    if ((element.restricted_members ?? []).length > 0) return false;
    // A type no organization restricts (a user, an organization, a marking...) is read whatever the sharing
    if (isOrganizationUnrestricted(element as unknown as BasicStoreCommon)) return true;
    // Organization sharing (platform access rules): an object shared with no organization is readable inside the platform
    // organization only, a shared object inside the platform organization and in each organization it is shared with.
    // An element is therefore readable by every reader of the container when it is shared with at least the
    // organizations of the container; an unshared container is read inside the platform organization only.
    const granted = new Set(grantedOf(element));
    return containerGranted.every((id) => granted.has(id));
  };
  const isElementAsVisibleAsContainer = (element: AnyStoreElement) => {
    return isElementSharedAsContainer(element) && markingsOf(element).every(isMarkingCoveredByContainer);
  };
  // The sources of a derived event (the relationships dating a technique, the run behind a finding) date or describe it
  // like its element. The access scope of a deleted element or source is unknown while the event still speaks about it:
  // never as visible as the container
  const isEventReferencesMatching = (event: StoredTimelineEvent, isElementMatching: (element: AnyStoreElement) => boolean) => {
    const referencedIds = [event.element_id, ...timelineEventSourceIds(event)].filter((id): id is string => !!id && id !== containerId);
    return referencedIds.every((id) => !!resolved[id] && isElementMatching(resolved[id]));
  };
  const isEventAsVisibleAsContainer = (event: StoredTimelineEvent) => {
    return markingsOf(event).every(isMarkingCoveredByContainer) && isEventReferencesMatching(event, isElementAsVisibleAsContainer);
  };
  const isEventSharedAsContainer = (event: StoredTimelineEvent) => isEventReferencesMatching(event, isElementSharedAsContainer);
  return { resolved, isElementAsVisibleAsContainer, isEventAsVisibleAsContainer, isEventSharedAsContainer };
};

/**
 * A file stored in the container is read by every reader of the container whose markings cover the file markings, which
 * already cover the markings of its events and of their elements. Beyond markings, the file only holds the events whose
 * element and sources are restricted to no authorized member and shared with the organizations of the container at least.
 */
export const filterEventsSharedAsContainer = async (context: AuthContext, container: AnyStoreElement, events: StoredTimelineEvent[]): Promise<StoredTimelineEvent[]> => {
  if (events.length === 0) return events;
  const scope = await resolveContainerVisibilityScope(context, container, events);
  return events.filter(scope.isEventSharedAsContainer);
};

/**
 * The annotation a derived event carries in the STIX exchange: only its analyst fields, a cleared annotation or ordering
 * hint named in `cleared_fields` so that the receiving platform clears it too.
 */
export const timelineExchangeAnnotation = (
  event: Pick<StoredTimelineEvent, 'rule_id' | 'kind' | 'analyst_fields' | 'pinned' | 'hidden' | 'annotation' | 'ordering_hint'>,
  elementRef: string,
): StixTimelineExtensionAnnotation => {
  const fields = event.analyst_fields ?? [];
  const cleared = TIMELINE_CLEARABLE_ANALYST_FIELDS.filter((field) => fields.includes(field) && !isNotEmptyField(event[field]));
  return {
    rule_id: timelineRuleFamily(event.rule_id ?? ''),
    kind: event.kind,
    element_ref: elementRef,
    pinned: fields.includes('pinned') ? event.pinned : undefined,
    hidden: fields.includes('hidden') ? event.hidden : undefined,
    annotation: fields.includes('annotation') ? (event.annotation || undefined) : undefined,
    ordering_hint: fields.includes('ordering_hint') ? (event.ordering_hint ?? undefined) : undefined,
    cleared_fields: cleared.length > 0 ? cleared : undefined,
  };
};

/**
 * The exchange is stored once on the container and served to every user who can read the container, in toStix and
 * in bundles: it only carries contributions exactly as visible as the container. Events marked more strictly than the
 * container are left out, and so are the references to (and annotations of) elements marked more strictly, restricted
 * to authorized members or shared with fewer organizations than the container.
 */
const buildExchange = async (
  context: AuthContext,
  container: AnyStoreElement,
  events: StoredTimelineEvent[],
  scope: ContainerVisibilityScope,
): Promise<StoreTimelineExchange> => {
  const containerId = container.internal_id;
  const { resolved, isElementAsVisibleAsContainer, isEventAsVisibleAsContainer } = scope;
  // The title and description of a manual event speak about its element: the event travels only when both are as visible as the container
  const manual = events.filter((e) => e.event_source === 'manual' && isEventAsVisibleAsContainer(e));
  const annotated = events.filter((e) => e.event_source === 'derived' && (e.analyst_fields ?? []).length > 0
    && isPortableDerivedEvent(containerId, e) && isEventAsVisibleAsContainer(e));
  const portableElementRef = (elementId: string | null | undefined): string | undefined => {
    const element = elementId ? resolved[elementId] : undefined;
    return element && isElementAsVisibleAsContainer(element) ? element.standard_id as string : undefined;
  };
  const markingsMap = await getEntitiesMapFromCache<AnyStoreElement>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const toStandardIds = (ids: string[]): string[] => ids.flatMap((id) => {
    const standardId = markingsMap.get(id)?.standard_id;
    return standardId ? [standardId as string] : [];
  });
  const exchangeEvents: StixTimelineExtensionEvent[] = manual.map((event) => ({
    id: event.standard_id as string,
    external_id: event.external_id || undefined,
    event_time: new Date(event.event_time).toISOString(),
    event_end_time: event.event_end_time ? new Date(event.event_end_time).toISOString() : undefined,
    precision: event.time_precision,
    lane: event.lane,
    kind: event.kind,
    title: event.name,
    description: event.description || undefined,
    element_ref: portableElementRef(event.element_id),
    confidence: event.confidence ?? undefined,
    ordering_hint: event.ordering_hint ?? undefined,
    pinned: event.pinned || undefined,
    hidden: event.hidden || undefined,
    annotation: event.annotation || undefined,
    object_marking_refs: toStandardIds(markingsOf(event)),
    // The author is a reference like the element: it travels only when it is as visible as the container
    created_by_ref: portableElementRef(authorOf(event)),
  }));
  const exchangeAnnotations: StixTimelineExtensionAnnotation[] = annotated
    .filter((event) => !!portableElementRef(event.element_id))
    .map((event) => timelineExchangeAnnotation(event, portableElementRef(event.element_id) as string));
  return { events: exchangeEvents, annotations: exchangeAnnotations };
};

export interface TimelineContributionsResult {
  anchors: TimelineAnchors;
  changedAnchors: TimelineAnchorKey[];
  // Anchor values of the anchor events passed beyond the stored ones, null when none were passed
  cappedAnchorBounds: TimelineAnchorBounds | null;
}

/** The derived events of a regeneration the cap of the case leaves out while they carry analyst fields, as recorded in its state. */
export const timelineCappedAnnotatedEvents = (
  derivedDocs: Array<ReturnType<typeof buildTimelineEventDoc>>,
  storedIds: Set<string>,
): TimelineCappedAnnotatedEvent[] => {
  return derivedDocs
    .filter((doc) => !storedIds.has(doc.internal_id) && doc.analyst_fields.length > 0 && !!doc.rule_id && !!doc.element_id)
    // Bounded like the pending annotations they come back from
    .slice(0, TIMELINE_MAX_EVENTS)
    .map((doc) => {
      const fields = new Set<TimelineAnalystField>(doc.analyst_fields);
      return {
        internal_id: doc.internal_id,
        rule_id: doc.rule_id as string,
        kind: doc.kind as TimelineCappedAnnotatedEvent['kind'],
        element_id: doc.element_id as string,
        markings: markingsOf(doc),
        element_access: doc.element_access,
        analyst_fields: doc.analyst_fields,
        pinned: doc.pinned,
        hidden: doc.hidden,
        annotation: fields.has('annotation') ? doc.annotation : null,
        ordering_hint: fields.has('ordering_hint') ? doc.ordering_hint : null,
      };
    });
};

/** A recorded derived event beyond the cap, read like a stored event by the exchange and its visibility checks. */
export const timelineCappedAnnotatedEventAsStored = (event: TimelineCappedAnnotatedEvent): StoredTimelineEvent => {
  const { markings, ...fields } = event;
  return { ...fields, event_source: 'derived', [buildRefRelationKey(RELATION_OBJECT_MARKING)]: markings } as unknown as StoredTimelineEvent;
};

/**
 * Recompute the anchors and the STIX exchange of a container from its stored events and write them
 * on the container through the side channel: no stream event, no history, no modification date change.
 * Both are exposed to every reader of the container (attribute, filters, orderings, notifications), so an event
 * a reader may not see never moves an anchor.
 */
export const refreshTimelineContributions = async (
  context: AuthContext,
  container: AnyStoreElement,
  // anchorEvents: the events the anchors are computed from when they are more than the stored ones (a regeneration
  // beyond the cap of the case passes every derived event, so that the cap never moves an anchor).
  // anchorBounds: the anchor values of the derived events beyond the cap, read from the settings when not given; a
  // change between two regenerations (milestone, pin, hide) computes the anchors from the stored events and these bounds
  opts: {
    events?: StoredTimelineEvent[];
    anchorEvents?: StoredTimelineEvent[];
    anchorBounds?: TimelineAnchorBounds | null;
    // The annotated derived events beyond the cap, read from the settings when not given: their annotations travel too
    cappedAnnotatedEvents?: TimelineCappedAnnotatedEvent[];
    // Elements of the events already read as the system user, base data
    elements?: Record<string, AnyStoreElement>;
    notifyAnchors?: boolean;
    // Set by a regeneration only: computed_at tells when the timeline was last generated from the knowledge, and the
    // consistency pass regenerates the timelines whose computed_at is too old, however often analysts curate them
    regenerated?: boolean;
    // The user whose change moved the anchors: like his other updates, he does not receive this one
    actor?: AuthUser;
  } = {},
): Promise<TimelineContributionsResult> => {
  const events = opts.events ?? await loadStoredTimelineEvents(context, container.internal_id);
  const anchorEvents = opts.anchorEvents ?? events;
  const isAnchorBoundsGiven = !!opts.anchorEvents || opts.anchorBounds !== undefined;
  const settings = !isAnchorBoundsGiven || !opts.cappedAnnotatedEvents ? await loadTimelineSettings(context, container.internal_id) : undefined;
  const anchorBounds = isAnchorBoundsGiven ? opts.anchorBounds ?? null : settings?.capped_anchor_bounds ?? null;
  const storedIds = new Set(events.map((e) => e.internal_id));
  const cappedAnnotated = (opts.cappedAnnotatedEvents ?? settings?.capped_annotated_events ?? [])
    .filter((event) => !storedIds.has(event.internal_id))
    .map(timelineCappedAnnotatedEventAsStored);
  const isClosed = await isContainerClosed(context, container);
  const previousAnchors = container[ATTRIBUTE_TIMELINE_ANCHORS] as Partial<TimelineAnchors> | undefined;
  const scope = await resolveContainerVisibilityScope(context, container, [...anchorEvents, ...cappedAnnotated], opts.elements);
  const anchorInput = anchorEvents.filter(scope.isEventAsVisibleAsContainer);
  const toAnchorEvent = (e: StoredTimelineEvent) => ({ lane: e.lane, kind: e.kind, rule_id: e.rule_id, event_time: e.event_time, hidden: e.hidden });
  const computedAt = now();
  const previousGeneratedAt = previousAnchors?.computed_at ? new Date(previousAnchors.computed_at as string).toISOString() : undefined;
  // A contribution to a timeline never generated keeps it so: the first read or the consistency pass still generates it
  const generatedAt = opts.regenerated ? computedAt : (previousGeneratedAt ?? null);
  const anchors = computeTimelineAnchors(anchorInput.map(toAnchorEvent), { isClosed, computedAt, generatedAt, previous: previousAnchors, bounds: anchorBounds });
  const cappedAnchorBounds = opts.anchorEvents
    ? computeTimelineAnchorBounds(anchorInput.filter((e) => !storedIds.has(e.internal_id)).map(toAnchorEvent))
    : null;
  const exchange = await buildExchange(context, container, [...events, ...cappedAnnotated], scope);
  const changedAnchors = diffTimelineAnchors(previousAnchors, anchors);
  await elUpdate(context, container._index, container.internal_id, {
    doc: { [ATTRIBUTE_TIMELINE_ANCHORS]: anchors, [ATTRIBUTE_TIMELINE_EXCHANGE]: exchange },
  });
  // The first computation (backfill) is not a change an analyst wants to be notified about
  const hadAnchors = !!previousAnchors?.computed_at;
  if (changedAnchors.length > 0) {
    await publishTimelineUpdate({ container_id: container.internal_id, update_type: 'anchors', changed_event_ids: [], anchors }, opts.actor);
    if (hadAnchors && opts.notifyAnchors !== false) {
      await notifyTimelineAnchorsChanged(context, container.internal_id, changedAnchors, anchors)
        .catch((error) => logApp.error('[TIMELINE] Unable to notify anchor changes', { cause: error, containerId: container.internal_id }));
    }
  }
  return { anchors, changedAnchors, cappedAnchorBounds };
};
// endregion

// region regeneration
const LANE_PRIORITY: Record<string, number> = { adversary: 0, detection: 1, response: 2, evidence: 3, knowledge: 4, custom: 5 };

const pendingAnnotationsMap = (settings: BasicStoreEntityTimelineSettings | undefined) => {
  return new Map<string, TimelinePendingAnnotation>((settings?.pending_annotations ?? []).map((a) => [a.event_id, a]));
};

/** Highest confidence of a timeline event the user may pin, hide or annotate, read like `controlUserConfidenceAgainstElement`; null when none. */
export const timelineEventMaxConfidence = (user: AuthUser): number | null => {
  const override = user.effective_confidence_level?.overrides?.find((o) => o.entity_type === ENTITY_TYPE_TIMELINE_EVENT);
  const maxConfidence = override?.max_confidence ?? user.effective_confidence_level?.max_confidence;
  return isNotEmptyField(maxConfidence) ? maxConfidence as number : null;
};

/**
 * The analyst fields of a derived event as an annotation waiting for the event, set by users the confidence check of
 * the event already let through: they apply whatever the confidence of the event.
 */
export const keptAnalystFields = (event: Pick<StoredTimelineEvent, 'internal_id' | 'analyst_fields' | 'pinned' | 'hidden' | 'annotation' | 'ordering_hint'>): TimelinePendingAnnotation => {
  const fields = new Set<TimelineAnalystField>(event.analyst_fields ?? []);
  return {
    event_id: event.internal_id,
    ...(fields.has('pinned') ? { pinned: event.pinned } : {}),
    ...(fields.has('hidden') ? { hidden: event.hidden } : {}),
    ...(fields.has('annotation') ? { annotation: event.annotation ?? null } : {}),
    ...(fields.has('ordering_hint') ? { ordering_hint: event.ordering_hint ?? null } : {}),
    max_confidence: 100,
  };
};

/** An imported annotation applies to a derived event only within the confidence level its importer had. */
export const isPendingAnnotationApplicable = (annotation: TimelinePendingAnnotation, confidence: number | null | undefined): boolean => {
  return isNotEmptyField(annotation.max_confidence) && cropNumber(confidence ?? 0, 0, 100) <= (annotation.max_confidence as number);
};

type PendingAnnotationTarget = Pick<StoredTimelineEvent, 'internal_id' | 'element_id' | 'element_access'>;

/**
 * Ids of the derived events whose imported annotation its importer cannot read, as the regeneration produces them: the
 * element and each source of the event are read as the importer, like a read of the stored event. An importer who no
 * longer exists reads nothing.
 */
const findAnnotationTargetsUnreadableByImporter = async (
  context: AuthContext,
  containerId: string,
  targets: PendingAnnotationTarget[],
  pending: Map<string, TimelinePendingAnnotation>,
): Promise<Set<string>> => {
  const targetsByImporter = new Map<string, PendingAnnotationTarget[]>();
  targets.forEach((target) => {
    const importerId = pending.get(target.internal_id)?.importer_id;
    if (importerId) targetsByImporter.set(importerId, [...(targetsByImporter.get(importerId) ?? []), target]);
  });
  const unreadable = await Promise.all(Array.from(targetsByImporter).map(async ([importerId, importerTargets]) => {
    const importer = await resolveUserByIdFromCache(context, importerId);
    if (!importer) return importerTargets.map((target) => target.internal_id);
    const { items } = await filterAccessibleEvents(context, importer, containerId, importerTargets, (target) => target);
    const readable = new Set(items.map((target) => target.internal_id));
    return importerTargets.filter((target) => !readable.has(target.internal_id)).map((target) => target.internal_id);
  }));
  return new Set(unreadable.flat());
};

const applyAnalystFields = (
  base: { pinned: boolean; hidden: boolean; annotation: string | null; ordering_hint: number | null },
  existing: StoredTimelineEvent | undefined,
  pending: TimelinePendingAnnotation | undefined,
) => {
  const result = { ...base };
  const fields = new Set<TimelineAnalystField>(existing?.analyst_fields ?? []);
  if (existing) {
    if (fields.has('pinned')) result.pinned = existing.pinned;
    if (fields.has('hidden')) result.hidden = existing.hidden;
    if (fields.has('annotation')) result.annotation = existing.annotation ?? null;
    if (fields.has('ordering_hint')) result.ordering_hint = existing.ordering_hint ?? null;
  }
  if (pending) {
    if (pending.pinned !== undefined) {
      result.pinned = pending.pinned;
      fields.add('pinned');
    }
    if (pending.hidden !== undefined) {
      result.hidden = pending.hidden;
      fields.add('hidden');
    }
    if (pending.annotation !== undefined) {
      result.annotation = pending.annotation ?? null;
      fields.add('annotation');
    }
    if (pending.ordering_hint !== undefined) {
      result.ordering_hint = pending.ordering_hint ?? null;
      fields.add('ordering_hint');
    }
  }
  return { ...result, analyst_fields: Array.from(fields) };
};

export interface TimelineRegenerationResult {
  container_id: string;
  derived_count: number;
  manual_count: number;
  created_count: number;
  updated_count: number;
  deleted_count: number;
  truncated: boolean;
  anchors: TimelineAnchors | null;
  duration_ms: number;
}

const regenerateLocked = async (context: AuthContext, container: AnyStoreElement, actor?: AuthUser): Promise<TimelineRegenerationResult> => {
  const start = Date.now();
  const containerId = container.internal_id;
  const { input, truncated: inputTruncated } = await loadTimelineDerivationInput(context, container);
  let derived = deriveTimelineEvents(input, getTimelineRules(), (ruleId, error) => {
    logApp.error('[TIMELINE] Derivation rule failure', { cause: error, ruleId, containerId });
  });
  let truncated = inputTruncated;
  // Every derived event counts for the anchors; only the capped subset is stored
  const allDerived = derived;
  const capped = derived.length > TIMELINE_MAX_EVENTS;
  if (capped) {
    // Keep the most meaningful events first (adversary, detection, response, ...) and the oldest within a lane
    derived = [...derived]
      .sort((a, b) => (LANE_PRIORITY[a.lane] - LANE_PRIORITY[b.lane]) || a.event_time.localeCompare(b.event_time))
      .slice(0, TIMELINE_MAX_EVENTS);
    truncated = true;
  }
  const stored = await loadStoredTimelineEvents(context, containerId);
  const storedById = new Map(stored.map((e) => [e.internal_id, e]));
  const settings = await loadTimelineSettings(context, containerId);
  const pending = pendingAnnotationsMap(settings);
  const access = containerAccessFields(container);
  // The access of each element beyond its markings is kept on its events: once the element is deleted, it still decides
  // who may learn of their removal. The same read serves the visibility scope of the anchors.
  const storedManual = stored.filter((e) => e.event_source === 'manual');
  const elementIds = uniq([
    ...[...allDerived, ...storedManual].map((event) => event.element_id),
    ...allDerived.flatMap((event) => event.source_ids ?? []),
  ].filter((id): id is string => !!id && id !== containerId));
  const elements = elementIds.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, elementIds, { toMap: true, baseData: true }) as unknown as Record<string, AnyStoreElement>
    : {};
  const elementAccessOf = (elementId: string | null | undefined, sourceIds: string[] = []): TimelineElementAccess | null => {
    const element = elementId ? elements[elementId] : undefined;
    if (!element) return null;
    // A source no longer found keeps its id: the reads look for it and never find it, until the next regeneration drops it
    const sources = uniq(sourceIds).map((id) => (elements[id]
      ? { id, entity_type: elements[id].entity_type, ...timelineElementAccessOf(elements[id]) }
      : { id, restricted_members: [], granted: [] }));
    return sources.length > 0 ? { ...timelineElementAccessOf(element), sources } : timelineElementAccessOf(element);
  };
  // A derived event is never less marked than the elements whose data it carries, whatever its rule merged
  const sourceMarkingsOf = (event: DerivedTimelineEvent): string[] => (event.source_ids ?? []).flatMap((id) => (elements[id] ? markingsOf(elements[id]) : []));
  // An imported annotation pins, hides or annotates the event like an edit of the event: its importer must read the event
  // as produced now, its element and each of its sources
  const annotationTargets = new Map<string, PendingAnnotationTarget>();
  allDerived.forEach((event) => {
    const internalId = computeDerivedEventId(containerId, event.rule_id, derivedEventKey(event), event.kind);
    if (!annotationTargets.has(internalId) && pending.get(internalId)?.importer_id) {
      annotationTargets.set(internalId, { internal_id: internalId, element_id: event.element_id, element_access: elementAccessOf(event.element_id, event.source_ids) });
    }
  });
  const unreadableAnnotationIds = await findAnnotationTargetsUnreadableByImporter(context, containerId, Array.from(annotationTargets.values()), pending);
  // Build the derived documents, deduplicated on their deterministic id
  const derivedDocsById = new Map<string, ReturnType<typeof buildTimelineEventDoc>>();
  const refusedAnnotationIds: string[] = [];
  allDerived.forEach((event) => {
    const internalId = computeDerivedEventId(containerId, event.rule_id, derivedEventKey(event), event.kind);
    if (derivedDocsById.has(internalId)) return;
    const existing = storedById.get(internalId);
    const pendingAnnotation = pending.get(internalId);
    const applicable = pendingAnnotation && !unreadableAnnotationIds.has(internalId) && isPendingAnnotationApplicable(pendingAnnotation, event.confidence);
    if (pendingAnnotation && !applicable) refusedAnnotationIds.push(internalId);
    const analyst = applyAnalystFields(
      { pinned: false, hidden: false, annotation: null, ordering_hint: event.ordering_hint ?? null },
      existing,
      applicable ? pendingAnnotation : undefined,
    );
    derivedDocsById.set(internalId, buildTimelineEventDoc({
      internal_id: internalId,
      container_id: containerId,
      name: event.name,
      description: event.description,
      event_time: event.event_time,
      event_end_time: event.event_end_time,
      open_ended: event.open_ended,
      time_precision: event.time_precision,
      lane: event.lane,
      kind: event.kind,
      event_source: 'derived',
      rule_id: event.rule_id,
      element_id: event.element_id,
      element_type: event.element_type,
      confidence: event.confidence,
      external_id: null,
      markings: timelineEventMarkings([...event.markings, ...sourceMarkingsOf(event)], event.element_id ? elements[event.element_id] : undefined, access.markings),
      created_by_id: event.created_by_id,
      creator_ids: event.creator_ids ?? [],
      restricted_members: access.restricted_members,
      source_state: event.source_state ?? null,
      element_access: elementAccessOf(event.element_id, event.source_ids),
      ...analyst,
    }, existing));
  });
  const keptIds = capped
    ? new Set(derived.map((event) => computeDerivedEventId(containerId, event.rule_id, derivedEventKey(event), event.kind)))
    : null;
  const docsById = new Map(Array.from(derivedDocsById).filter(([internalId]) => !keptIds || keptIds.has(internalId)));
  // Manual events follow the access of the container and of their element: never less marked than either, with the access
  // of the element beyond its markings recorded like on derived events (a deleted element keeps the markings it gave)
  storedManual.forEach((event) => {
    const element = event.element_id && event.element_id !== containerId ? elements[event.element_id] : undefined;
    const markings = timelineEventMarkings(markingsOf(event), element, access.markings);
    const doc = buildTimelineEventDoc({
      internal_id: event.internal_id,
      container_id: containerId,
      name: event.name,
      description: event.description,
      event_time: event.event_time,
      event_end_time: event.event_end_time,
      time_precision: event.time_precision,
      lane: event.lane,
      kind: event.kind,
      event_source: 'manual',
      rule_id: null,
      element_id: event.element_id,
      element_type: event.element_type,
      pinned: event.pinned,
      hidden: event.hidden,
      annotation: event.annotation,
      confidence: event.confidence,
      ordering_hint: event.ordering_hint,
      analyst_fields: event.analyst_fields ?? [],
      external_id: event.external_id,
      markings,
      created_by_id: (event[buildRefRelationKey(RELATION_CREATED_BY)] ?? [])[0],
      creator_ids: Array.isArray(event.creator_id) ? event.creator_id : uniq([event.creator_id as string]),
      restricted_members: access.restricted_members,
      // Once its element is deleted, the event keeps the access recorded for it: it decides who still reads the event
      element_access: element ? elementAccessOf(event.element_id) : (event.element_id && event.element_id !== containerId ? (event.element_access ?? null) : null),
    }, event);
    docsById.set(event.internal_id, doc);
  });
  const docs = Array.from(docsById.values());
  const changedDocs = docs.filter((doc) => {
    const existing = storedById.get(doc.internal_id);
    return !existing || timelineEventSignature(existing) !== timelineEventSignature(doc);
  });
  const createdCount = changedDocs.filter((doc) => !storedById.has(doc.internal_id)).length;
  if (changedDocs.length > 0) {
    await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, changedDocs);
  }
  const staleEvents = stored.filter((e) => e.event_source === 'derived' && !docsById.has(e.internal_id));
  const staleIds = staleEvents.map((e) => e.internal_id);
  await deleteTimelineDocuments(staleIds);
  // Consume the imported annotations that found their event and record the generation
  const remaining = new Map((settings?.pending_annotations ?? []).filter((a) => !docsById.has(a.event_id)).map((a) => [a.event_id, a]));
  // A derived event pushed out by the cap of the case keeps its analyst fields in the timeline state: they come back
  // with the event once it is within the cap again
  staleEvents.filter((event) => derivedDocsById.has(event.internal_id) && (event.analyst_fields ?? []).length > 0).forEach((event) => {
    if (!remaining.has(event.internal_id) && remaining.size < TIMELINE_MAX_EVENTS) {
      remaining.set(event.internal_id, keptAnalystFields(event));
    }
  });
  const refusedAnnotations = refusedAnnotationIds.filter((id) => docsById.has(id)).length;
  if (refusedAnnotations > 0) {
    logApp.warn('[TIMELINE] Imported annotations of events their importer cannot read or above his confidence level were not applied', { containerId, refused: refusedAnnotations });
  }
  // Their annotations keep travelling in the STIX exchange while they are out of the cap
  const cappedAnnotatedEvents = capped ? timelineCappedAnnotatedEvents(Array.from(derivedDocsById.values()), new Set(docsById.keys())) : [];
  const generatedSettings = await upsertTimelineSettings(context, container, {
    pending_annotations: Array.from(remaining.values()),
    derivation_truncated: truncated,
    generated_at: now(),
    capped_annotated_events: cappedAnnotatedEvents,
    ...(capped ? {} : { capped_anchor_bounds: null }),
  }, settings ?? null);
  if (createdCount > 0) {
    addTimelineDerivedEventCount(createdCount);
  }
  const finalEvents = docs as unknown as StoredTimelineEvent[];
  // Beyond the cap of the case, the anchors still read every derived event: the cap never moves the containment or the closure
  const anchorEvents = capped
    ? [...derivedDocsById.values(), ...docs.filter((doc) => doc.event_source === 'manual')] as unknown as StoredTimelineEvent[]
    : undefined;
  const { anchors, cappedAnchorBounds } = await refreshTimelineContributions(context, container, {
    events: finalEvents,
    anchorEvents,
    anchorBounds: null,
    cappedAnnotatedEvents,
    elements,
    regenerated: true,
    actor,
  });
  if (capped) {
    // The changes made until the next regeneration recompute the anchors from the stored events and these bounds
    await upsertTimelineSettings(context, container, { capped_anchor_bounds: cappedAnchorBounds }, generatedSettings);
  }
  if (changedDocs.length > 0 || staleEvents.length > 0) {
    const refreshEveryReader = isTimelineRefreshForEveryReader(
      changedDocs.map((doc) => ({ previous: storedById.get(doc.internal_id), next: doc })),
      staleEvents,
    );
    await publishTimelineUpdate({
      container_id: containerId,
      update_type: 'derived',
      changed_event_ids: changedDocs.map((d) => d.internal_id).slice(0, TIMELINE_UPDATE_MAX_EVENTS),
      removed_events: toRemovedTimelineEvents(staleEvents.slice(0, TIMELINE_UPDATE_MAX_EVENTS)),
      truncated: refreshEveryReader || changedDocs.length > TIMELINE_UPDATE_MAX_EVENTS || staleEvents.length > TIMELINE_UPDATE_MAX_EVENTS,
      anchors,
    }, actor);
  }
  return {
    container_id: containerId,
    derived_count: docs.filter((d) => d.event_source === 'derived').length,
    manual_count: docs.filter((d) => d.event_source === 'manual').length,
    created_count: createdCount,
    updated_count: changedDocs.length - createdCount,
    deleted_count: staleIds.length,
    truncated,
    anchors,
    duration_ms: Date.now() - start,
  };
};

const timelineLockKey = (containerId: string) => `timeline_regeneration_${containerId}`;

/**
 * Every write to the timeline of a container (regeneration, analyst contributions, settings) runs under one
 * per-container lock, so that a regeneration never rebuilds events or settings from a snapshot older than a
 * contribution, and contributions never interleave with each other.
 */
export const withTimelineLock = async <T>(containerId: string, write: () => Promise<T>): Promise<T> => {
  let lock;
  try {
    lock = await lockResources([timelineLockKey(containerId)]);
    return await write();
  } finally {
    if (lock) await lock.unlock();
  }
};

/**
 * Regenerate the derived events of a container. Idempotent: derived events have deterministic ids,
 * unchanged events are not rewritten and analyst fields survive. Returns null when another
 * regeneration of the same container is already running, or, with `skipIfGenerated`, when a
 * concurrent call generated the timeline while this one was waiting for the lock. The updates of a regeneration asked
 * by a user (`actor`) are published as his, so that he does not receive them, like the updates of his other changes.
 */
export const regenerateContainerTimeline = async (
  context: AuthContext,
  containerId: string,
  opts: { wait?: boolean; skipIfGenerated?: boolean; actor?: AuthUser } = {},
): Promise<TimelineRegenerationResult | null> => {
  const container = await internalLoadById<AnyStoreElement>(context, SYSTEM_USER, containerId, { type: TIMELINE_CONTAINER_TYPES });
  if (!container) {
    // The container is gone: its timeline goes with it
    await deleteContainerTimeline(containerId);
    return null;
  }
  let lock;
  try {
    // Background regenerations skip a container being regenerated, explicit ones wait for it
    lock = await lockResources([timelineLockKey(container.internal_id)], opts.wait ? {} : { retryCount: 0 });
    // The snapshot is read again under the lock: a contribution may have changed the container while this call waited
    const current = await internalLoadById<AnyStoreElement>(context, SYSTEM_USER, container.internal_id, { type: TIMELINE_CONTAINER_TYPES });
    if (!current) {
      await deleteContainerTimeline(container.internal_id);
      return null;
    }
    if (opts.skipIfGenerated && current[ATTRIBUTE_TIMELINE_ANCHORS]?.computed_at) return null;
    return await regenerateLocked(context, current, opts.actor);
  } catch (error: any) {
    if (error?.name === TYPE_LOCK_ERROR) {
      // The running regeneration may have started before the latest changes: another one is scheduled
      await enqueueTimelineRegeneration([container.internal_id]);
      logApp.debug('[TIMELINE] Regeneration already running, scheduled again', { containerId });
      return null;
    }
    throw error;
  } finally {
    if (lock) await lock.unlock();
  }
};
// endregion

export type StoredTimelineContainer = AnyStoreElement & BasicStoreEntity;
