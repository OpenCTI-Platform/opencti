import { v5 as uuidv5 } from 'uuid';
import conf, { BUS_TOPICS, logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, StoreMarkingDefinition } from '../../types/store';
import { SYSTEM_USER } from '../../utils/access';
import { fullEntitiesList, internalFindByIds, internalLoadById } from '../../database/middleware-loader';
import { elIndexElements, elRawDeleteByQuery, elUpdate } from '../../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
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
  TIMELINE_CONTAINER_TYPES,
  TIMELINE_DEFAULT_SETTINGS,
  type TimelineAnalystField,
  type TimelineAnchorKey,
  type TimelineAnchors,
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
import { computeTimelineAnchors, diffTimelineAnchors } from './timeline-anchors';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { notifyTimelineAnchorsChanged } from './timeline-notification';
import { addTimelineDerivedEventCount } from '../../manager/telemetryManager';

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

export const computeManualEventId = (containerId: string, externalId: string): string => {
  return uuidv5(JSON.stringify([containerId, 'manual', externalId]), OPENCTI_NAMESPACE);
};

export const timelineEventStandardId = (internalId: string) => `timeline-event--${internalId}`;

const derivedEventKey = (event: DerivedTimelineEvent) => {
  return event.discriminator ? `${event.element_id ?? ''}|${event.discriminator}` : event.element_id;
};
// endregion

// region store helpers
const uniq = (values: Array<string | null | undefined>): string[] => Array.from(new Set(values.filter((v): v is string => !!v)));

export const markingsOf = (element: Record<string, any>): string[] => timelineRefIds(element, RELATION_OBJECT_MARKING);

export const loadStoredTimelineEvents = async (context: AuthContext, containerId: string): Promise<StoredTimelineEvent[]> => {
  return fullEntitiesList<StoredTimelineEvent>(context, SYSTEM_USER, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: { mode: FilterMode.And, filters: [{ key: ['container_id'], values: [containerId] }], filterGroups: [] },
    noFiltersChecking: true,
    // Events are rewritten from what is loaded here: their author must come along with them
    withoutRels: false,
    maxSize: TIMELINE_MAX_STORED_EVENTS,
  } as any);
};

const TIMELINE_INITIAL_STATE: TimelineSettingsState = {
  ...TIMELINE_DEFAULT_SETTINGS,
  pending_annotations: [],
  derivation_truncated: false,
  generated_at: null,
};

const stateOf = (settings: Partial<TimelineSettingsState> | null | undefined): TimelineSettingsState => ({
  enabled_lanes: settings?.enabled_lanes ?? TIMELINE_INITIAL_STATE.enabled_lanes,
  default_grouping: settings?.default_grouping ?? TIMELINE_INITIAL_STATE.default_grouping,
  default_zoom_window: settings?.default_zoom_window ?? TIMELINE_INITIAL_STATE.default_zoom_window,
  hidden_kinds: settings?.hidden_kinds ?? TIMELINE_INITIAL_STATE.hidden_kinds,
  pending_annotations: settings?.pending_annotations ?? [],
  derivation_truncated: settings?.derivation_truncated ?? false,
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
  'name', 'description', 'event_time', 'event_end_time', 'time_precision', 'lane', 'kind', 'event_source', 'rule_id', 'element_id', 'element_type',
  'pinned', 'hidden', 'annotation', 'confidence', 'ordering_hint', 'analyst_fields', 'external_id', 'restricted_members', 'creator_id',
  'source_state', buildRefRelationKey(RELATION_OBJECT_MARKING), buildRefRelationKey(RELATION_CREATED_BY),
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

export const timelineEventSignature = (doc: Record<string, any>): string => {
  return JSON.stringify(CONTENT_FIELDS.map((field) => normalizeForSignature(doc[field])));
};

export interface TimelineEventDocInput {
  internal_id: string;
  container_id: string;
  name: string;
  description?: string | null;
  event_time: string;
  event_end_time?: string | null;
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
export interface TimelineUpdatePayload {
  id: string;
  container_id: string;
  update_type: 'derived' | 'manual' | 'annotation' | 'settings' | 'anchors';
  changed_event_ids: string[];
  updated_at: string;
  anchors?: TimelineAnchors | null;
}

// The author of the change does not receive its own update (the subscription filters on the publishing user)
export const publishTimelineUpdate = async (payload: Omit<TimelineUpdatePayload, 'id' | 'updated_at'>, user: AuthUser = SYSTEM_USER) => {
  const event: TimelineUpdatePayload = { ...payload, id: payload.container_id, updated_at: now() };
  await notify(BUS_TOPICS[ENTITY_TYPE_TIMELINE_EVENT].EDIT_TOPIC, event, user);
};
// endregion

// region contributions (anchors and STIX exchange) refreshed from the stored events
const grantedOf = (element: Record<string, any>): string[] => timelineRefIds(element, RELATION_GRANTED_TO);
const authorOf = (event: StoredTimelineEvent): string | undefined => (event[buildRefRelationKey(RELATION_CREATED_BY)] ?? [])[0];

interface ContainerVisibilityScope {
  resolved: Record<string, AnyStoreElement>;
  /** The element is readable by every reader of the container: same markings at most, no authorized members, shared with the same organizations at least */
  isElementAsVisibleAsContainer: (element: AnyStoreElement) => boolean;
  /** The event and the element it references are readable by every reader of the container */
  isEventAsVisibleAsContainer: (event: StoredTimelineEvent) => boolean;
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
): Promise<ContainerVisibilityScope> => {
  const containerId = container.internal_id;
  const containerGranted = grantedOf(container);
  const elementIds = uniq(events.map((e) => e.element_id).filter((id): id is string => !!id && id !== containerId));
  const authorIds = uniq(events.filter((e) => e.event_source === 'manual').map(authorOf).filter((id): id is string => !!id));
  // Base data carries the authorized members; markings and organization sharing come with every read as security doc values
  const resolved = elementIds.length + authorIds.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, [...elementIds, ...authorIds], { toMap: true, baseData: true }) as unknown as Record<string, AnyStoreElement>
    : {};
  const markingsMap = await getEntitiesMapFromCache<StoreMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  const isMarkingCoveredByContainer = buildContainerMarkingCoverage(markingsOf(container), markingsMap);
  const isElementAsVisibleAsContainer = (element: AnyStoreElement) => {
    if ((element.restricted_members ?? []).length > 0) return false;
    if (!markingsOf(element).every(isMarkingCoveredByContainer)) return false;
    // Organization sharing (platform access rules): an object shared with no organization is readable inside the platform
    // organization only, a shared object inside the platform organization and in each organization it is shared with.
    // An element is therefore readable by every reader of the container when it is shared with at least the
    // organizations of the container; an unshared container is read inside the platform organization only.
    const granted = new Set(grantedOf(element));
    return containerGranted.every((id) => granted.has(id));
  };
  const isEventAsVisibleAsContainer = (event: StoredTimelineEvent) => {
    if (!markingsOf(event).every(isMarkingCoveredByContainer)) return false;
    if (!event.element_id || event.element_id === containerId) return true;
    // The access scope of a deleted element is unknown while the event still speaks about it: never as visible as the container
    const element = resolved[event.element_id];
    return !!element && isElementAsVisibleAsContainer(element);
  };
  return { resolved, isElementAsVisibleAsContainer, isEventAsVisibleAsContainer };
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
  const annotated = events.filter((e) => e.event_source === 'derived' && (e.analyst_fields ?? []).length > 0 && e.element_id
    // Only annotations of events whose identity is portable travel: history-based events depend on local history ids
    && e.internal_id === computeDerivedEventId(containerId, e.rule_id ?? '', e.element_id, e.kind)
    && isEventAsVisibleAsContainer(e));
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
    .map((event) => {
      const fields = event.analyst_fields ?? [];
      return {
        rule_id: timelineRuleFamily(event.rule_id ?? ''),
        kind: event.kind,
        element_ref: portableElementRef(event.element_id) as string,
        pinned: fields.includes('pinned') ? event.pinned : undefined,
        hidden: fields.includes('hidden') ? event.hidden : undefined,
        annotation: fields.includes('annotation') ? (event.annotation ?? undefined) : undefined,
        ordering_hint: fields.includes('ordering_hint') ? (event.ordering_hint ?? undefined) : undefined,
      };
    });
  return { events: exchangeEvents, annotations: exchangeAnnotations };
};

export interface TimelineContributionsResult {
  anchors: TimelineAnchors;
  changedAnchors: TimelineAnchorKey[];
}

/**
 * Recompute the anchors and the STIX exchange of a container from its stored events and write them
 * on the container through the side channel: no stream event, no history, no modification date change.
 * Both are exposed to every reader of the container (attribute, filters, orderings, notifications), so an event
 * a reader may not see never moves an anchor.
 */
export const refreshTimelineContributions = async (
  context: AuthContext,
  container: AnyStoreElement,
  opts: { events?: StoredTimelineEvent[]; notifyAnchors?: boolean } = {},
): Promise<TimelineContributionsResult> => {
  const events = opts.events ?? await loadStoredTimelineEvents(context, container.internal_id);
  const isClosed = await isContainerClosed(context, container);
  const previousAnchors = container[ATTRIBUTE_TIMELINE_ANCHORS] as Partial<TimelineAnchors> | undefined;
  const scope = await resolveContainerVisibilityScope(context, container, events);
  const anchors = computeTimelineAnchors(events.filter(scope.isEventAsVisibleAsContainer).map((e) => ({
    lane: e.lane,
    kind: e.kind,
    rule_id: e.rule_id,
    event_time: e.event_time,
    hidden: e.hidden,
  })), { isClosed, computedAt: now(), previous: previousAnchors });
  const exchange = await buildExchange(context, container, events, scope);
  const changedAnchors = diffTimelineAnchors(previousAnchors, anchors);
  await elUpdate(context, container._index, container.internal_id, {
    doc: { [ATTRIBUTE_TIMELINE_ANCHORS]: anchors, [ATTRIBUTE_TIMELINE_EXCHANGE]: exchange },
  });
  // The first computation (backfill) is not a change an analyst wants to be notified about
  const hadAnchors = !!previousAnchors?.computed_at;
  if (changedAnchors.length > 0) {
    await publishTimelineUpdate({ container_id: container.internal_id, update_type: 'anchors', changed_event_ids: [], anchors });
    if (hadAnchors && opts.notifyAnchors !== false) {
      await notifyTimelineAnchorsChanged(context, container.internal_id, changedAnchors, anchors)
        .catch((error) => logApp.error('[TIMELINE] Unable to notify anchor changes', { cause: error, containerId: container.internal_id }));
    }
  }
  return { anchors, changedAnchors };
};
// endregion

// region regeneration
const LANE_PRIORITY: Record<string, number> = { adversary: 0, detection: 1, response: 2, evidence: 3, knowledge: 4, custom: 5 };

const pendingAnnotationsMap = (settings: BasicStoreEntityTimelineSettings | undefined) => {
  return new Map<string, TimelinePendingAnnotation>((settings?.pending_annotations ?? []).map((a) => [a.event_id, a]));
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

const regenerateLocked = async (context: AuthContext, container: AnyStoreElement): Promise<TimelineRegenerationResult> => {
  const start = Date.now();
  const containerId = container.internal_id;
  const { input, truncated: inputTruncated } = await loadTimelineDerivationInput(context, container);
  let derived = deriveTimelineEvents(input, getTimelineRules(), (ruleId, error) => {
    logApp.error('[TIMELINE] Derivation rule failure', { cause: error, ruleId, containerId });
  });
  let truncated = inputTruncated;
  if (derived.length > TIMELINE_MAX_EVENTS) {
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
  // Build the derived documents, deduplicated on their deterministic id
  const docsById = new Map<string, ReturnType<typeof buildTimelineEventDoc>>();
  derived.forEach((event) => {
    const internalId = computeDerivedEventId(containerId, event.rule_id, derivedEventKey(event), event.kind);
    if (docsById.has(internalId)) return;
    const existing = storedById.get(internalId);
    const analyst = applyAnalystFields(
      { pinned: false, hidden: false, annotation: null, ordering_hint: event.ordering_hint ?? null },
      existing,
      pending.get(internalId),
    );
    docsById.set(internalId, buildTimelineEventDoc({
      internal_id: internalId,
      container_id: containerId,
      name: event.name,
      description: event.description,
      event_time: event.event_time,
      event_end_time: event.event_end_time,
      time_precision: event.time_precision,
      lane: event.lane,
      kind: event.kind,
      event_source: 'derived',
      rule_id: event.rule_id,
      element_id: event.element_id,
      element_type: event.element_type,
      confidence: event.confidence,
      external_id: null,
      markings: [...event.markings, ...access.markings],
      created_by_id: event.created_by_id,
      creator_ids: event.creator_ids ?? [],
      restricted_members: access.restricted_members,
      source_state: event.source_state ?? null,
      ...analyst,
    }, existing));
  });
  // Manual events only follow the access of the container
  stored.filter((e) => e.event_source === 'manual').forEach((event) => {
    const markings = uniq([...markingsOf(event), ...access.markings]);
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
  const staleIds = stored.filter((e) => e.event_source === 'derived' && !docsById.has(e.internal_id)).map((e) => e.internal_id);
  await deleteTimelineDocuments(staleIds);
  // Consume the imported annotations that found their event and record the generation
  const remaining = (settings?.pending_annotations ?? []).filter((a) => !docsById.has(a.event_id));
  await upsertTimelineSettings(context, container, { pending_annotations: remaining, derivation_truncated: truncated, generated_at: now() }, settings ?? null);
  if (createdCount > 0) {
    addTimelineDerivedEventCount(createdCount);
  }
  const finalEvents = docs as unknown as StoredTimelineEvent[];
  const { anchors } = await refreshTimelineContributions(context, container, { events: finalEvents });
  const changedIds = [...changedDocs.map((d) => d.internal_id), ...staleIds];
  if (changedIds.length > 0) {
    await publishTimelineUpdate({ container_id: containerId, update_type: 'derived', changed_event_ids: changedIds.slice(0, 500), anchors });
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
 * concurrent call generated the timeline while this one was waiting for the lock.
 */
export const regenerateContainerTimeline = async (
  context: AuthContext,
  containerId: string,
  opts: { wait?: boolean; skipIfGenerated?: boolean } = {},
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
    if (opts.skipIfGenerated) {
      const current = await internalLoadById<AnyStoreElement>(context, SYSTEM_USER, container.internal_id, { type: TIMELINE_CONTAINER_TYPES });
      if (!current) return null;
      if (current[ATTRIBUTE_TIMELINE_ANCHORS]?.computed_at) return null;
      return await regenerateLocked(context, current);
    }
    return await regenerateLocked(context, container);
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
