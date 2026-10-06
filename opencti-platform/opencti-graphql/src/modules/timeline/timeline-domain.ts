import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, StoreMarkingDefinition } from '../../types/store';
import { AccessOperation, executionContext, isBypassUser, isUserHasCapability, KNOWLEDGE_KNUPDATE, SYSTEM_USER, validateUserAccessOperation } from '../../utils/access';
import { controlCreateInputWithUserConfidence, controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { fullEntitiesList, internalFindByIds, internalLoadById, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { elAggregationCount, elCount, elIndexElements, elLoadById } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { getDraftContext } from '../../utils/draftContext';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import type {
  QueryContainerTimelineArgs,
  QueryContainerTimelineBoundsArgs,
  QueryContainerTimelineExportArgs,
  QueryContainerTimelineExportFileArgs,
  TimelineBounds,
  TimelineEventAddInput,
  TimelineEventEditInput,
  TimelineEventKind,
  TimelineRuleDefinition,
  TimelineSettings,
  TimelineSettingsInput,
  TimelineSummary,
} from '../../generated/graphql';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { getEntitiesListFromCache, getEntitiesMapFromCache, getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import { getExportFilter } from '../../utils/getExportFilter';
import { cleanMarkings } from '../../utils/markingDefinition-utils';
import { findById as findMarkingDefinitionById } from '../../domain/markingDefinition';
import { checkUserCanShareMarkings } from '../user/user-domain';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { isStixDomainObjectIdentity } from '../../schema/stixDomainObject';
import { now } from '../../utils/format';
import {
  ATTRIBUTE_TIMELINE_ANCHORS,
  ENTITY_TYPE_TIMELINE_EVENT,
  type StixTimelineExtensionEvent,
  TIMELINE_CONTAINER_TYPES,
  TIMELINE_DEFAULT_SETTINGS,
  TIMELINE_KINDS,
  TIMELINE_MILESTONE_KINDS,
  type TimelineAnalystField,
  type TimelineAnchors,
  type TimelinePendingAnnotation,
} from './timeline-types';
import {
  buildTimelineEventDoc,
  computeDerivedEventId,
  computeManualEventId,
  containerAccessFields,
  createConcurrencyLimiter,
  deleteTimelineDocuments,
  filterAccessibleEvents,
  filterEventsSharedAsContainer,
  findEventsReadableThroughRecords,
  getTimelineRules,
  isTimelineElementChangeWidening,
  loadStoredTimelineEvents,
  loadTimelineSettings,
  markingsOf,
  publishTimelineUpdate,
  recordedTimelineReference,
  referencedElementIds,
  refreshTimelineContributions,
  regenerateContainerTimeline,
  type StoredTimelineEvent,
  type StoredTimelineSettings,
  TIMELINE_MAX_EVENTS,
  TIMELINE_MAX_MANUAL_EVENTS,
  TIMELINE_MAX_STORED_EVENTS,
  timelineElementAccessOf,
  timelineEventMaxConfidence,
  type TimelineReadableEvent,
  type TimelineRegenerationResult,
  toRemovedTimelineEvents,
  type TimelineRemovedEvent,
  type TimelineUpdatePayload,
  upsertTimelineSettings,
  withTimelineLock,
} from './timeline-engine';
import { renderTimelineCsv, renderTimelineHtml, renderTimelineSvg, type TimelineExportEvent } from './timeline-export';
import { computeTimelineAnchors } from './timeline-anchors';
import { isContainerClosed } from './timeline-loader';
import { notifyTimelineMilestoneAdded, notifyTimelineMilestonesAdded } from './timeline-notification';
import { type SanitizedTimelineExtension, sanitizeTimelineExtension } from './timeline-extension';
import { addTimelineExportCount, addTimelineManualEventCount, addTimelineViewCount } from '../../manager/telemetryManager';
import conf, { logApp } from '../../config/conf';
import { enqueueTimelineRegeneration } from './timeline-queue';

type AnyStoreElement = BasicStoreBase & Record<string, any>;

const TIMELINE_DEFAULT_PAGE = 200;
const TIMELINE_MAX_PAGE = 1000;

// region access
export const loadTimelineContainer = async (context: AuthContext, user: AuthUser, containerId: string): Promise<AnyStoreElement> => {
  const container = await internalLoadById<AnyStoreElement>(context, user, containerId, { type: TIMELINE_CONTAINER_TYPES });
  if (!container) {
    throw FunctionalError('Timeline container cannot be found', { id: containerId });
  }
  return container;
};

/** A user can contribute to a timeline when he can update the container itself. */
export const canEditTimeline = (user: AuthUser, container: AnyStoreElement): boolean => {
  return isUserHasCapability(user, KNOWLEDGE_KNUPDATE)
    && validateUserAccessOperation(user, container, AccessOperation.EDIT)
    && controlUserConfidenceAgainstElement(user, container as unknown as BasicStoreEntity, true);
};

/** Timeline contributions are written on the live knowledge only, never inside a draft. */
export const canContributeToTimeline = (context: AuthContext, user: AuthUser, container: AnyStoreElement | null | undefined): boolean => {
  return !!container && canEditTimeline(user, container) && !getDraftContext(context, user);
};

const loadEditableTimelineContainer = async (context: AuthContext, user: AuthUser, containerId: string) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Timeline contributions are not available in a draft');
  }
  const container = await loadTimelineContainer(context, user, containerId);
  if (!canEditTimeline(user, container)) {
    throw ForbiddenAccess();
  }
  return container;
};

const validateMarkings = (user: AuthUser, markingIds: string[]) => {
  if (isBypassUser(user)) return;
  const allowed = new Set(user.allowed_marking.map((m) => m.internal_id));
  const forbidden = markingIds.filter((id) => !allowed.has(id));
  if (forbidden.length > 0) {
    throw ForbiddenAccess('You cannot apply markings you do not have access to');
  }
};

const resolveElement = async (context: AuthContext, user: AuthUser, elementId: string | null | undefined) => {
  if (!elementId) return null;
  const element = await internalLoadById<AnyStoreElement>(context, user, elementId);
  if (!element) {
    throw FunctionalError('Timeline element cannot be found', { id: elementId });
  }
  return element;
};

const hasPlatformOrganization = async (context: AuthContext): Promise<boolean> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return !!settings.platform_organization;
};

// The event keeps the markings of every element it pointed to, but its other readers are those of its current element:
// it is never pointed to an element, or to none, that users its current element is hidden from can read
const controlTimelineElementChange = async (
  context: AuthContext,
  container: AnyStoreElement,
  event: StoredTimelineEvent,
  next: AnyStoreElement | null,
) => {
  const previousElementId = event.element_id;
  if (!previousElementId || previousElementId === next?.internal_id) return;
  // A deleted element is read from the access recorded on the event
  const previous = await internalLoadById<AnyStoreElement>(context, SYSTEM_USER, previousElementId) ?? recordedTimelineReference(event, previousElementId);
  if (isTimelineElementChangeWidening(container, previous, next, await hasPlatformOrganization(context))) {
    throw FunctionalError('This event cannot point to an element, or to none, that users its current element is hidden from can read: add a new event instead', { id: previousElementId });
  }
};

const resolveAuthor = async (context: AuthContext, user: AuthUser, authorId: string | null | undefined) => {
  if (!authorId) return null;
  const author = await internalLoadById<AnyStoreElement>(context, user, authorId, { type: ENTITY_TYPE_IDENTITY });
  if (!author) {
    throw FunctionalError('Timeline event author cannot be found', { id: authorId });
  }
  return author;
};

const resolveMarkingIds = async (context: AuthContext, markingIds: string[]) => {
  if (markingIds.length === 0) return [];
  const markings = await getEntitiesMapFromCache<AnyStoreElement>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION);
  return markingIds.map((id) => {
    const marking = markings.get(id);
    if (!marking) throw FunctionalError('Marking definition cannot be found', { id });
    return marking.internal_id;
  });
};

const validateWindow = (eventTime: string, eventEndTime: string | null | undefined) => {
  const start = new Date(eventTime).getTime();
  if (Number.isNaN(start)) throw FunctionalError('Invalid event time', { event_time: eventTime });
  if (eventEndTime) {
    const end = new Date(eventEndTime).getTime();
    if (Number.isNaN(end) || end <= start) {
      throw FunctionalError('The end time of an event must be after its start time', { event_time: eventTime, event_end_time: eventEndTime });
    }
  }
};

// The external id is the idempotency key of a manual event: an empty one would match nothing and add the event again on every call
const validateExternalId = (externalId: string | null | undefined) => {
  if (typeof externalId === 'string' && externalId.trim().length === 0) throw FunctionalError('The external id of a timeline event cannot be empty');
};
// endregion

// region reads
// First openings build their timeline in the read path, within a limit per platform node; beyond the readers waiting for
// a slot, the container goes to the timeline manager, whose batches and concurrency bound the work
const TIMELINE_FIRST_USE_CONCURRENCY = conf.get('timeline_manager:first_use_concurrency') ?? 2;
const TIMELINE_FIRST_USE_MAX_WAITING = 50;
// The events of an imported extension are bounded on their own, never by the cap of manual events of the case: that cap
// applies to the new milestones only, once the known events (always updated) are told apart
const TIMELINE_IMPORT_MAX_EVENTS = Math.max(10000, TIMELINE_MAX_MANUAL_EVENTS);
const runFirstUseGeneration = createConcurrencyLimiter(TIMELINE_FIRST_USE_CONCURRENCY, TIMELINE_FIRST_USE_MAX_WAITING);
const firstUseGenerations = new Map<string, Promise<boolean>>();

const ensureTimelineGenerated = async (context: AuthContext, user: AuthUser, container: AnyStoreElement) => {
  if (container[ATTRIBUTE_TIMELINE_ANCHORS]?.computed_at) return container;
  // First opening of a container that was never processed: build its timeline now, always on the
  // live knowledge (never inside the draft the reader may be working in). Concurrent first reads
  // (summary and events are resolved in parallel) share the generation in flight instead of
  // reading a partial timeline, and do not run it a second time (another node waits for its lock).
  const containerId = container.internal_id;
  const generationContext = executionContext('timeline_generation');
  let generation = firstUseGenerations.get(containerId);
  if (!generation) {
    generation = runFirstUseGeneration(() => regenerateContainerTimeline(generationContext, containerId, { wait: true, skipIfGenerated: true }))
      .then((result) => result.started)
      .finally(() => firstUseGenerations.delete(containerId));
    firstUseGenerations.set(containerId, generation);
  }
  if (!(await generation)) {
    await enqueueTimelineRegeneration([containerId], 0);
    throw FunctionalError('The timeline of this case is being built, open it again in a moment', { id: containerId });
  }
  // Read again as the reader: the wait for a generation slot can be long, and a container deleted or no longer accessible
  // meanwhile is not found, as it would be on a new request
  return loadTimelineContainer(context, user, containerId);
};

interface TimelineFilterArgs {
  from?: string | null;
  to?: string | null;
  lanes?: string[] | null;
  kinds?: string[] | null;
  sources?: string[] | null;
  markings?: string[] | null;
  search?: string | null;
  includeHidden?: boolean | null;
  pinnedOnly?: boolean | null;
}

export const buildTimelineFilters = (containerId: string, args: TimelineFilterArgs) => {
  const filters: any[] = [{ key: ['container_id'], values: [containerId] }];
  const filterGroups: any[] = [];
  if (args.lanes && args.lanes.length > 0) filters.push({ key: ['lane'], values: args.lanes });
  if (args.kinds && args.kinds.length > 0) filters.push({ key: ['kind'], values: args.kinds });
  if (args.sources && args.sources.length > 0) filters.push({ key: ['event_source'], values: args.sources });
  if (args.markings && args.markings.length > 0) filters.push({ key: ['objectMarking'], values: args.markings });
  if (!args.includeHidden) filters.push({ key: ['hidden'], values: ['true'], operator: FilterOperator.NotEq });
  if (args.pinnedOnly) filters.push({ key: ['pinned'], values: ['true'] });
  if (args.to) filters.push({ key: ['event_time'], values: [args.to], operator: FilterOperator.Lte });
  if (args.from) {
    // Point events after the start of the window, or windows still open at the start of the window: ending after it, or
    // without a known end (the `to` bound above keeps those started before the end of the window)
    filterGroups.push({
      mode: FilterMode.Or,
      filters: [
        { key: ['event_time'], values: [args.from], operator: FilterOperator.Gte },
        { key: ['event_end_time'], values: [args.from], operator: FilterOperator.Gte },
        { key: ['open_ended'], values: ['true'] },
      ],
      filterGroups: [],
    });
  }
  if (args.search && args.search.trim().length > 0) {
    filters.push({ key: ['name', 'description', 'annotation'], values: [args.search.trim()], operator: FilterOperator.Search, mode: FilterMode.Or });
  }
  return { mode: FilterMode.And, filters, filterGroups };
};

/** Latest instant of a timeline: the greatest start time or the greatest end time, whichever is later. */
export const latestTimelineTime = (latestStart: string | null | undefined, latestEnd: string | null | undefined): string | null => {
  if (!latestStart) return latestEnd ?? null;
  if (!latestEnd) return latestStart;
  return new Date(latestEnd).getTime() > new Date(latestStart).getTime() ? latestEnd : latestStart;
};

interface InaccessibleTimelineReferences {
  elementIds: string[];
  // Events carrying data of a source the user cannot access: sources are not indexed, these events are left out by id
  eventIds: string[];
}

/** Elements and sources referenced by the events of a container that the user cannot access (or that no longer exist), read from every event. */
const computeInaccessibleReferences = async (context: AuthContext, user: AuthUser, containerId: string): Promise<InaccessibleTimelineReferences> => {
  const references = await fullEntitiesList<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: buildTimelineFilters(containerId, { includeHidden: true }) as any,
    baseData: true,
    baseFields: ['element_id', 'element_type', 'element_access', buildRefRelationKey(RELATION_OBJECT_MARKING)],
  } as any);
  const referencedIds = Array.from(new Set(references.flatMap((event) => referencedElementIds(event, containerId))));
  if (referencedIds.length === 0) return { elementIds: [], eventIds: [] };
  const accessible = await internalFindByIds(context, user, referencedIds, { toMap: true, baseData: true }) as unknown as Record<string, AnyStoreElement>;
  const isInaccessible = (id: string) => !accessible[id];
  // An event about an element or a source deleted since is read from the access recorded on it: it is left out, or
  // kept, by itself, and so are the other events of a deleted element
  const unresolved = references.filter((event) => referencedElementIds(event, containerId).some(isInaccessible));
  const readableThroughRecords = unresolved.length > 0
    ? await findEventsReadableThroughRecords(context, user, containerId, unresolved, accessible)
    : new Set<string>();
  const recordedElementIds = new Set(unresolved.filter((event) => readableThroughRecords.has(event.internal_id)).map((event) => event.element_id));
  const elementIds = Array.from(new Set(references.map((event) => event.element_id).filter((id): id is string => !!id && id !== containerId)));
  return {
    elementIds: elementIds.filter((id) => isInaccessible(id) && !recordedElementIds.has(id)),
    eventIds: unresolved.filter((event) => !readableThroughRecords.has(event.internal_id)).map((event) => event.internal_id),
  };
};

// The list, the bounds and the summary of one request share the scan of the events, which is bounded by the cap of the
// case: the sources of an event are not indexed (they would take mapping fields), so their access is read from the events.
// The context lives as long as its request, so a change of access is seen by the next request.
const inaccessibleReferencesByRequest = new WeakMap<AuthContext, Map<string, Promise<InaccessibleTimelineReferences>>>();
const findInaccessibleReferences = (context: AuthContext, user: AuthUser, containerId: string): Promise<InaccessibleTimelineReferences> => {
  let requestCache = inaccessibleReferencesByRequest.get(context);
  if (!requestCache) {
    requestCache = new Map();
    inaccessibleReferencesByRequest.set(context, requestCache);
  }
  const key = `${user.id}:${containerId}`;
  let references = requestCache.get(key);
  if (!references) {
    references = computeInaccessibleReferences(context, user, containerId);
    // A failed scan is not kept: a retry in the same request computes it again
    references.catch(() => requestCache?.delete(key));
    requestCache.set(key, references);
  }
  return references;
};

// Filters with these exclusions are built by the module alone (users give values, never keys): they are not checked
// against the filterable attributes, `internal_id` not being one
const excludeInaccessible = (filters: ReturnType<typeof buildTimelineFilters>, hidden: InaccessibleTimelineReferences) => {
  const exclusions = [
    ...(hidden.elementIds.length > 0 ? [{ key: ['element_id'], values: hidden.elementIds, operator: FilterOperator.NotEq, mode: FilterMode.And }] : []),
    ...(hidden.eventIds.length > 0 ? [{ key: ['internal_id'], values: hidden.eventIds, operator: FilterOperator.NotEq, mode: FilterMode.And }] : []),
  ];
  if (exclusions.length === 0) return filters;
  return { ...filters, filters: [...filters.filters, ...exclusions] };
};

/** Timeline filters restricted to the events of the elements and sources the user can access, before any pagination or count. */
const buildAccessibleTimelineFilters = async (context: AuthContext, user: AuthUser, containerId: string, args: TimelineFilterArgs) => {
  return excludeInaccessible(buildTimelineFilters(containerId, args), await findInaccessibleReferences(context, user, containerId));
};

export const findContainerTimeline = async (context: AuthContext, user: AuthUser, args: QueryContainerTimelineArgs) => {
  const container = await ensureTimelineGenerated(context, user, await loadTimelineContainer(context, user, args.id));
  const first = Math.min(args.first ?? TIMELINE_DEFAULT_PAGE, TIMELINE_MAX_PAGE);
  const connection = await pageEntitiesConnection<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: await buildAccessibleTimelineFilters(context, user, container.internal_id, args) as any,
    noFiltersChecking: true,
    first,
    after: args.after,
    orderBy: ['event_time', 'ordering_hint'],
    orderMode: args.orderMode ?? OrderingMode.Asc,
  });
  const { items } = await filterAccessibleEvents(context, user, container.internal_id, connection.edges, (edge) => edge.node);
  return { ...connection, edges: items };
};

/** Earliest start and latest instant (start or end) of the events matching already accessible filters. */
const computeTimelineBounds = async (context: AuthContext, user: AuthUser, filters: ReturnType<typeof buildTimelineFilters>): Promise<TimelineBounds> => {
  const windowFilters = { ...filters, filters: [...filters.filters, { key: ['event_end_time'], values: [], operator: FilterOperator.NotNil }] };
  const firstOf = (pageFilters: typeof filters, orderBy: string, orderMode: OrderingMode) => pageEntitiesConnection<StoredTimelineEvent>(
    context,
    user,
    [ENTITY_TYPE_TIMELINE_EVENT],
    { filters: pageFilters as any, noFiltersChecking: true, first: 1, orderBy, orderMode },
  );
  const [firstEvents, lastEvents, lastEndingEvents] = await Promise.all([
    firstOf(filters, 'event_time', OrderingMode.Asc),
    firstOf(filters, 'event_time', OrderingMode.Desc),
    firstOf(windowFilters, 'event_end_time', OrderingMode.Desc),
  ]);
  return {
    first_event_time: firstEvents.edges[0]?.node.event_time ?? null,
    last_event_time: latestTimelineTime(lastEvents.edges[0]?.node.event_time, lastEndingEvents.edges[0]?.node.event_end_time),
  };
};

export const findContainerTimelineBounds = async (context: AuthContext, user: AuthUser, args: QueryContainerTimelineBoundsArgs): Promise<TimelineBounds> => {
  const container = await ensureTimelineGenerated(context, user, await loadTimelineContainer(context, user, args.id));
  return computeTimelineBounds(context, user, await buildAccessibleTimelineFilters(context, user, container.internal_id, args));
};

export const findTimelineEvent = async (context: AuthContext, user: AuthUser, id: string) => {
  const event = await elLoadById<StoredTimelineEvent>(context, user, id, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent;
  if (!event) return null;
  // The event is only visible with its container and its element
  const container = await internalLoadById(context, user, event.container_id, { type: TIMELINE_CONTAINER_TYPES });
  if (!container) return null;
  const { items } = await filterAccessibleEvents(context, user, event.container_id, [event], (e) => e);
  return items[0] ?? null;
};

/** An event can only be changed by a user who can read it (event and element), edit its container and reach its confidence. */
const loadEditableTimelineEvent = async (context: AuthContext, user: AuthUser, eventId: string) => {
  const event = await findTimelineEvent(context, user, eventId);
  if (!event) {
    throw FunctionalError('Timeline event cannot be found', { id: eventId });
  }
  const container = await loadEditableTimelineContainer(context, user, event.container_id);
  controlUserConfidenceAgainstElement(user, event as unknown as BasicStoreEntity);
  return { event, container };
};

/** Confidence written on an event: capped by the effective max confidence of the user, like any entity input; none stays none. */
const cappedTimelineConfidence = (user: AuthUser, confidence: number | null | undefined): number | null => {
  if (confidence === null || confidence === undefined) return null;
  return controlCreateInputWithUserConfidence(user, { id: '', entity_type: ENTITY_TYPE_TIMELINE_EVENT, confidence }, ENTITY_TYPE_TIMELINE_EVENT).confidenceLevelToApply;
};

/** The higher of two confidence levels; none counts as no level at all. */
export const strongerTimelineConfidence = (stored: number | null | undefined, incoming: number | null): number | null => {
  if (stored === null || stored === undefined) return incoming;
  return incoming === null ? stored : Math.max(stored, incoming);
};

export const findTimelineAnchors = async (context: AuthContext, user: AuthUser, containerId: string): Promise<TimelineAnchors | null> => {
  const container = await ensureTimelineGenerated(context, user, await loadTimelineContainer(context, user, containerId));
  return container?.[ATTRIBUTE_TIMELINE_ANCHORS] ?? null;
};

const settingsWithDefaults = (containerId: string, settings: StoredTimelineSettings | undefined | null): TimelineSettings => ({
  id: settings?.internal_id ?? `timeline-settings-${containerId}`,
  internal_id: settings?.internal_id ?? `timeline-settings-${containerId}`,
  standard_id: settings?.standard_id ?? `timeline-settings--${containerId}`,
  entity_type: 'Timeline-Settings',
  parent_types: settings?.parent_types ?? [],
  representative: { main: 'Timeline settings', secondary: containerId },
  container_id: containerId,
  enabled_lanes: settings?.enabled_lanes?.length ? settings.enabled_lanes : TIMELINE_DEFAULT_SETTINGS.enabled_lanes,
  default_grouping: settings?.default_grouping ?? TIMELINE_DEFAULT_SETTINGS.default_grouping,
  default_zoom_window: settings?.default_zoom_window ?? TIMELINE_DEFAULT_SETTINGS.default_zoom_window,
  hidden_kinds: settings?.hidden_kinds ?? TIMELINE_DEFAULT_SETTINGS.hidden_kinds,
} as unknown as TimelineSettings);

export const findContainerTimelineSummary = async (
  context: AuthContext,
  user: AuthUser,
  containerId: string,
  restriction: Pick<TimelineFilterArgs, 'lanes' | 'kinds'> = {},
): Promise<TimelineSummary> => {
  const loaded = await storeLoadById<AnyStoreElement>(context, user, containerId, TIMELINE_CONTAINER_TYPES);
  if (!loaded) {
    throw FunctionalError('Timeline container cannot be found', { id: containerId });
  }
  const container = await ensureTimelineGenerated(context, user, loaded);
  const baseArgs = { types: [ENTITY_TYPE_TIMELINE_EVENT], noFiltersChecking: true };
  // Same visibility as the list: the events of elements or sources the user cannot access are not counted
  const hidden = await findInaccessibleReferences(context, user, container.internal_id);
  // Lanes and kinds narrow the counts and bounds, so that a view showing only some of them can name its own span
  const scope = { lanes: restriction.lanes, kinds: restriction.kinds };
  const visibleFilters = excludeInaccessible(buildTimelineFilters(container.internal_id, scope), hidden);
  const allFilters = excludeInaccessible(buildTimelineFilters(container.internal_id, { ...scope, includeHidden: true }), hidden);
  const count = (filters: any) => elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...baseArgs, filters });
  const withFilter = (extra: any) => ({ ...allFilters, filters: [...allFilters.filters, extra] });
  const [total, manualCount, pinnedCount, hiddenCount, lanes, kinds, bounds, settings] = await Promise.all([
    count(visibleFilters),
    count({ ...visibleFilters, filters: [...visibleFilters.filters, { key: ['event_source'], values: ['manual'] }] }),
    count({ ...visibleFilters, filters: [...visibleFilters.filters, { key: ['pinned'], values: ['true'] }] }),
    count(withFilter({ key: ['hidden'], values: ['true'] })),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...baseArgs, filters: visibleFilters as any, field: 'lane', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...baseArgs, filters: visibleFilters as any, field: 'kind', normalizeLabel: false }),
    computeTimelineBounds(context, user, visibleFilters),
    loadTimelineSettings(context, container.internal_id),
  ]);
  return {
    container_id: container.internal_id,
    total,
    manual_count: manualCount,
    pinned_count: pinnedCount,
    hidden_count: hiddenCount,
    first_event_time: bounds.first_event_time,
    last_event_time: bounds.last_event_time,
    lanes: lanes.map((l) => ({ lane: l.label, count: l.count })),
    kinds: kinds.map((k) => ({ kind: k.label, count: k.count })),
    anchors: container[ATTRIBUTE_TIMELINE_ANCHORS] ?? null,
    settings: settingsWithDefaults(container.internal_id, settings),
    can_edit: canContributeToTimeline(context, user, container),
    truncated: settings?.derivation_truncated ?? false,
    generated_at: settings?.generated_at ?? null,
  } as unknown as TimelineSummary;
};

/** Count one opening of the Timeline tab (the summary is also read by overview strips and widgets). */
export const recordTimelineView = async (context: AuthContext, user: AuthUser, containerId: string): Promise<boolean> => {
  await loadTimelineContainer(context, user, containerId);
  addTimelineViewCount();
  return true;
};
export const listTimelineRules = (): TimelineRuleDefinition[] => {
  return getTimelineRules().map((rule) => ({
    id: rule.id,
    label: rule.label,
    kinds: rule.kinds as unknown as TimelineEventKind[],
    available: !rule.isAvailable || rule.isAvailable(),
  }));
};
// endregion

// region exports
interface TimelineExportArgs extends TimelineFilterArgs {
  id: string;
  format: QueryContainerTimelineExportArgs['format'];
  labels?: QueryContainerTimelineExportArgs['labels'];
  contentMaxMarkings?: string[] | null;
}

interface TimelineExportSnapshot {
  container: AnyStoreElement;
  items: StoredTimelineEvent[];
  elements: Record<string, AnyStoreElement>;
  // Computed from the exported events only: an event left out by the ceiling or the filters never moves an anchor of the file
  anchors: TimelineAnchors;
}

// An export is built in memory and answered at once: the text of its events is bounded (in characters, about 10 MB),
// a larger one is narrowed by the user with the filters or the window
const TIMELINE_EXPORT_MAX_TEXT_LENGTH = 10_000_000;
const TIMELINE_EXPORT_PAGE_SIZE = 500;
export const TIMELINE_EXPORT_TOO_LARGE = 'TIMELINE_EXPORT_TOO_LARGE';

/** Collects the pages of an export until the text of its events passes the bound, then refuses the next ones. */
export const collectTimelineExportPages = (maxTextLength = TIMELINE_EXPORT_MAX_TEXT_LENGTH) => {
  const events: StoredTimelineEvent[] = [];
  let textLength = 0;
  const textOf = (event: StoredTimelineEvent): number => (event.name?.length ?? 0) + (event.description?.length ?? 0) + (event.annotation?.length ?? 0);
  return {
    events,
    exceeded: () => textLength > maxTextLength,
    collect: (page: StoredTimelineEvent[]): boolean => {
      textLength += page.reduce((length, event) => length + textOf(event), 0);
      if (textLength > maxTextLength) return false;
      events.push(...page);
      return true;
    },
  };
};

/**
 * The events an export contains: the events the user can see, within the content ceiling he selected and his max
 * shareable markings (same rule as every export of the platform). The ceiling also applies to the element and the sources
 * of each event, which can be marked more strictly than the event itself until the next regeneration copies their markings.
 */
const loadExportedTimelineEvents = async (
  context: AuthContext,
  user: AuthUser,
  args: TimelineExportArgs,
  opts: { storedInContainer?: boolean } = {},
): Promise<TimelineExportSnapshot> => {
  const container = await ensureTimelineGenerated(context, user, await loadTimelineContainer(context, user, args.id));
  const contentMaxMarkings = args.contentMaxMarkings ?? [];
  if (contentMaxMarkings.length > 0) {
    const markingLevels = await Promise.all(contentMaxMarkings.map((markingId) => findMarkingDefinitionById(context, user, markingId)));
    if (markingLevels.some((marking) => !marking)) {
      throw FunctionalError('Marking definition cannot be found', { ids: contentMaxMarkings });
    }
    await checkUserCanShareMarkings(context, user, markingLevels as unknown as StoreMarkingDefinition[]);
  }
  const markingList = await getEntitiesListFromCache<StoreMarkingDefinition>(context, user, ENTITY_TYPE_MARKING_DEFINITION);
  const { markingFilter } = await getExportFilter(user, { markingList, contentMaxMarkings, objectIdsList: [] });
  const baseFilters = buildTimelineFilters(container.internal_id, args);
  const ceilingFilters = (markingFilter.filters as { key: string | string[]; values?: string[] }[])
    .map((filter) => ({ ...filter, key: Array.isArray(filter.key) ? filter.key : [filter.key] }));
  const markingsAboveCeiling = new Set(ceilingFilters.flatMap((filter) => filter.values ?? []));
  // Read page by page, so that an export over its text bound stops reading before holding all of it
  const pages = collectTimelineExportPages();
  await fullEntitiesList<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: { ...baseFilters, filters: [...baseFilters.filters, ...ceilingFilters] } as any,
    orderBy: ['event_time', 'ordering_hint'],
    orderMode: OrderingMode.Asc,
    first: TIMELINE_EXPORT_PAGE_SIZE,
    maxSize: TIMELINE_MAX_STORED_EVENTS,
    callback: pages.collect,
  } as any);
  const { events } = pages;
  if (pages.exceeded()) {
    throw FunctionalError('This timeline is too large to export at once: narrow the export with the filters or the time window', {
      doc_code: TIMELINE_EXPORT_TOO_LARGE,
      max_text_length: TIMELINE_EXPORT_MAX_TEXT_LENGTH,
    });
  }
  const { items, elements } = await filterAccessibleEvents(context, user, container.internal_id, events, (e) => e, { fullElements: true });
  // A reference deleted since is marked by the event, which keeps its markings
  const withinCeiling = items.filter((event) => referencedElementIds(event, container.internal_id)
    .every((id) => markingsOf(elements[id] ?? event).every((markingId) => !markingsAboveCeiling.has(markingId))));
  // A file stored in the container reaches every reader of the container whose markings cover it, not only this user
  const exported = opts.storedInContainer ? await filterEventsSharedAsContainer(context, container, withinCeiling) : withinCeiling;
  const anchors = computeTimelineAnchors(exported, { isClosed: await isContainerClosed(context, container), computedAt: now() });
  return { container, items: exported, elements, anchors };
};

const renderTimelineExport = (snapshot: TimelineExportSnapshot, args: TimelineExportArgs): string => {
  const { container, items, elements } = snapshot;
  const exportEvents: TimelineExportEvent[] = items.map((event) => {
    const element = event.element_id && event.element_id !== container.internal_id ? elements[event.element_id] : null;
    return {
      id: event.internal_id,
      lane: event.lane,
      kind: event.kind,
      event_time: event.event_time,
      event_end_time: event.event_end_time,
      open_ended: event.open_ended ?? null,
      precision: event.time_precision,
      title: event.name,
      description: event.description,
      element_name: element ? extractEntityRepresentativeName(element) : null,
      element_type: element?.entity_type ?? null,
      source: event.event_source,
      pinned: event.pinned,
      hidden: event.hidden,
      annotation: event.annotation,
    };
  });
  const labels = Object.fromEntries((args.labels ?? []).map((l) => [l.key, l.label]));
  const exportInput = {
    containerName: extractEntityRepresentativeName(container),
    containerType: container.entity_type,
    events: exportEvents,
    anchors: snapshot.anchors,
    generatedAt: now(),
    labels,
    lanes: args.lanes,
  };
  switch (args.format) {
    case 'csv':
      return renderTimelineCsv(exportInput);
    case 'svg':
      return renderTimelineSvg(exportInput);
    case 'html':
      return renderTimelineHtml(exportInput);
    default:
      throw UnsupportedError('Unsupported timeline export format', { format: args.format });
  }
};

export const exportContainerTimeline = async (context: AuthContext, user: AuthUser, args: QueryContainerTimelineExportArgs) => {
  const snapshot = await loadExportedTimelineEvents(context, user, args);
  const content = renderTimelineExport(snapshot, args);
  addTimelineExportCount();
  return content;
};

/**
 * A stored export and its markings come from the same events: the file is never marked less strictly than the events
 * it contains nor than the elements and sources they reference (highest marking per definition type).
 */
export const exportContainerTimelineFile = async (context: AuthContext, user: AuthUser, args: QueryContainerTimelineExportFileArgs) => {
  const selected = await resolveMarkingIds(context, args.fileMarkings ?? []);
  validateMarkings(user, selected);
  const snapshot = await loadExportedTimelineEvents(context, user, args, { storedInContainer: true });
  const content = renderTimelineExport(snapshot, args);
  // The file always names the container: its markings are required even when no event is exported
  const required = [...markingsOf(snapshot.container), ...snapshot.items.flatMap((event) => [
    ...markingsOf(event),
    ...referencedElementIds(event, snapshot.container.internal_id).flatMap((id) => markingsOf(snapshot.elements[id] ?? event)),
  ])];
  const fileMarkings = await cleanMarkings(context, Array.from(new Set([...selected, ...required])));
  addTimelineExportCount();
  return { content, file_markings: fileMarkings };
};
// endregion

// region live updates
/**
 * A live update as one subscriber may see it: it names only the changed or removed events this user can read, and an
 * update about events the user cannot read at all is not sent to it (null). Updates about the container itself
 * (settings, anchors) name no event and go through to every reader of the container, and so does an update naming only
 * part of its events (truncated), whose other events this user may read.
 */
export const timelineUpdateForUser = async (context: AuthContext, user: AuthUser, update: TimelineUpdatePayload): Promise<TimelineUpdatePayload | null> => {
  // The subscription checked the access to the container when it started: it is read again for every update, so a
  // subscriber who lost it receives nothing more about the container, its anchors included
  const container = await internalLoadById(context, user, update.container_id, { type: TIMELINE_CONTAINER_TYPES, baseData: true });
  if (!container) {
    return null;
  }
  const { removed_events: removed = [], truncated = false, ...signal } = update;
  if (update.changed_event_ids.length === 0 && removed.length === 0) {
    return signal;
  }
  const changed = update.changed_event_ids.length > 0
    ? await internalFindByIds(context, user, update.changed_event_ids, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent[]
    : [];
  const allowedMarkings = new Set(user.allowed_marking.map((marking) => marking.internal_id));
  const readableRemoved = removed.filter((event) => isBypassUser(user) || event.marking_ids.every((id) => allowedMarkings.has(id)));
  // A removed event is read like a stored one, from what it recorded: an element or a source deleted since is read as it
  // was (the markings of the event carry its own), the ones that still exist as they are now
  const removedAsStored = (event: TimelineRemovedEvent) => ({
    internal_id: event.id,
    element_id: event.element_id,
    element_type: event.element_type,
    element_access: event.element_access,
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: event.marking_ids,
  }) as unknown as TimelineReadableEvent;
  const candidates: TimelineReadableEvent[] = [...changed, ...readableRemoved.map(removedAsStored)];
  const { items } = await filterAccessibleEvents(context, user, update.container_id, candidates, (event) => event);
  const changedEventIds = items.map((event) => event.internal_id);
  if (changedEventIds.length > 0) {
    return { ...signal, changed_event_ids: changedEventIds };
  }
  return truncated ? { ...signal, changed_event_ids: [] } : null;
};

/**
 * Maps the live updates of a subscription through `forUser`, skipping the ones it drops. Closing the subscription
 * closes the source at once, even while an update is awaited, so no listener outlives its subscriber.
 */
export const visibleTimelineUpdates = <T extends { instance: TimelineUpdatePayload }>(
  source: AsyncIterator<T>,
  forUser: (update: TimelineUpdatePayload) => Promise<TimelineUpdatePayload | null>,
): AsyncIterableIterator<T> => {
  // A loop rather than a recursion: a subscriber who reads none of a long run of updates waits on one promise, not
  // on a chain growing with every update skipped
  const pull = async (): Promise<IteratorResult<T>> => {
    for (;;) {
      const next = await source.next();
      if (next.done) {
        return next;
      }
      const instance = await forUser(next.value.instance);
      if (instance) {
        return { done: false, value: { ...next.value, instance } };
      }
    }
  };
  const iterator: AsyncIterableIterator<T> = {
    next: pull,
    return: (value?: unknown) => (source.return ? source.return(value) : Promise.resolve({ done: true, value: undefined } as IteratorResult<T>)),
    throw: (error?: unknown) => (source.throw ? source.throw(error) : Promise.reject(error)),
    [Symbol.asyncIterator]: () => iterator,
  };
  return iterator;
};
// endregion

// region mutations
const afterTimelineChange = async (
  context: AuthContext,
  user: AuthUser,
  container: AnyStoreElement,
  updateType: 'manual' | 'annotation' | 'settings',
  changedIds: string[],
  removed: StoredTimelineEvent[] = [],
) => {
  const { anchors } = await refreshTimelineContributions(context, container, { actor: user });
  await publishTimelineUpdate({
    container_id: container.internal_id,
    update_type: updateType,
    changed_event_ids: changedIds,
    removed_events: toRemovedTimelineEvents(removed),
    anchors,
  }, user);
};

const reloadEvent = async (context: AuthContext, user: AuthUser, id: string) => {
  return elLoadById<StoredTimelineEvent>(context, user, id, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent;
};

/** The manual event of a container added through the API with this external id, or imported with it as its external id. */
const loadManualEventByExternalId = async (context: AuthContext, containerId: string, externalId: string): Promise<StoredTimelineEvent | null> => {
  const added = await elLoadById<StoredTimelineEvent>(context, SYSTEM_USER, computeManualEventId(containerId, externalId), { type: ENTITY_TYPE_TIMELINE_EVENT });
  if (added) return added as unknown as StoredTimelineEvent;
  const [imported] = await fullEntitiesList<StoredTimelineEvent>(context, SYSTEM_USER, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['container_id'], values: [containerId] }, { key: ['event_source'], values: ['manual'] }, { key: ['external_id'], values: [externalId] }],
      filterGroups: [],
    },
    noFiltersChecking: true,
    first: 1,
    maxSize: 1,
  } as any);
  return imported ?? null;
};

const countManualTimelineEvents = (context: AuthContext, containerId: string): Promise<number> => {
  return elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_TIMELINE_EVENT],
    noFiltersChecking: true,
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['container_id'], values: [containerId] }, { key: ['event_source'], values: ['manual'] }],
      filterGroups: [],
    },
  } as any);
};

type LoadedTimelineEvent = Awaited<ReturnType<typeof loadEditableTimelineEvent>>;

/** Write an event under the lock of its container, from the event as stored once the lock is held. */
const writeTimelineEvent = async <T>(
  context: AuthContext,
  user: AuthUser,
  eventId: string,
  write: (loaded: LoadedTimelineEvent) => Promise<T>,
): Promise<T> => {
  const { container } = await loadEditableTimelineEvent(context, user, eventId);
  return withTimelineLock(container.internal_id, async () => write(await loadEditableTimelineEvent(context, user, eventId)));
};

const creatorIdsOf = (event: StoredTimelineEvent): string[] => {
  if (Array.isArray(event.creator_id)) return event.creator_id;
  return event.creator_id ? [event.creator_id] : [];
};

const docFromStored = (event: StoredTimelineEvent, container: AnyStoreElement, patch: Partial<Parameters<typeof buildTimelineEventDoc>[0]>) => {
  const access = containerAccessFields(container);
  const markings = (event[buildRefRelationKey(RELATION_OBJECT_MARKING)] ?? []) as string[];
  return buildTimelineEventDoc({
    internal_id: event.internal_id,
    container_id: event.container_id,
    name: event.name,
    description: event.description,
    event_time: event.event_time,
    event_end_time: event.event_end_time,
    time_precision: event.time_precision,
    lane: event.lane,
    kind: event.kind,
    event_source: event.event_source,
    rule_id: event.rule_id,
    element_id: event.element_id,
    element_type: event.element_type,
    pinned: event.pinned,
    hidden: event.hidden,
    annotation: event.annotation,
    confidence: event.confidence,
    ordering_hint: event.ordering_hint,
    analyst_fields: event.analyst_fields ?? [],
    external_id: event.external_id,
    markings: Array.from(new Set([...markings, ...access.markings])),
    created_by_id: (event[buildRefRelationKey(RELATION_CREATED_BY)] ?? [])[0],
    creator_ids: creatorIdsOf(event),
    restricted_members: access.restricted_members,
    // Kept as recorded: the access of the element and of the sources still decides who reads the event once it is edited
    source_state: event.source_state ?? null,
    element_access: event.element_access ?? null,
    ...patch,
  }, event);
};

export const addTimelineEvent = async (context: AuthContext, user: AuthUser, input: TimelineEventAddInput) => {
  const container = await loadEditableTimelineContainer(context, user, input.container_id);
  validateWindow(input.event_time, input.event_end_time);
  validateExternalId(input.external_id);
  const markingIds = await resolveMarkingIds(context, input.objectMarking ?? []);
  validateMarkings(user, markingIds);
  // Checked before waiting for the lock, read again under it for its markings
  await resolveElement(context, user, input.element_id);
  const author = await resolveAuthor(context, user, input.createdBy);
  const newEventId = input.external_id ? computeManualEventId(container.internal_id, input.external_id) : uuidv4();
  const kind = input.kind ?? 'milestone';
  const buildManualEventDoc = (
    internalId: string,
    previous: StoredTimelineEvent | null,
    access: ReturnType<typeof containerAccessFields>,
    element: AnyStoreElement | null,
  ) => {
    // Added again without naming an element, a known event keeps its element and the access it records: the element
    // decides who may read the event, and adding it again never loosens that
    const kept = input.element_id === undefined ? previous : null;
    return buildTimelineEventDoc({
      internal_id: internalId,
      container_id: container.internal_id,
      name: input.title.trim(),
      description: input.description,
      event_time: new Date(input.event_time).toISOString(),
      event_end_time: input.event_end_time ? new Date(input.event_end_time).toISOString() : null,
      time_precision: input.precision ?? 'exact',
      lane: input.lane ?? 'custom',
      kind,
      event_source: 'manual',
      rule_id: null,
      element_id: kept ? (kept.element_id ?? null) : (element?.internal_id ?? null),
      element_type: kept ? (kept.element_type ?? null) : (element?.entity_type ?? null),
      pinned: input.pinned ?? previous?.pinned ?? false,
      hidden: previous?.hidden ?? false,
      annotation: input.annotation ?? previous?.annotation ?? null,
      // Added again without a confidence, a known event keeps its own: it decides who may edit the event; an explicit null removes it
      confidence: input.confidence === undefined && previous ? (previous.confidence ?? null) : cappedTimelineConfidence(user, input.confidence),
      ordering_hint: input.ordering_hint ?? null,
      analyst_fields: [],
      external_id: input.external_id ?? null,
      // An event is never less marked than the element it points to, nor than its container; adding it again never declassifies it
      markings: Array.from(new Set([...(previous ? markingsOf(previous) : []), ...markingIds, ...(element ? markingsOf(element) : []), ...access.markings])),
      // Added again without naming an author, a known event keeps its author; an explicit null removes it
      created_by_id: input.createdBy === undefined && previous
        ? ((previous[buildRefRelationKey(RELATION_CREATED_BY)] ?? [])[0] ?? null)
        : (author?.internal_id ?? null),
      creator_ids: previous ? Array.from(new Set([...creatorIdsOf(previous), user.id])) : [user.id],
      restricted_members: access.restricted_members,
      element_access: kept ? (kept.element_access ?? null) : (element ? timelineElementAccessOf(element) : null),
    }, previous);
  };
  const { stored, existing } = await withTimelineLock(container.internal_id, async () => {
    // Read again under the lock: a change of the access to the container, or of the markings of the element, made while
    // this write waited applies to it
    const locked = await loadEditableTimelineContainer(context, user, container.internal_id);
    const element = await resolveElement(context, user, input.element_id);
    const current = input.external_id ? await loadManualEventByExternalId(context, container.internal_id, input.external_id) : null;
    const internalId = current?.internal_id ?? newEventId;
    // The idempotent upsert never lets a user overwrite (and unmark) an event he cannot read
    if (current && !(await findTimelineEvent(context, user, internalId))) {
      throw ForbiddenAccess('A timeline event you cannot access already uses this external id');
    }
    // Nor one above his confidence level, like any edit of the event
    if (current) controlUserConfidenceAgainstElement(user, current as unknown as BasicStoreEntity);
    // Nor does it point a known event to an element, or to none, that more users read
    if (current && input.element_id !== undefined) await controlTimelineElementChange(context, locked, current, element);
    if (!current && (await countManualTimelineEvents(context, container.internal_id)) >= TIMELINE_MAX_MANUAL_EVENTS) {
      throw FunctionalError('This timeline already holds the maximum number of milestones', { max: TIMELINE_MAX_MANUAL_EVENTS });
    }
    await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [buildManualEventDoc(internalId, current, containerAccessFields(locked), element)]);
    await afterTimelineChange(context, user, locked, 'manual', [internalId]);
    return { stored: await reloadEvent(context, user, internalId), existing: current };
  });
  if (!existing) {
    addTimelineManualEventCount();
    if (stored && (TIMELINE_MILESTONE_KINDS as readonly string[]).includes(kind)) {
      notifyTimelineMilestoneAdded(context, user, container.internal_id, stored)
        .catch((error) => logApp.error('[TIMELINE] Unable to notify milestone', { cause: error, containerId: container.internal_id }));
    }
  }
  return stored;
};

const DERIVED_EDITABLE_FIELDS = ['annotation', 'ordering_hint'];

const applyTimelineEventEdit = async (context: AuthContext, user: AuthUser, loaded: LoadedTimelineEvent, input: TimelineEventEditInput) => {
  const { event, container } = loaded;
  const providedFields = Object.entries(input).filter(([, value]) => value !== undefined).map(([key]) => key);
  if (event.event_source === 'derived') {
    const forbidden = providedFields.filter((field) => !DERIVED_EDITABLE_FIELDS.includes(field));
    if (forbidden.length > 0) {
      throw FunctionalError('A derived event only accepts an annotation and an ordering hint (pin and hide it with timelineEventPin and timelineEventHide)', { fields: forbidden });
    }
    const analystFields = new Set<TimelineAnalystField>(event.analyst_fields ?? []);
    const patch: Record<string, unknown> = {};
    if (input.annotation !== undefined) {
      patch.annotation = input.annotation || null;
      analystFields.add('annotation');
    }
    if (input.ordering_hint !== undefined) {
      patch.ordering_hint = input.ordering_hint;
      analystFields.add('ordering_hint');
    }
    const doc = docFromStored(event, container, { ...patch, analyst_fields: Array.from(analystFields) });
    await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [doc]);
    await afterTimelineChange(context, user, container, 'annotation', [event.internal_id]);
    return reloadEvent(context, user, event.internal_id);
  }
  const eventTime = input.event_time ? new Date(input.event_time).toISOString() : event.event_time;
  let eventEndTime = event.event_end_time ?? null;
  if (input.clear_event_end_time) eventEndTime = null;
  if (input.event_end_time) eventEndTime = new Date(input.event_end_time).toISOString();
  validateWindow(eventTime, eventEndTime);
  const patch: Partial<Parameters<typeof buildTimelineEventDoc>[0]> = { event_time: eventTime, event_end_time: eventEndTime };
  if (input.precision) patch.time_precision = input.precision;
  if (input.lane) patch.lane = input.lane;
  if (input.kind) patch.kind = input.kind;
  if (input.title !== undefined && input.title !== null) patch.name = input.title.trim();
  if (input.description !== undefined) patch.description = input.description;
  if (input.confidence !== undefined) patch.confidence = cappedTimelineConfidence(user, input.confidence);
  if (input.ordering_hint !== undefined) patch.ordering_hint = input.ordering_hint;
  if (input.annotation !== undefined) patch.annotation = input.annotation;
  // An event is never less marked than the element it points to, nor than its container
  let elementMarkings: string[] | null = null;
  if (input.element_id !== undefined) {
    const element = await resolveElement(context, user, input.element_id);
    await controlTimelineElementChange(context, container, event, element);
    patch.element_id = element?.internal_id ?? null;
    patch.element_type = element?.entity_type ?? null;
    patch.element_access = element ? timelineElementAccessOf(element) : null;
    elementMarkings = element ? markingsOf(element) : [];
  }
  if (input.createdBy !== undefined) {
    const author = await resolveAuthor(context, user, input.createdBy);
    patch.created_by_id = author?.internal_id ?? null;
  }
  if (input.objectMarking) {
    const markingIds = await resolveMarkingIds(context, input.objectMarking);
    validateMarkings(user, markingIds);
    if (elementMarkings === null && event.element_id) {
      const current = await internalLoadById<AnyStoreElement>(context, SYSTEM_USER, event.element_id);
      elementMarkings = current ? markingsOf(current) : [];
    }
    // Like adding it again or importing it, editing an event never declassifies it: the markings of an element it pointed
    // to, or of a deleted one, live on the event only
    patch.markings = Array.from(new Set([...markingsOf(event), ...markingIds, ...(elementMarkings ?? []), ...containerAccessFields(container).markings]));
  } else if (elementMarkings !== null) {
    patch.markings = Array.from(new Set([...markingsOf(event), ...elementMarkings]));
  }
  patch.creator_ids = Array.from(new Set([...creatorIdsOf(event), user.id]));
  const doc = docFromStored(event, container, patch);
  await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [doc]);
  await afterTimelineChange(context, user, container, 'manual', [event.internal_id]);
  return reloadEvent(context, user, event.internal_id);
};

export const editTimelineEvent = async (context: AuthContext, user: AuthUser, id: string, input: TimelineEventEditInput) => {
  return writeTimelineEvent(context, user, id, (loaded) => applyTimelineEventEdit(context, user, loaded, input));
};

export const deleteTimelineEvent = async (context: AuthContext, user: AuthUser, id: string) => {
  return writeTimelineEvent(context, user, id, async ({ event, container }) => {
    if (event.event_source !== 'manual') {
      throw FunctionalError('A derived event cannot be deleted, hide it instead', { id });
    }
    await deleteTimelineDocuments([event.internal_id]);
    await afterTimelineChange(context, user, container, 'manual', [], [event]);
    return event.internal_id;
  });
};

const setAnalystFlag = async (context: AuthContext, user: AuthUser, id: string, field: 'pinned' | 'hidden', value: boolean) => {
  return writeTimelineEvent(context, user, id, async ({ event, container }) => {
    const analystFields = new Set<TimelineAnalystField>(event.analyst_fields ?? []);
    if (event.event_source === 'derived') analystFields.add(field);
    const doc = docFromStored(event, container, { [field]: value, analyst_fields: Array.from(analystFields) });
    await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [doc]);
    await afterTimelineChange(context, user, container, 'annotation', [event.internal_id]);
    return reloadEvent(context, user, event.internal_id);
  });
};

export const pinTimelineEvent = async (context: AuthContext, user: AuthUser, id: string, pinned: boolean) => {
  return setAnalystFlag(context, user, id, 'pinned', pinned);
};

export const hideTimelineEvent = async (context: AuthContext, user: AuthUser, id: string, hidden: boolean) => {
  return setAnalystFlag(context, user, id, 'hidden', hidden);
};

export const updateTimelineSettings = async (context: AuthContext, user: AuthUser, containerId: string, input: TimelineSettingsInput) => {
  const container = await loadEditableTimelineContainer(context, user, containerId);
  const patch: Record<string, unknown> = {};
  if (input.enabled_lanes) {
    if (input.enabled_lanes.length === 0) throw FunctionalError('At least one lane must be enabled');
    patch.enabled_lanes = Array.from(new Set(input.enabled_lanes));
  }
  if (input.default_grouping) patch.default_grouping = input.default_grouping;
  if (input.default_zoom_window) patch.default_zoom_window = input.default_zoom_window;
  if (input.hidden_kinds) {
    // An empty kinds filter means every kind: hiding them all would show them all again
    const hidden = new Set<string>(input.hidden_kinds);
    if (TIMELINE_KINDS.every((kind) => hidden.has(kind))) throw FunctionalError('At least one kind must stay visible');
    patch.hidden_kinds = Array.from(hidden);
  }
  // Read again under the lock: a change of the access to the container, or of its anchors by a regeneration, made while
  // this write waited applies to it and to the update published
  const { settings, anchors } = await withTimelineLock(container.internal_id, async () => {
    const locked = await loadEditableTimelineContainer(context, user, container.internal_id);
    return { settings: await upsertTimelineSettings(context, locked, patch), anchors: locked[ATTRIBUTE_TIMELINE_ANCHORS] ?? null };
  });
  await publishTimelineUpdate({ container_id: container.internal_id, update_type: 'settings', changed_event_ids: [], anchors }, user);
  return settingsWithDefaults(container.internal_id, settings);
};

export const regenerateTimeline = async (context: AuthContext, user: AuthUser, containerId: string): Promise<TimelineRegenerationResult | null> => {
  const container = await loadEditableTimelineContainer(context, user, containerId);
  return regenerateContainerTimeline(context, container.internal_id, { wait: true, actor: user });
};

/** Write the imported contributions and return the ids of the milestones created; runs under the timeline lock of the container. */
const writeImportedContributions = async (
  context: AuthContext,
  user: AuthUser,
  container: AnyStoreElement,
  contributions: SanitizedTimelineExtension,
  resolved: Record<string, AnyStoreElement>,
) => {
  const { events, annotations } = contributions;
  const access = containerAccessFields(container);
  const allowedMarkings = new Set(user.allowed_marking.map((m) => m.internal_id));
  // A manual event travelling back to a platform that already knows it must update it, never duplicate it. Its STIX id
  // comes first (an event of this platform, or one imported earlier, whose id is computed from that STIX id); its
  // external id (the id it was originally imported from, or the one given when it was added through the API) comes second.
  const storedEvents = await loadStoredTimelineEvents(context, container.internal_id);
  const storedManual = storedEvents.filter((e) => e.event_source === 'manual');
  const storedByStandardId = new Map(storedManual.map((e) => [e.standard_id as string, e]));
  const storedByExternalId = new Map(storedManual.filter((e) => !!e.external_id).map((e) => [e.external_id as string, e]));
  const storedById = new Map(storedManual.map((e) => [e.internal_id, e]));
  const findKnownEvent = (event: StixTimelineExtensionEvent) => {
    const keys = [event.id, event.external_id].filter((key): key is string => !!key);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const known = storedByStandardId.get(key) ?? storedById.get(computeManualEventId(container.internal_id, key)) ?? storedByExternalId.get(key);
      if (known) return known;
    }
    return null;
  };
  // An event is never declassified: when one of its markings is unknown here, is not a marking definition (a reference
  // resolves to any object the user can read) or is not allowed to the user, it is skipped
  const importableMarkings = (event: StixTimelineExtensionEvent): string[] | null => {
    const markings = (event.object_marking_refs ?? []).map((ref) => resolved[ref]);
    const isImportable = (marking: AnyStoreElement | undefined): marking is AnyStoreElement => !!marking
      && marking.entity_type === ENTITY_TYPE_MARKING_DEFINITION
      && (isBypassUser(user) || allowedMarkings.has(marking.internal_id));
    return markings.every(isImportable) ? markings.map(({ internal_id }) => internal_id) : null;
  };
  const storedIds = new Set(storedManual.map((e) => e.internal_id));
  // Two new events of one extension sharing an external id are one event, as they would be once the first is stored
  const batchIdByExternalId = new Map<string, string>();
  const identified = events.map((event) => {
    const existing = findKnownEvent(event);
    const internalId = existing?.internal_id
      ?? (event.external_id ? batchIdByExternalId.get(event.external_id) : undefined)
      ?? computeManualEventId(container.internal_id, event.id);
    if (event.external_id && !batchIdByExternalId.has(event.external_id)) batchIdByExternalId.set(event.external_id, internalId);
    return { event, existing, internalId };
  });
  // Nor is a stored event the user cannot read ever overwritten by an imported one: every known event the extension names
  // is read as the user, however many events the case holds
  const knownIds = Array.from(new Set(identified.map((candidate) => candidate.internalId).filter((id) => storedIds.has(id))));
  const knownAsUser = knownIds.length > 0
    ? await internalFindByIds(context, user, knownIds, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent[]
    : [];
  const { items: readable } = await filterAccessibleEvents(context, user, container.internal_id, knownAsUser, (e) => e);
  const readableIds = new Set(readable.map((e) => e.internal_id));
  // An extension naming the same event twice writes, counts and notifies it once, and takes the cap of the case once:
  // its last occurrence wins
  const candidates = Array.from(new Map(identified.map((candidate) => [candidate.internalId, candidate])).values()).map(({ event, existing, internalId }) => {
    const overwritesUnreadable = storedIds.has(internalId) && !readableIds.has(internalId);
    // Nor is a stored event above the confidence level of the user overwritten, like any edit of the event
    const stored = existing ?? storedById.get(internalId);
    const overwritesAboveConfidence = !!stored && !controlUserConfidenceAgainstElement(user, stored as unknown as BasicStoreEntity, true);
    return { event, existing, stored, internalId, markings: overwritesUnreadable || overwritesAboveConfidence ? null : importableMarkings(event) };
  });
  const skipped = candidates.filter((candidate) => candidate.markings === null).length;
  if (skipped > 0) {
    logApp.warn('[TIMELINE] Contributions skipped on import: markings unknown, not marking definitions or not allowed, event not readable or above the confidence level', { containerId: container.internal_id, skipped });
  }
  // New milestones stay within the cap of the case, updates of known events always apply
  const accepted = candidates.filter((candidate) => candidate.markings !== null);
  let capacity = Math.max(0, TIMELINE_MAX_MANUAL_EVENTS - storedManual.length);
  const isKnown = (candidate: { existing: StoredTimelineEvent | null; internalId: string }) => !!candidate.existing || storedIds.has(candidate.internalId);
  const importable = accepted.filter((candidate) => {
    if (isKnown(candidate)) return true;
    if (capacity === 0) return false;
    capacity -= 1;
    return true;
  });
  if (importable.length < accepted.length) {
    logApp.warn('[TIMELINE] Imported milestones beyond the cap of the case were skipped', {
      containerId: container.internal_id,
      skipped: accepted.length - importable.length,
      max: TIMELINE_MAX_MANUAL_EVENTS,
    });
  }
  // The references were resolved without their markings: the markings of the elements are read in full, with the stored
  // elements of the known events, whose readers decide whether an imported element may replace them
  const elementIds = Array.from(new Set(importable.flatMap(({ event, stored }) => [event.element_ref ? resolved[event.element_ref]?.internal_id : null, stored?.element_id])
    .filter((id): id is string => !!id)));
  const elementsWithMarkings = elementIds.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, elementIds, { toMap: true }) as unknown as Record<string, AnyStoreElement>
    : {};
  const platformOrganization = await hasPlatformOrganization(context);
  // A known event keeps its element when the imported version names none, one the user cannot resolve, or one that users
  // its stored element is hidden from can read: its element decides who may read it, and an import never loosens that
  const importedElementOf = (event: StixTimelineExtensionEvent, stored: StoredTimelineEvent | null | undefined): AnyStoreElement | null => {
    const element = event.element_ref ? resolved[event.element_ref] : null;
    if (!element || !stored?.element_id) return element ?? null;
    const previous = elementsWithMarkings[stored.element_id] ?? recordedTimelineReference(stored, stored.element_id);
    const next = elementsWithMarkings[element.internal_id] ?? element;
    return isTimelineElementChangeWidening(container, previous, next, platformOrganization) ? null : element;
  };
  const keptElements = importable.filter(({ event, stored }) => !!event.element_ref && !!resolved[event.element_ref] && !importedElementOf(event, stored)).length;
  if (keptElements > 0) {
    logApp.warn('[TIMELINE] Imported elements read by more users than the stored ones were skipped, the events keep their element', { containerId: container.internal_id, skipped: keptElements });
  }
  // An imported author is kept only when it resolves to an identity, like the author of a milestone added through the API
  const importedAuthorId = (ref: string | null | undefined): string | null => {
    const author = ref ? resolved[ref] : undefined;
    return author && isStixDomainObjectIdentity(author.entity_type) ? author.internal_id : null;
  };
  const docs = importable.map(({ event, existing, stored, internalId, markings }) => {
    validateWindow(event.event_time, event.event_end_time);
    const element = importedElementOf(event, stored);
    return buildTimelineEventDoc({
      internal_id: internalId,
      container_id: container.internal_id,
      name: event.title,
      description: event.description,
      event_time: new Date(event.event_time).toISOString(),
      event_end_time: event.event_end_time ? new Date(event.event_end_time).toISOString() : null,
      time_precision: event.precision,
      lane: event.lane,
      kind: event.kind,
      event_source: 'manual',
      rule_id: null,
      element_id: element?.internal_id ?? stored?.element_id ?? null,
      element_type: element?.entity_type ?? stored?.element_type ?? null,
      pinned: event.pinned ?? false,
      hidden: event.hidden ?? false,
      annotation: event.annotation ?? null,
      // Like its markings, a known event keeps the higher of its stored and imported confidence: an import never lets less
      // trusted users edit it
      confidence: strongerTimelineConfidence(stored?.confidence, cappedTimelineConfidence(user, event.confidence)),
      ordering_hint: event.ordering_hint ?? null,
      analyst_fields: [],
      external_id: existing ? (existing.external_id ?? null) : (event.external_id ?? event.id),
      // An update keeps the markings the stored event already carries: an import never declassifies it
      markings: Array.from(new Set([
        ...(stored ? markingsOf(stored) : []),
        ...(markings as string[]),
        ...(element ? markingsOf(elementsWithMarkings[element.internal_id] ?? {}) : []),
        ...access.markings,
      ])),
      // Like its element, a known event keeps its author when the imported version names none the user can resolve: the
      // exchange leaves out the authors that are not as visible as the container
      created_by_id: importedAuthorId(event.created_by_ref) ?? (stored ? (stored[buildRefRelationKey(RELATION_CREATED_BY)] ?? [])[0] ?? null : null),
      creator_ids: existing ? Array.from(new Set([...creatorIdsOf(existing), user.id])) : [user.id],
      restricted_members: access.restricted_members,
      element_access: element ? timelineElementAccessOf(elementsWithMarkings[element.internal_id] ?? element) : (stored?.element_access ?? null),
    }, existing);
  });
  let createdMilestoneIds: string[] = [];
  if (docs.length > 0) {
    await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, docs);
    // Milestones created by the import count and notify like the ones added by an analyst; updates of known events do not
    const created = importable.filter((candidate) => !isKnown(candidate));
    if (created.length > 0) addTimelineManualEventCount(created.length);
    createdMilestoneIds = created.filter(({ event }) => (TIMELINE_MILESTONE_KINDS as readonly string[]).includes(event.kind))
      .map(({ internalId }) => internalId);
  }
  // An imported annotation pins, hides or annotates a derived event like an edit of the event: never one the user cannot
  // read (the event, its element and each of its sources) nor one above his confidence level. A derived event already
  // stored is checked now; the importer and his confidence level are kept with the annotation for the event the derivation
  // has not produced yet, and checked again when the regeneration applies it.
  const maxConfidence = timelineEventMaxConfidence(user);
  const storedDerivedById = new Map(storedEvents.filter((e) => e.event_source === 'derived').map((e) => [e.internal_id, e]));
  const importedAnnotations: TimelinePendingAnnotation[] = annotations
    .filter((a) => a.element_ref && resolved[a.element_ref] && a.rule_id && a.kind)
    .map((a) => ({
      event_id: computeDerivedEventId(container.internal_id, a.rule_id, resolved[a.element_ref].internal_id, a.kind),
      pinned: a.pinned,
      hidden: a.hidden,
      // A field cleared by the analyst who exported it is cleared here too, an absent one leaves the event unchanged
      annotation: a.cleared_fields?.includes('annotation') ? null : a.annotation,
      ordering_hint: a.cleared_fields?.includes('ordering_hint') ? null : a.ordering_hint,
      max_confidence: maxConfidence,
      importer_id: user.id,
    }));
  const storedTargetIds = Array.from(new Set(importedAnnotations.map((a) => a.event_id).filter((id) => storedDerivedById.has(id))));
  const storedTargetsAsUser = storedTargetIds.length > 0
    ? await internalFindByIds(context, user, storedTargetIds, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent[]
    : [];
  const { items: readableTargets } = await filterAccessibleEvents(context, user, container.internal_id, storedTargetsAsUser, (e) => e);
  const readableTargetIds = new Set(readableTargets.map((e) => e.internal_id));
  const pending = importedAnnotations.filter((annotation) => {
    const target = storedDerivedById.get(annotation.event_id);
    if (maxConfidence === null) return false;
    return !target || (readableTargetIds.has(target.internal_id) && controlUserConfidenceAgainstElement(user, target as unknown as BasicStoreEntity, true));
  });
  if (pending.length < importedAnnotations.length) {
    logApp.warn('[TIMELINE] Imported annotations of events the user cannot read or above his confidence level were skipped', {
      containerId: container.internal_id,
      skipped: importedAnnotations.length - pending.length,
    });
  }
  if (pending.length > 0) {
    const settings = await loadTimelineSettings(context, container.internal_id);
    const byId = new Map((settings?.pending_annotations ?? []).map((a) => [a.event_id, a]));
    // Pending annotations stay within the cap of the case (they are read and rewritten on every regeneration), updates always apply
    let skippedAnnotations = 0;
    pending.forEach((annotation) => {
      if (byId.has(annotation.event_id) || byId.size < TIMELINE_MAX_EVENTS) {
        byId.set(annotation.event_id, annotation);
      } else {
        skippedAnnotations += 1;
      }
    });
    if (skippedAnnotations > 0) {
      logApp.warn('[TIMELINE] Imported annotations beyond the cap of the case were skipped', { containerId: container.internal_id, skipped: skippedAnnotations });
    }
    await upsertTimelineSettings(context, container, { pending_annotations: Array.from(byId.values()) }, settings ?? null);
  }
  return createdMilestoneIds;
};

/** Notify the "Timeline milestone added" trigger for milestones just written, read at once as their author, in one pass over the triggers. */
const notifyMilestonesAdded = async (context: AuthContext, user: AuthUser, containerId: string, milestoneIds: string[]) => {
  const stored = await internalFindByIds(context, user, milestoneIds, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent[];
  await notifyTimelineMilestonesAdded(context, user, containerId, stored);
};

/**
 * Import the analyst contributions of a timeline STIX extension: manual events are created
 * (idempotent on their STIX id), annotations are applied to the derived events they target or kept
 * pending until the derivation produces them.
 */
export const importTimelineExtension = async (context: AuthContext, user: AuthUser, containerId: string, rawExtension: string) => {
  const container = await loadEditableTimelineContainer(context, user, containerId);
  let extension: unknown;
  try {
    extension = JSON.parse(rawExtension);
  } catch {
    throw FunctionalError('Invalid timeline extension');
  }
  const contributions = sanitizeTimelineExtension(extension, { maxEvents: TIMELINE_IMPORT_MAX_EVENTS, maxAnnotations: TIMELINE_MAX_EVENTS });
  const { events, annotations, dropped, normalized } = contributions;
  if (dropped > 0 || normalized > 0) {
    logApp.warn('[TIMELINE] Timeline extension values dropped or normalized on import', { containerId: container.internal_id, dropped, normalized });
  }
  const refs = Array.from(new Set([
    ...events.flatMap((e) => [e.element_ref, e.created_by_ref, ...(e.object_marking_refs ?? [])]),
    ...annotations.map((a) => a.element_ref),
  ].filter((ref): ref is string => !!ref)));
  // The container and the references are read under the lock: a change of access made while the import waited applies to it
  const createdMilestoneIds = await withTimelineLock(container.internal_id, async () => {
    const locked = await loadEditableTimelineContainer(context, user, container.internal_id);
    const resolved = refs.length > 0
      ? await internalFindByIds(context, user, refs, { toMap: true, mapWithAllIds: true, baseData: true }) as unknown as Record<string, AnyStoreElement>
      : {};
    return writeImportedContributions(context, user, locked, contributions, resolved);
  });
  const regenerated = await regenerateContainerTimeline(context, container.internal_id, { wait: true, actor: user });
  if (createdMilestoneIds.length > 0) {
    notifyMilestonesAdded(context, user, container.internal_id, createdMilestoneIds)
      .catch((error) => logApp.error('[TIMELINE] Unable to notify imported milestones', { cause: error, containerId: container.internal_id }));
  }
  return regenerated;
};
// endregion
