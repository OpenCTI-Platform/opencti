import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../../types/store';
import { AccessOperation, executionContext, isBypassUser, isUserHasCapability, KNOWLEDGE_KNUPDATE, SYSTEM_USER, validateUserAccessOperation } from '../../utils/access';
import { controlUserConfidenceAgainstElement } from '../../utils/confidence-level';
import { fullEntitiesList, internalFindByIds, internalLoadById, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { elAggregationCount, elCount, elIndexElements, elLoadById } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { getDraftContext } from '../../utils/draftContext';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import type {
  QueryContainerTimelineArgs,
  QueryContainerTimelineExportArgs,
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
import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { now } from '../../utils/format';
import {
  ATTRIBUTE_TIMELINE_ANCHORS,
  ENTITY_TYPE_TIMELINE_EVENT,
  type StixTimelineExtension,
  type StixTimelineExtensionEvent,
  TIMELINE_CONTAINER_TYPES,
  TIMELINE_DEFAULT_SETTINGS,
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
  deleteTimelineDocuments,
  getTimelineRules,
  loadStoredTimelineEvents,
  loadTimelineSettings,
  publishTimelineUpdate,
  refreshTimelineContributions,
  regenerateContainerTimeline,
  type StoredTimelineEvent,
  type StoredTimelineSettings,
  TIMELINE_MAX_EVENTS,
  type TimelineRegenerationResult,
  upsertTimelineSettings,
} from './timeline-engine';
import { renderTimelineCsv, renderTimelineHtml, renderTimelineSvg, type TimelineExportEvent } from './timeline-export';
import { notifyTimelineMilestoneAdded } from './timeline-notification';
import { addTimelineExportCount, addTimelineManualEventCount, addTimelineViewCount } from '../../manager/telemetryManager';
import { logApp } from '../../config/conf';

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

const loadEditableTimelineEvent = async (context: AuthContext, user: AuthUser, eventId: string) => {
  const event = await elLoadById<StoredTimelineEvent>(context, SYSTEM_USER, eventId, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent;
  if (!event) {
    throw FunctionalError('Timeline event cannot be found', { id: eventId });
  }
  const container = await loadEditableTimelineContainer(context, user, event.container_id);
  return { event, container };
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
    if (Number.isNaN(end) || end < start) {
      throw FunctionalError('The end time of an event must be after its start time', { event_time: eventTime, event_end_time: eventEndTime });
    }
  }
};
// endregion

// region reads
const ensureTimelineGenerated = async (context: AuthContext, container: AnyStoreElement) => {
  if (container[ATTRIBUTE_TIMELINE_ANCHORS]?.computed_at) return container;
  // First opening of a container that was never processed: build its timeline now, always on the
  // live knowledge (never inside the draft the reader may be working in)
  const generationContext = executionContext('timeline_generation');
  await regenerateContainerTimeline(generationContext, container.internal_id);
  const generated = await internalLoadById<AnyStoreElement>(generationContext, SYSTEM_USER, container.internal_id, { type: TIMELINE_CONTAINER_TYPES });
  return generated ?? container;
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
    // Point events after the start of the window, or windows still open at the start of the window
    filterGroups.push({
      mode: FilterMode.Or,
      filters: [
        { key: ['event_time'], values: [args.from], operator: FilterOperator.Gte },
        { key: ['event_end_time'], values: [args.from], operator: FilterOperator.Gte },
      ],
      filterGroups: [],
    });
  }
  if (args.search && args.search.trim().length > 0) {
    filters.push({ key: ['name', 'description', 'annotation'], values: [args.search.trim()], operator: FilterOperator.Search, mode: FilterMode.Or });
  }
  return { mode: FilterMode.And, filters, filterGroups };
};

/** Drop the events pointing to elements the user cannot see (or that no longer exist). */
const filterAccessibleEvents = async <T extends { node: StoredTimelineEvent } | StoredTimelineEvent>(
  context: AuthContext,
  user: AuthUser,
  containerId: string,
  items: T[],
  getEvent: (item: T) => StoredTimelineEvent,
): Promise<{ items: T[]; elements: Record<string, AnyStoreElement> }> => {
  const elementIds = Array.from(new Set(items.map((item) => getEvent(item).element_id).filter((id): id is string => !!id && id !== containerId)));
  const elements = elementIds.length > 0
    ? await internalFindByIds(context, user, elementIds, { toMap: true, baseData: true }) as unknown as Record<string, AnyStoreElement>
    : {};
  const filtered = items.filter((item) => {
    const elementId = getEvent(item).element_id;
    return !elementId || elementId === containerId || !!elements[elementId];
  });
  return { items: filtered, elements };
};

/** Elements referenced by the events of a container that the user cannot access (or that no longer exist). */
const findInaccessibleElementIds = async (context: AuthContext, user: AuthUser, containerId: string): Promise<string[]> => {
  const references = await fullEntitiesList<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: buildTimelineFilters(containerId, { includeHidden: true }) as any,
    baseData: true,
    baseFields: ['element_id'],
    maxSize: TIMELINE_MAX_EVENTS * 2,
  } as any);
  const elementIds = Array.from(new Set(references.map((event) => event.element_id).filter((id): id is string => !!id && id !== containerId)));
  if (elementIds.length === 0) return [];
  const accessible = await internalFindByIds(context, user, elementIds, { toMap: true, baseData: true }) as unknown as Record<string, AnyStoreElement>;
  return elementIds.filter((id) => !accessible[id]);
};

export const findContainerTimeline = async (context: AuthContext, user: AuthUser, args: QueryContainerTimelineArgs) => {
  const container = await ensureTimelineGenerated(context, await loadTimelineContainer(context, user, args.id));
  const first = Math.min(args.first ?? TIMELINE_DEFAULT_PAGE, TIMELINE_MAX_PAGE);
  const connection = await pageEntitiesConnection<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: buildTimelineFilters(container.internal_id, args) as any,
    first,
    after: args.after,
    orderBy: ['event_time', 'ordering_hint'],
    orderMode: args.orderMode ?? OrderingMode.Asc,
  });
  const { items } = await filterAccessibleEvents(context, user, container.internal_id, connection.edges, (edge) => edge.node);
  return { ...connection, edges: items };
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

export const findTimelineAnchors = async (context: AuthContext, user: AuthUser, containerId: string): Promise<TimelineAnchors | null> => {
  const container = await ensureTimelineGenerated(context, await loadTimelineContainer(context, user, containerId));
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

export const findContainerTimelineSummary = async (context: AuthContext, user: AuthUser, containerId: string): Promise<TimelineSummary> => {
  const loaded = await storeLoadById<AnyStoreElement>(context, user, containerId, TIMELINE_CONTAINER_TYPES);
  if (!loaded) {
    throw FunctionalError('Timeline container cannot be found', { id: containerId });
  }
  const container = await ensureTimelineGenerated(context, loaded);
  const baseArgs = { types: [ENTITY_TYPE_TIMELINE_EVENT], noFiltersChecking: true };
  // Same visibility as the list: the events of elements the user cannot access are not counted
  const hiddenElementIds = await findInaccessibleElementIds(context, user, container.internal_id);
  const restrict = (filters: ReturnType<typeof buildTimelineFilters>) => (hiddenElementIds.length === 0 ? filters : {
    ...filters,
    filters: [...filters.filters, { key: ['element_id'], values: hiddenElementIds, operator: FilterOperator.NotEq, mode: FilterMode.And }],
  });
  const visibleFilters = restrict(buildTimelineFilters(container.internal_id, {}));
  const allFilters = restrict(buildTimelineFilters(container.internal_id, { includeHidden: true }));
  const count = (filters: any) => elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...baseArgs, filters });
  const withFilter = (extra: any) => ({ ...allFilters, filters: [...allFilters.filters, extra] });
  const [total, manualCount, pinnedCount, hiddenCount, lanes, kinds, firstEvents, lastEvents, settings] = await Promise.all([
    count(visibleFilters),
    count({ ...visibleFilters, filters: [...visibleFilters.filters, { key: ['event_source'], values: ['manual'] }] }),
    count({ ...visibleFilters, filters: [...visibleFilters.filters, { key: ['pinned'], values: ['true'] }] }),
    count(withFilter({ key: ['hidden'], values: ['true'] })),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...baseArgs, filters: visibleFilters as any, field: 'lane', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...baseArgs, filters: visibleFilters as any, field: 'kind', normalizeLabel: false }),
    pageEntitiesConnection<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], { filters: visibleFilters as any, first: 1, orderBy: 'event_time', orderMode: OrderingMode.Asc }),
    pageEntitiesConnection<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], { filters: visibleFilters as any, first: 1, orderBy: 'event_time', orderMode: OrderingMode.Desc }),
    loadTimelineSettings(context, container.internal_id),
  ]);
  const lastEvent = lastEvents.edges[0]?.node;
  addTimelineViewCount();
  return {
    container_id: container.internal_id,
    total,
    manual_count: manualCount,
    pinned_count: pinnedCount,
    hidden_count: hiddenCount,
    first_event_time: firstEvents.edges[0]?.node.event_time ?? null,
    last_event_time: lastEvent ? (lastEvent.event_end_time ?? lastEvent.event_time) : null,
    lanes: lanes.map((l) => ({ lane: l.label, count: l.count })),
    kinds: kinds.map((k) => ({ kind: k.label, count: k.count })),
    anchors: container[ATTRIBUTE_TIMELINE_ANCHORS] ?? null,
    settings: settingsWithDefaults(container.internal_id, settings),
    can_edit: canEditTimeline(user, container) && !getDraftContext(context, user),
    truncated: settings?.derivation_truncated ?? false,
    generated_at: settings?.generated_at ?? null,
  } as unknown as TimelineSummary;
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
export const exportContainerTimeline = async (context: AuthContext, user: AuthUser, args: QueryContainerTimelineExportArgs) => {
  const container = await ensureTimelineGenerated(context, await loadTimelineContainer(context, user, args.id));
  const events = await fullEntitiesList<StoredTimelineEvent>(context, user, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: buildTimelineFilters(container.internal_id, args) as any,
    orderBy: ['event_time', 'ordering_hint'],
    orderMode: OrderingMode.Asc,
    maxSize: TIMELINE_MAX_EVENTS,
  } as any);
  const { items, elements } = await filterAccessibleEvents(context, user, container.internal_id, events, (e) => e);
  const exportEvents: TimelineExportEvent[] = items.map((event) => {
    const element = event.element_id && event.element_id !== container.internal_id ? elements[event.element_id] : null;
    return {
      id: event.internal_id,
      lane: event.lane,
      kind: event.kind,
      event_time: event.event_time,
      event_end_time: event.event_end_time,
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
    anchors: container[ATTRIBUTE_TIMELINE_ANCHORS] ?? null,
    generatedAt: now(),
    labels,
  };
  addTimelineExportCount();
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
// endregion

// region mutations
const afterTimelineChange = async (
  context: AuthContext,
  user: AuthUser,
  container: AnyStoreElement,
  updateType: 'manual' | 'annotation' | 'settings',
  changedIds: string[],
) => {
  const { anchors } = await refreshTimelineContributions(context, container);
  await publishTimelineUpdate({ container_id: container.internal_id, update_type: updateType, changed_event_ids: changedIds, anchors }, user);
};

const reloadEvent = async (context: AuthContext, user: AuthUser, id: string) => {
  return elLoadById<StoredTimelineEvent>(context, user, id, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent;
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
    ...patch,
  }, event);
};

export const addTimelineEvent = async (context: AuthContext, user: AuthUser, input: TimelineEventAddInput) => {
  const container = await loadEditableTimelineContainer(context, user, input.container_id);
  validateWindow(input.event_time, input.event_end_time);
  const markingIds = await resolveMarkingIds(context, input.objectMarking ?? []);
  validateMarkings(user, markingIds);
  const element = await resolveElement(context, user, input.element_id);
  const author = await resolveAuthor(context, user, input.createdBy);
  const internalId = input.external_id ? computeManualEventId(container.internal_id, input.external_id) : uuidv4();
  const existing = input.external_id
    ? await elLoadById<StoredTimelineEvent>(context, SYSTEM_USER, internalId, { type: ENTITY_TYPE_TIMELINE_EVENT }) as unknown as StoredTimelineEvent
    : null;
  const access = containerAccessFields(container);
  const kind = input.kind ?? 'milestone';
  const doc = buildTimelineEventDoc({
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
    element_id: element?.internal_id ?? null,
    element_type: element?.entity_type ?? null,
    pinned: input.pinned ?? existing?.pinned ?? false,
    hidden: existing?.hidden ?? false,
    annotation: input.annotation ?? existing?.annotation ?? null,
    confidence: input.confidence ?? null,
    ordering_hint: input.ordering_hint ?? null,
    analyst_fields: [],
    external_id: input.external_id ?? null,
    markings: [...markingIds, ...access.markings],
    created_by_id: author?.internal_id ?? null,
    creator_ids: existing ? Array.from(new Set([...creatorIdsOf(existing), user.id])) : [user.id],
    restricted_members: access.restricted_members,
  }, existing);
  await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [doc]);
  await afterTimelineChange(context, user, container, 'manual', [internalId]);
  const stored = await reloadEvent(context, user, internalId);
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

export const editTimelineEvent = async (context: AuthContext, user: AuthUser, id: string, input: TimelineEventEditInput) => {
  const { event, container } = await loadEditableTimelineEvent(context, user, id);
  const providedFields = Object.entries(input).filter(([, value]) => value !== undefined).map(([key]) => key);
  if (event.event_source === 'derived') {
    const forbidden = providedFields.filter((field) => !DERIVED_EDITABLE_FIELDS.includes(field));
    if (forbidden.length > 0) {
      throw FunctionalError('A derived event can only be annotated, pinned or hidden', { fields: forbidden });
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
  if (input.confidence !== undefined) patch.confidence = input.confidence;
  if (input.ordering_hint !== undefined) patch.ordering_hint = input.ordering_hint;
  if (input.annotation !== undefined) patch.annotation = input.annotation;
  if (input.element_id !== undefined) {
    const element = await resolveElement(context, user, input.element_id);
    patch.element_id = element?.internal_id ?? null;
    patch.element_type = element?.entity_type ?? null;
  }
  if (input.createdBy !== undefined) {
    const author = await resolveAuthor(context, user, input.createdBy);
    patch.created_by_id = author?.internal_id ?? null;
  }
  if (input.objectMarking) {
    const markingIds = await resolveMarkingIds(context, input.objectMarking);
    validateMarkings(user, markingIds);
    patch.markings = [...markingIds, ...containerAccessFields(container).markings];
  }
  patch.creator_ids = Array.from(new Set([...creatorIdsOf(event), user.id]));
  const doc = docFromStored(event, container, patch);
  await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [doc]);
  await afterTimelineChange(context, user, container, 'manual', [event.internal_id]);
  return reloadEvent(context, user, event.internal_id);
};

export const deleteTimelineEvent = async (context: AuthContext, user: AuthUser, id: string) => {
  const { event, container } = await loadEditableTimelineEvent(context, user, id);
  if (event.event_source !== 'manual') {
    throw FunctionalError('A derived event cannot be deleted, hide it instead', { id });
  }
  await deleteTimelineDocuments([event.internal_id]);
  await afterTimelineChange(context, user, container, 'manual', [event.internal_id]);
  return event.internal_id;
};

const setAnalystFlag = async (context: AuthContext, user: AuthUser, id: string, field: 'pinned' | 'hidden', value: boolean) => {
  const { event, container } = await loadEditableTimelineEvent(context, user, id);
  const analystFields = new Set<TimelineAnalystField>(event.analyst_fields ?? []);
  if (event.event_source === 'derived') analystFields.add(field);
  const doc = docFromStored(event, container, { [field]: value, analyst_fields: Array.from(analystFields) });
  await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, [doc]);
  await afterTimelineChange(context, user, container, 'annotation', [event.internal_id]);
  return reloadEvent(context, user, event.internal_id);
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
  if (input.hidden_kinds) patch.hidden_kinds = Array.from(new Set(input.hidden_kinds));
  const settings = await upsertTimelineSettings(context, container, patch);
  await publishTimelineUpdate({ container_id: container.internal_id, update_type: 'settings', changed_event_ids: [], anchors: container[ATTRIBUTE_TIMELINE_ANCHORS] ?? null }, user);
  return settingsWithDefaults(container.internal_id, settings);
};

export const regenerateTimeline = async (context: AuthContext, user: AuthUser, containerId: string): Promise<TimelineRegenerationResult | null> => {
  const container = await loadEditableTimelineContainer(context, user, containerId);
  return regenerateContainerTimeline(context, container.internal_id, { wait: true });
};

/**
 * Import the analyst contributions of a timeline STIX extension: manual events are created
 * (idempotent on their STIX id), annotations are applied to the derived events they target or kept
 * pending until the derivation produces them.
 */
export const importTimelineExtension = async (context: AuthContext, user: AuthUser, containerId: string, rawExtension: string) => {
  const container = await loadEditableTimelineContainer(context, user, containerId);
  let extension: StixTimelineExtension;
  try {
    extension = JSON.parse(rawExtension);
  } catch {
    throw FunctionalError('Invalid timeline extension');
  }
  const events = Array.isArray(extension.events) ? extension.events : [];
  const annotations = Array.isArray(extension.annotations) ? extension.annotations : [];
  const refs = Array.from(new Set([
    ...events.flatMap((e) => [e.element_ref, e.created_by_ref, ...(e.object_marking_refs ?? [])]),
    ...annotations.map((a) => a.element_ref),
  ].filter((ref): ref is string => !!ref)));
  const resolved = refs.length > 0
    ? await internalFindByIds(context, user, refs, { toMap: true, mapWithAllIds: true, baseData: true }) as unknown as Record<string, AnyStoreElement>
    : {};
  const access = containerAccessFields(container);
  const allowedMarkings = new Set(user.allowed_marking.map((m) => m.internal_id));
  // A manual event travelling back to a platform that already knows it (same STIX id, or the id it
  // was originally imported from) must update it, never duplicate it.
  const storedManual = (await loadStoredTimelineEvents(context, container.internal_id)).filter((e) => e.event_source === 'manual');
  const storedByStandardId = new Map(storedManual.map((e) => [e.standard_id as string, e]));
  const storedByExternalId = new Map(storedManual.filter((e) => !!e.external_id).map((e) => [e.external_id as string, e]));
  const findKnownEvent = (event: StixTimelineExtensionEvent) => {
    const keys = [event.id, event.external_id].filter((key): key is string => !!key);
    for (let index = 0; index < keys.length; index += 1) {
      const known = storedByStandardId.get(keys[index]) ?? storedByExternalId.get(keys[index]);
      if (known) return known;
    }
    return null;
  };
  // An event is never declassified: when one of its markings is unknown here or not allowed to the user, it is skipped
  const importableMarkings = (event: StixTimelineExtensionEvent): string[] | null => {
    const markingIds = (event.object_marking_refs ?? []).map((ref) => resolved[ref]?.internal_id);
    return markingIds.every((id) => !!id && (isBypassUser(user) || allowedMarkings.has(id))) ? markingIds as string[] : null;
  };
  const candidates = events.filter((e) => e.title && e.event_time).map((event) => ({ event, markings: importableMarkings(event) }));
  const skipped = candidates.filter((candidate) => candidate.markings === null).length;
  if (skipped > 0) {
    logApp.warn('[TIMELINE] Contributions skipped on import: markings unknown or not allowed', { containerId: container.internal_id, skipped });
  }
  const docs = candidates.filter((candidate) => candidate.markings !== null).map(({ event, markings }) => {
    validateWindow(event.event_time, event.event_end_time);
    const existing = findKnownEvent(event);
    const internalId = existing?.internal_id ?? computeManualEventId(container.internal_id, event.external_id ?? event.id);
    const element = event.element_ref ? resolved[event.element_ref] : null;
    return buildTimelineEventDoc({
      internal_id: internalId,
      container_id: container.internal_id,
      name: event.title,
      description: event.description,
      event_time: new Date(event.event_time).toISOString(),
      event_end_time: event.event_end_time ? new Date(event.event_end_time).toISOString() : null,
      time_precision: event.precision ?? 'exact',
      lane: event.lane ?? 'custom',
      kind: event.kind ?? 'milestone',
      event_source: 'manual',
      rule_id: null,
      element_id: element?.internal_id ?? null,
      element_type: element?.entity_type ?? null,
      pinned: event.pinned ?? false,
      hidden: event.hidden ?? false,
      annotation: event.annotation ?? null,
      confidence: event.confidence ?? null,
      ordering_hint: event.ordering_hint ?? null,
      analyst_fields: [],
      external_id: existing ? (existing.external_id ?? null) : (event.external_id ?? event.id),
      markings: [...(markings as string[]), ...access.markings],
      created_by_id: event.created_by_ref ? resolved[event.created_by_ref]?.internal_id : null,
      creator_ids: existing ? Array.from(new Set([...creatorIdsOf(existing), user.id])) : [user.id],
      restricted_members: access.restricted_members,
    }, existing);
  });
  if (docs.length > 0) {
    await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_TIMELINE_EVENT, docs);
  }
  const pending: TimelinePendingAnnotation[] = annotations
    .filter((a) => a.element_ref && resolved[a.element_ref] && a.rule_id && a.kind)
    .map((a) => ({
      event_id: computeDerivedEventId(container.internal_id, a.rule_id, resolved[a.element_ref].internal_id, a.kind),
      pinned: a.pinned,
      hidden: a.hidden,
      annotation: a.annotation,
      ordering_hint: a.ordering_hint,
    }));
  if (pending.length > 0) {
    const settings = await loadTimelineSettings(context, container.internal_id);
    const byId = new Map((settings?.pending_annotations ?? []).map((a) => [a.event_id, a]));
    pending.forEach((annotation) => byId.set(annotation.event_id, annotation));
    await upsertTimelineSettings(context, container, { pending_annotations: Array.from(byId.values()) }, settings ?? null);
  }
  return regenerateContainerTimeline(context, container.internal_id, { wait: true });
};
// endregion
