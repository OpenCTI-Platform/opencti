import * as R from 'ramda';
import conf from '../../config/conf';
import type { AuthContext } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { SYSTEM_USER } from '../../utils/access';
import { fullEntitiesList, fullRelationsList, internalFindByIds } from '../../database/middleware-loader';
import { getEntitiesListFromCache } from '../../database/cache';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, BASE_TYPE_RELATION, buildRefRelationKey } from '../../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_HAS_COVERED } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_HISTORY, ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { READ_INDEX_HISTORY } from '../../database/utils';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ENTITY_TYPE_CONTAINER_TASK } from '../task/task-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_SECURITY_COVERAGE, RELATION_COVERED } from '../securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_SECURITY_COVERAGE_RESULT, RELATION_RESULT_OF } from '../securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { FilterMode, OrderingMode, StatusScope } from '../../generated/graphql';
import { type BasicStoreEntityEntitySetting, ENTITY_TYPE_ENTITY_SETTING } from '../entitySetting/entitySetting-types';
import { getWorkflowDefinition } from '../workflow/domain/workflow-domain';
import { computeStateOrder } from '../workflow/domain/workflow-ordering';
import type {
  TimelineContainerData,
  TimelineDerivationInput,
  TimelineElementData,
  TimelineFileData,
  TimelineHistoryChange,
  TimelineHistoryEntry,
  TimelineKillChainPhaseData,
  TimelineSoftSources,
  TimelineStatusData,
} from './timeline-rules';

// Bounds protecting large cases: the timeline of a case is built from at most this many elements of each family.
export const TIMELINE_MAX_OBJECTS = conf.get('timeline_manager:max_objects') ?? 5000;
const TIMELINE_MAX_HISTORY = conf.get('timeline_manager:max_history_entries') ?? 5000;
const TIMELINE_MAX_RELATED = conf.get('timeline_manager:max_related_elements') ?? 1000;

/** Truncation of one derivation input: every bounded read asks for one item more than its bound to know it was reached. */
interface TimelineReadBounds {
  truncated: boolean;
}

export const capTimelineRead = <T>(bounds: TimelineReadBounds, items: T[], max: number): T[] => {
  if (items.length <= max) return items;
  bounds.truncated = true;
  return items.slice(0, max);
};

// Types owned by other modules, consumed only when they are registered on the platform (soft checks).
export const SOFT_TYPE_HUNT = 'Hunt';
export const SOFT_TYPE_HUNT_RUN = 'Hunt-Run';
export const SOFT_TYPE_INVESTIGATION_RUN = 'InvestigationRun';
export const SOFT_RELATION_DEPLOYED_ON = 'deployed-on';

export const isTimelineSoftTypeAvailable = (type: string): boolean => {
  return schemaAttributesDefinition.getRegisteredTypes().includes(type);
};

const SOFT_EXTRA_KEYS = [
  // security coverage results and has-covered relationships
  'coverage_last_result', 'coverage_valid_from', 'coverage_valid_to', 'coverage_information',
  // hunt runs
  'hunt_id', 'hunt_run_status', 'hunt_run_trigger', 'incident_id', 'hits_count', 'verdict', 'time_window_start', 'time_window_end',
  // investigation runs
  'run_status', 'run_trigger', 'timeline', 'steps', 'goal_plan', 'evidence',
  // deployed-on relationships
  'deployment_status', 'deployed_at', 'removed_at', 'hit_count', 'last_hit_at', 'validation_status', 'last_validation_at',
  // shared
  'status', 'started_at', 'completed_at',
];

type AnyStoreElement = BasicStoreBase & Record<string, any>;

const asArray = (value: unknown): string[] => {
  if (value === null || value === undefined) return [];
  return (Array.isArray(value) ? value : [value]).filter((v) => typeof v === 'string' && v.length > 0) as string[];
};

// Read with its relations, a document carries a ref in its rel_ key; read without them (the default of the engine), the
// markings, labels and author come back as doc values under the relation type: both are read, whatever loaded the element
export const timelineRefIds = (element: Record<string, any>, relationType: string): string[] => Array.from(new Set([
  ...asArray(element[buildRefRelationKey(relationType)]),
  ...asArray(element[relationType]),
]));

const dateString = (value: unknown): string | null => {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
};

export const toTimelineElement = (element: AnyStoreElement, opts: { labels?: Map<string, string> } = {}): TimelineElementData => {
  const isRelation = element.base_type === BASE_TYPE_RELATION;
  const relation = element as unknown as BasicStoreRelation;
  const extra: Record<string, unknown> = {};
  SOFT_EXTRA_KEYS.forEach((key) => {
    if (element[key] !== undefined && element[key] !== null) extra[key] = element[key];
  });
  const labelIds = timelineRefIds(element, RELATION_OBJECT_LABEL);
  return {
    id: element.internal_id,
    standard_id: element.standard_id,
    entity_type: element.entity_type,
    name: extractEntityRepresentativeName(element),
    markings: timelineRefIds(element, RELATION_OBJECT_MARKING),
    labels: opts.labels ? labelIds.map((id) => opts.labels?.get(id)).filter((v): v is string => !!v) : undefined,
    created: dateString(element.created),
    created_at: dateString(element.created_at),
    updated_at: dateString(element.updated_at),
    creator_ids: asArray(element.creator_id),
    created_by_id: timelineRefIds(element, RELATION_CREATED_BY)[0] ?? null,
    confidence: element.confidence ?? null,
    description: element.description ?? element.x_opencti_description ?? null,
    first_seen: dateString(element.first_seen),
    last_seen: dateString(element.last_seen),
    start_time: dateString(element.start_time),
    stop_time: dateString(element.stop_time),
    first_observed: dateString(element.first_observed),
    last_observed: dateString(element.last_observed),
    number_observed: element.number_observed ?? null,
    attribute_count: element.attribute_count ?? null,
    valid_from: dateString(element.valid_from),
    valid_until: dateString(element.valid_until),
    published: dateString(element.published),
    due_date: dateString(element.due_date),
    workflow_id: element.x_opencti_workflow_id ?? null,
    kill_chain_phase_ids: timelineRefIds(element, RELATION_KILL_CHAIN_PHASE),
    relationship_type: isRelation ? element.entity_type : undefined,
    from_id: isRelation ? relation.fromId : undefined,
    to_id: isRelation ? relation.toId : undefined,
    from_type: isRelation ? relation.fromType : undefined,
    to_type: isRelation ? relation.toType : undefined,
    from_name: isRelation ? relation.fromName : undefined,
    to_name: isRelation ? relation.toName : undefined,
    source_name: element.source_name,
    external_id: element.external_id,
    url: element.url,
    extra,
  };
};

const parseTranslated = (translated: string | undefined): Record<string, string> => {
  if (!translated) return {};
  try {
    return JSON.parse(translated);
  } catch {
    return {};
  }
};

export const toTimelineHistoryEntry = (log: AnyStoreElement): TimelineHistoryEntry => {
  const contextData = log.context_data ?? {};
  const changes: TimelineHistoryChange[] = (contextData.history_changes ?? []).map((change: any) => {
    const toValues = (values: Array<{ raw: string; translated?: string }> | undefined) => (values ?? []).map((v) => {
      const translatedMap = parseTranslated(v.translated);
      return { raw: v.raw, name: translatedMap[v.raw] };
    });
    return { field: change.field, added: toValues(change.changes_added), removed: toValues(change.changes_removed) };
  });
  return {
    id: log.internal_id,
    timestamp: dateString(log.timestamp) ?? dateString(log.created_at) ?? '',
    event_scope: log.event_scope ?? '',
    entity_id: contextData.id ?? '',
    entity_type: contextData.entity_type ?? '',
    entity_name: contextData.entity_name ?? '',
    message: contextData.message ?? '',
    user_id: log.user_id ?? null,
    markings: timelineRefIds(log, RELATION_OBJECT_MARKING),
    changes,
  };
};

const toFiles = (container: AnyStoreElement): TimelineFileData[] => {
  return (container.x_opencti_files ?? []).map((file: any) => ({
    id: file.id,
    name: file.name,
    version: dateString(file.version) ?? '',
    mime_type: file.mime_type,
    markings: asArray(file.file_markings),
  }));
};

/**
 * Entries read from the newest one, capped to their bound and given back in chronological order: beyond its bound, the
 * history of a case keeps its newest entries (the latest transitions, completions and assignments drive the anchors).
 */
export const keepNewestTimelineEntries = <T>(bounds: TimelineReadBounds, newestFirst: T[], max: number): T[] => {
  return capTimelineRead(bounds, newestFirst, max).reverse();
};

const findHistory = async (context: AuthContext, bounds: TimelineReadBounds, filters: any, maxSize: number) => {
  const logs = await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_HISTORY], {
    indices: [READ_INDEX_HISTORY],
    filters,
    noFiltersChecking: true,
    orderBy: ['timestamp'],
    orderMode: OrderingMode.Desc,
    maxSize: maxSize + 1,
  } as any);
  return keepNewestTimelineEntries(bounds, logs, maxSize).map((log) => toTimelineHistoryEntry(log as AnyStoreElement));
};

const findBoundedEntities = async <T extends BasicStoreEntity>(
  context: AuthContext,
  bounds: TimelineReadBounds,
  types: string[],
  filters: any,
  maxSize: number,
): Promise<T[]> => {
  const items = await fullEntitiesList<T>(context, SYSTEM_USER, types, { filters, noFiltersChecking: true, maxSize: maxSize + 1 } as any);
  return capTimelineRead(bounds, items, maxSize);
};

const findBoundedRelations = async (
  context: AuthContext,
  bounds: TimelineReadBounds,
  types: string | string[],
  args: Record<string, unknown>,
  maxSize: number,
): Promise<BasicStoreRelation[]> => {
  const items = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, types, { ...args, maxSize: maxSize + 1 } as any);
  return capTimelineRead(bounds, items, maxSize);
};

const findContainersReferencing = async <T extends BasicStoreEntity>(context: AuthContext, bounds: TimelineReadBounds, types: string[], ids: string[], maxSize: number) => {
  if (ids.length === 0) return [];
  const filters = { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(RELATION_OBJECT)], values: ids }], filterGroups: [] };
  return findBoundedEntities<T>(context, bounds, types, filters, maxSize);
};

interface TimelineStatusSource {
  internal_id: string;
  name: string;
  order: number;
  type: string;
  scope?: string | null;
  template_id?: string | null;
}

/**
 * Terminal states of a workflow defined by transitions: the states that no forward transition leaves. The order of a
 * state is its longest distance from the initial state, so a forward transition always leads to a higher order, and a
 * transition back to an earlier state (a reopening) does not keep a state from being terminal. A branching workflow
 * can end at a lower order than its longest branch.
 */
export const terminalWorkflowStates = (definition: { initialState: string; transitions: Array<{ from: string | string[] | null; to: string | null }> }): Set<string> => {
  const order = computeStateOrder(definition.initialState, definition.transitions);
  const leftForward = new Set<string>();
  definition.transitions.forEach((transition) => {
    const targetOrder = transition.to ? order.get(transition.to) : undefined;
    if (targetOrder === undefined) return;
    asArray(transition.from).forEach((from) => {
      const fromOrder = order.get(from);
      if (fromOrder !== undefined && targetOrder > fromOrder) leftForward.add(from);
    });
  });
  return new Set(Array.from(order.keys()).filter((state) => !leftForward.has(state)));
};

export const buildTimelineStatuses = (
  statuses: TimelineStatusSource[],
  terminalStatesByType: Map<string, Set<string>> = new Map(),
): Map<string, TimelineStatusData> => {
  // One type has one workflow per scope (the case workflow, the request access workflow of requests for information)
  const workflowOf = (status: TimelineStatusSource) => `${status.type}|${status.scope ?? StatusScope.Global}`;
  const maxOrderByWorkflow = new Map<string, number>();
  statuses.forEach((status) => {
    const current = maxOrderByWorkflow.get(workflowOf(status));
    if (current === undefined || status.order > current) maxOrderByWorkflow.set(workflowOf(status), status.order);
  });
  const map = new Map<string, TimelineStatusData>();
  statuses.forEach((status) => {
    // The statuses of a type whose workflow is defined by transitions are its states (global scope): its terminal states
    // are final. Otherwise the last status of the workflow (highest order) is its closed category.
    const terminalStates = (status.scope ?? StatusScope.Global) === StatusScope.Global ? terminalStatesByType.get(status.type) : undefined;
    map.set(status.internal_id, {
      id: status.internal_id,
      name: status.name,
      order: status.order,
      type: status.type,
      is_final: terminalStates
        ? !!status.template_id && terminalStates.has(status.template_id)
        : maxOrderByWorkflow.get(workflowOf(status)) === status.order,
    });
  });
  return map;
};

const loadStatuses = async (context: AuthContext): Promise<Map<string, TimelineStatusData>> => {
  const statuses = await getEntitiesListFromCache<TimelineStatusSource & BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_STATUS);
  // Only the few types with a workflow defined by transitions need their published definition
  const statusTypes = new Set(statuses.map((status) => status.type));
  const entitySettings = await getEntitiesListFromCache<BasicStoreEntityEntitySetting>(context, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING);
  const workflowTypes = entitySettings.filter((setting) => !!setting.workflow_id && statusTypes.has(setting.target_type)).map((setting) => setting.target_type);
  const terminalStatesByType = new Map<string, Set<string>>();
  for (let index = 0; index < workflowTypes.length; index += 1) {
    const definition = await getWorkflowDefinition(context, SYSTEM_USER, workflowTypes[index]);
    if (definition) terminalStatesByType.set(workflowTypes[index], terminalWorkflowStates(definition));
  }
  return buildTimelineStatuses(statuses, terminalStatesByType);
};

export const isContainerClosed = async (context: AuthContext, container: AnyStoreElement): Promise<boolean> => {
  const statusId = container.x_opencti_workflow_id;
  if (!statusId) return false;
  const statuses = await loadStatuses(context);
  return statuses.get(statusId)?.is_final === true;
};

const loadSoftSources = async (
  context: AuthContext,
  bounds: TimelineReadBounds,
  container: AnyStoreElement,
  entities: TimelineElementData[],
): Promise<TimelineSoftSources> => {
  const soft: TimelineSoftSources = { coverageResults: [], coverageRelationships: [], huntRuns: [], deployments: [], investigationRuns: [] };
  const containerId = container.internal_id;
  const toElement = (element: BasicStoreBase) => toTimelineElement(element as AnyStoreElement);
  // Security coverage (OpenAEV): coverages targeting the container, their results and covered techniques
  if (isTimelineSoftTypeAvailable(ENTITY_TYPE_SECURITY_COVERAGE) && isTimelineSoftTypeAvailable(ENTITY_TYPE_SECURITY_COVERAGE_RESULT)) {
    const coverageFilters = { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(RELATION_COVERED)], values: [containerId] }], filterGroups: [] };
    const coverages = await findBoundedEntities<BasicStoreEntity>(context, bounds, [ENTITY_TYPE_SECURITY_COVERAGE], coverageFilters, TIMELINE_MAX_RELATED);
    const coverageIds = coverages.map((c) => c.internal_id);
    if (coverageIds.length > 0) {
      const resultFilters = { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(RELATION_RESULT_OF)], values: coverageIds }], filterGroups: [] };
      const results = await findBoundedEntities<BasicStoreEntity>(context, bounds, [ENTITY_TYPE_SECURITY_COVERAGE_RESULT], resultFilters, TIMELINE_MAX_RELATED);
      soft.coverageResults = results.map(toElement);
      const covered = await findBoundedRelations(context, bounds, RELATION_HAS_COVERED, { fromId: coverageIds }, TIMELINE_MAX_RELATED);
      soft.coverageRelationships = covered.map(toElement);
    }
  }
  // Hunt runs (innovation 01) of the hunts in scope, and the runs that opened the incident
  const huntIds = entities.filter((e) => e.entity_type === SOFT_TYPE_HUNT).map((e) => e.id);
  if (isTimelineSoftTypeAvailable(SOFT_TYPE_HUNT_RUN)) {
    const huntRunFilters: any[] = [{ key: ['incident_id'], values: [containerId] }];
    if (huntIds.length > 0) huntRunFilters.push({ key: ['hunt_id'], values: huntIds });
    const runFilters = { mode: FilterMode.Or, filters: huntRunFilters, filterGroups: [] };
    const runs = await findBoundedEntities<BasicStoreEntity>(context, bounds, [SOFT_TYPE_HUNT_RUN], runFilters, TIMELINE_MAX_RELATED);
    soft.huntRuns = runs.map(toElement);
  }
  // Deployments (innovation 10) of the indicators in scope
  const indicatorIds = entities.filter((e) => e.entity_type === ENTITY_TYPE_INDICATOR).map((e) => e.id);
  if (indicatorIds.length > 0 && isTimelineSoftTypeAvailable(SOFT_RELATION_DEPLOYED_ON)) {
    const deployments = await findBoundedRelations(context, bounds, SOFT_RELATION_DEPLOYED_ON, { fromId: indicatorIds }, TIMELINE_MAX_RELATED);
    soft.deployments = deployments.map(toElement);
  }
  // Case Autopilot investigation runs (innovation 02) on the container, known by any of its ids
  if (isTimelineSoftTypeAvailable(SOFT_TYPE_INVESTIGATION_RUN)) {
    const containerIds = asArray([containerId, container.standard_id]);
    const runFilters = {
      mode: FilterMode.Or,
      filters: [
        { key: ['case_ids'], values: containerIds },
        { key: ['subject_id'], values: [containerId] },
      ],
      filterGroups: [],
    };
    const runs = await findBoundedEntities<BasicStoreEntity>(context, bounds, [SOFT_TYPE_INVESTIGATION_RUN], runFilters, TIMELINE_MAX_RELATED);
    soft.investigationRuns = runs.map(toElement);
  }
  return soft;
};

export interface TimelineLoadResult {
  input: TimelineDerivationInput;
  truncated: boolean;
}

/**
 * Read everything the derivation rules need for one container, as the system user.
 * Access filtering happens when events are read, never at derivation time, so that one
 * timeline serves every viewer and each viewer only gets what he can see.
 */
export const loadTimelineDerivationInput = async (context: AuthContext, container: AnyStoreElement): Promise<TimelineLoadResult> => {
  const containerId = container.internal_id;
  const isCase = container.entity_type !== ENTITY_TYPE_INCIDENT;
  const bounds: TimelineReadBounds = { truncated: false };
  let entities: AnyStoreElement[];
  let relationships: AnyStoreElement[];
  if (isCase) {
    // Knowledge of a case: its object refs
    const objectIds = capTimelineRead(bounds, asArray(container[buildRefRelationKey(RELATION_OBJECT)]), TIMELINE_MAX_OBJECTS);
    const objects = await internalFindByIds(context, SYSTEM_USER, objectIds) as unknown as AnyStoreElement[];
    entities = objects.filter((o) => o.base_type !== BASE_TYPE_RELATION);
    relationships = objects.filter((o) => o.base_type === BASE_TYPE_RELATION);
  } else {
    // Knowledge of an incident: its relationships and the entities on the other side
    const related = await findBoundedRelations(context, bounds, [ABSTRACT_STIX_CORE_RELATIONSHIP], { fromOrToId: containerId }, TIMELINE_MAX_OBJECTS);
    relationships = related as unknown as AnyStoreElement[];
    const otherIds = R.uniq(related.map((r) => (r.fromId === containerId ? r.toId : r.fromId)));
    entities = otherIds.length > 0 ? await internalFindByIds(context, SYSTEM_USER, otherIds) as unknown as AnyStoreElement[] : [];
  }
  // Sightings of the elements in scope: by a security platform, the platform detections of its indicators; at another
  // element in scope (a victim, a location, a system), adversary activity. Their sightings anywhere else belong to other
  // incidents and stay out, like the sightings explicitly added to a case, which come with its objects.
  const indicatorIds = entities.filter((e) => e.entity_type === ENTITY_TYPE_INDICATOR).map((e) => e.internal_id);
  const entityIds = entities.map((e) => e.internal_id);
  const sightedIds = isCase ? entityIds : [containerId, ...entityIds];
  const [platformSightings, inScopeSightings] = await Promise.all([
    indicatorIds.length > 0
      ? findBoundedRelations(context, bounds, STIX_SIGHTING_RELATIONSHIP, { fromId: indicatorIds, toTypes: [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM] }, TIMELINE_MAX_RELATED)
      : Promise.resolve([]),
    entityIds.length > 0
      ? findBoundedRelations(context, bounds, STIX_SIGHTING_RELATIONSHIP, { fromId: sightedIds, toId: entityIds }, TIMELINE_MAX_RELATED)
      : Promise.resolve([]),
  ]);
  const known = new Set(relationships.map((r) => r.internal_id));
  const sightings = [...platformSightings, ...inScopeSightings].filter((sighting) => {
    if (known.has(sighting.internal_id)) return false;
    known.add(sighting.internal_id);
    return true;
  });
  relationships = [...relationships, ...(sightings as unknown as AnyStoreElement[])];
  // Tasks, notes and opinions referencing the container
  const [tasks, notes, opinions] = await Promise.all([
    findContainersReferencing<BasicStoreEntity>(context, bounds, [ENTITY_TYPE_CONTAINER_TASK], [containerId], TIMELINE_MAX_RELATED),
    findContainersReferencing<BasicStoreEntity>(context, bounds, [ENTITY_TYPE_CONTAINER_NOTE], [containerId], TIMELINE_MAX_RELATED),
    findContainersReferencing<BasicStoreEntity>(context, bounds, [ENTITY_TYPE_CONTAINER_OPINION], [containerId], TIMELINE_MAX_RELATED),
  ]);
  // Reports: contained by a case, containing an incident
  const reports = isCase
    ? entities.filter((e) => e.entity_type === ENTITY_TYPE_CONTAINER_REPORT)
    : await findContainersReferencing<BasicStoreEntity>(context, bounds, [ENTITY_TYPE_CONTAINER_REPORT], [containerId], TIMELINE_MAX_RELATED) as AnyStoreElement[];
  // Meta: kill chain phases of the techniques, labels of the tasks, external references of the container
  const killChainPhaseIds = R.uniq(entities.flatMap((e) => timelineRefIds(e, RELATION_KILL_CHAIN_PHASE)));
  const labelIds = R.uniq(tasks.flatMap((t) => timelineRefIds(t, RELATION_OBJECT_LABEL)));
  const externalReferenceIds = capTimelineRead(bounds, asArray(container[buildRefRelationKey(RELATION_EXTERNAL_REFERENCE)]), TIMELINE_MAX_RELATED);
  const [killChainPhases, labels, externalReferences] = await Promise.all([
    killChainPhaseIds.length > 0 ? internalFindByIds(context, SYSTEM_USER, killChainPhaseIds, { type: ENTITY_TYPE_KILL_CHAIN_PHASE }) : [],
    labelIds.length > 0 ? internalFindByIds(context, SYSTEM_USER, labelIds, { type: ENTITY_TYPE_LABEL }) : [],
    externalReferenceIds.length > 0 ? internalFindByIds(context, SYSTEM_USER, externalReferenceIds) : [],
  ]) as unknown as [AnyStoreElement[], AnyStoreElement[], AnyStoreElement[]];
  const labelsMap = new Map(labels.map((l) => [l.internal_id, l.value as string]));
  const killChainPhasesMap = new Map<string, TimelineKillChainPhaseData>(killChainPhases.map((k) => [k.internal_id, {
    id: k.internal_id,
    phase_name: k.phase_name,
    kill_chain_name: k.kill_chain_name,
    order: k.x_opencti_order ?? 0,
  }]));
  // History: the container itself (status, assignees, objects, files, merges) and merges of its objects
  const objectIds = entities.map((e) => e.internal_id);
  const containerHistoryFilters = { mode: FilterMode.And, filters: [{ key: ['context_data.id'], values: [containerId] }], filterGroups: [] };
  const history = await findHistory(context, bounds, containerHistoryFilters, TIMELINE_MAX_HISTORY);
  const objectMerges = objectIds.length > 0 ? await findHistory(context, bounds, {
    mode: FilterMode.And,
    filters: [
      { key: ['event_scope'], values: ['merge'] },
      { key: ['context_data.id'], values: objectIds },
    ],
    filterGroups: [],
  }, TIMELINE_MAX_RELATED) : [];
  const taskIds = tasks.map((t) => t.internal_id);
  // Task updates only: the task rule reads the workflow transitions, older entries without structured changes fall back to the update date
  const taskHistory = taskIds.length > 0 ? await findHistory(context, bounds, {
    mode: FilterMode.And,
    filters: [
      { key: ['context_data.id'], values: taskIds },
      { key: ['event_scope'], values: ['update'] },
    ],
    filterGroups: [],
  }, TIMELINE_MAX_HISTORY) : [];
  const statuses = await loadStatuses(context);
  const toElement = (e: AnyStoreElement) => toTimelineElement(e);
  const entitiesData = entities.map(toElement);
  const containerData: TimelineContainerData = {
    ...toTimelineElement(container),
    is_case: isCase,
    files: toFiles(container),
  };
  const soft = await loadSoftSources(context, bounds, container, entitiesData);
  return {
    truncated: bounds.truncated,
    input: {
      container: containerData,
      entities: entitiesData,
      relationships: relationships.map(toElement),
      tasks: tasks.map((t) => toTimelineElement(t as AnyStoreElement, { labels: labelsMap })),
      notes: notes.map((n) => toElement(n as AnyStoreElement)),
      opinions: opinions.map((o) => toElement(o as AnyStoreElement)),
      reports: reports.map((r) => toElement(r as AnyStoreElement)),
      externalReferences: externalReferences.map(toElement),
      history: [...history, ...objectMerges],
      taskHistory,
      killChainPhases: killChainPhasesMap,
      statuses,
      soft,
      securityPlatformType: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM,
    },
  };
};
