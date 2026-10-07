import { Promise as BluePromise } from 'bluebird';
import * as jsonpatch from 'fast-json-patch';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent, UpdateEvent } from '../types/event';
import type { BasicStoreEntity, BasicStoreRelation } from '../types/store';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { fetchStreamEventsRangeFromEventId, fetchStreamInfo } from '../database/stream/stream-handler';
import { redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';
import { fullEntitiesList, fullRelationsList, internalFindByIds } from '../database/middleware-loader';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { RELATION_CREATED_BY, RELATION_EXTERNAL_REFERENCE, RELATION_KILL_CHAIN_PHASE, RELATION_OBJECT, RELATION_OBJECT_LABEL } from '../schema/stixRefRelationship';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL } from '../schema/stixMetaObject';
import { ENTITY_TYPE_STATUS } from '../schema/internalObject';
import { getEntitiesListFromCache } from '../database/cache';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_TASK } from '../modules/task/task-types';
import { FilterMode, FilterOperator } from '../generated/graphql';
import {
  ATTRIBUTE_TIMELINE_ANCHORS,
  ENTITY_TYPE_TIMELINE_EVENT,
  ENTITY_TYPE_TIMELINE_SETTINGS,
  isTimelineContainerType,
  TIMELINE_CONTAINER_TYPES,
} from '../modules/timeline/timeline-types';
import { regenerateContainerTimeline } from '../modules/timeline/timeline-engine';
import { RULE_INVESTIGATION_RUN } from '../modules/timeline/timeline-rules';
import { SOFT_RELATION_DEPLOYED_ON, timelineRefIds } from '../modules/timeline/timeline-loader';
import { ATTRIBUTE_COVERED, ENTITY_TYPE_SECURITY_COVERAGE, RELATION_COVERED } from '../modules/securityCoverage/securityCoverage-types';
import { ATTRIBUTE_RESULT_OF } from '../modules/securityCoverage/securityCoverageResult/securityCoverageResult-types';
import { type BasicStoreEntityEntitySetting, ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from '../modules/workflow/types/workflow-types';
import {
  acknowledgeTimelineRegeneration,
  claimDueTimelineRegenerations,
  clearTimelineRegenerationAttempts,
  enqueueTimelineRegeneration,
  getTimelineConsistencyLastRun,
  retryTimelineRegeneration,
  setTimelineConsistencyLastRun,
} from '../modules/timeline/timeline-queue';

const TIMELINE_MANAGER_ID = 'TIMELINE_MANAGER';
const TIMELINE_MANAGER_LABEL = 'Timeline manager';
const TIMELINE_MANAGER_CONTEXT = 'timeline_manager';
const TIMELINE_MANAGER_STATE = 'timeline_manager';

const TIMELINE_MANAGER_ENABLED = booleanConf('timeline_manager:enabled', true);
const TIMELINE_MANAGER_LOCK_KEY = conf.get('timeline_manager:lock_key') ?? 'timeline_manager_lock';
const TIMELINE_MANAGER_INTERVAL = conf.get('timeline_manager:interval') ?? 10000;
const TIMELINE_MANAGER_STREAM_BATCH_SIZE = conf.get('timeline_manager:stream_batch_size') ?? 1000;
// Upper bound of stream batches read per run, so that the queue keeps being served under heavy ingestion
const TIMELINE_MANAGER_MAX_STREAM_BATCHES = conf.get('timeline_manager:max_stream_batches_per_run') ?? 20;
const TIMELINE_MANAGER_REGENERATION_BATCH = conf.get('timeline_manager:regeneration_batch_size') ?? 20;
const TIMELINE_MANAGER_MAX_CONCURRENCY = conf.get('timeline_manager:max_concurrency') ?? 2;
// Containers impacted through a shared element are read and queued page by page: none is dropped, each page is bounded
const TIMELINE_MANAGER_IMPACTED_PAGE_SIZE = conf.get('timeline_manager:impacted_containers_page_size') ?? 1000;
// Nightly consistency pass (UTC hour), and the age after which a timeline is regenerated even without any change
const TIMELINE_MANAGER_CONSISTENCY_HOUR = conf.get('timeline_manager:consistency_hour') ?? 2;
const TIMELINE_MANAGER_CONSISTENCY_MAX_AGE_DAYS = conf.get('timeline_manager:consistency_max_age_days') ?? 30;
const DAY_MS = 24 * 60 * 60 * 1000;

const CONTAINERS_REFERENCING_TYPES = [ENTITY_TYPE_CONTAINER_TASK, ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_CONTAINER_REPORT];

interface ImpactCollector {
  containers: Set<string>;
  // elements whose containing cases are impacted
  contained: Set<string>;
  // entities whose related incidents are impacted
  related: Set<string>;
  // stix ids referenced by tasks, notes, opinions and reports
  references: Set<string>;
  // labels read through the tasks of the cases (containment)
  labels: Set<string>;
  // kill chain phases ordering the techniques of the cases
  killChainPhases: Set<string>;
  // external references of the containers (publications)
  externalReferences: Set<string>;
  // security coverages whose covered containers are impacted (through their results and has-covered relationships)
  coverages: Set<string>;
}

export const newImpactCollector = (): ImpactCollector => ({
  containers: new Set(),
  contained: new Set(),
  related: new Set(),
  references: new Set(),
  labels: new Set(),
  killChainPhases: new Set(),
  externalReferences: new Set(),
  coverages: new Set(),
});

const idValues = (value: unknown): string[] => (Array.isArray(value) ? value : [value]).filter((v): v is string => typeof v === 'string' && v.length > 0);

/** An updated object before its update, rebuilt from the reverse patch of the event; null when the update changed none of `fields`. */
const previousVersion = (event: SseEvent<DataEvent>, fields: string[]): Record<string, unknown> | null => {
  const reversePatch = (event.data as Partial<UpdateEvent>)?.context?.reverse_patch;
  if (event.data?.type !== 'update' || !Array.isArray(reversePatch) || reversePatch.length === 0) return null;
  const changesField = (path: string) => fields.some((field) => path === `/${field}` || path.startsWith(`/${field}/`));
  if (!reversePatch.some((operation) => typeof operation?.path === 'string' && changesField(operation.path))) return null;
  try {
    const { newDocument: previous } = jsonpatch.applyPatch(structuredClone(event.data.data), reversePatch, false, false);
    return previous as Record<string, unknown>;
  } catch (error) {
    // A patch that no longer applies cannot name the previous values: the nightly consistency pass catches up
    logApp.debug('[TIMELINE] Previous version of an update not rebuilt', { cause: error });
    return null;
  }
};

/** The refs of an updated object before its update (none when the update left them unchanged). */
const previousObjectRefs = (event: SseEvent<DataEvent>): string[] => idValues(previousVersion(event, ['object_refs'])?.object_refs);

// Fields through which the loader selects the soft-check sources of a container (see loadSoftSources)
const SOFT_SOURCE_CONTAINER_FIELDS = ['subject_id', 'case_ids', 'incident_id', ATTRIBUTE_COVERED];
const SOFT_SOURCE_FIELDS = [...SOFT_SOURCE_CONTAINER_FIELDS, 'hunt_id', ATTRIBUTE_RESULT_OF];

/** Collect, from one stream event, what can impact a timeline (pure, no database access). */
export const collectTimelineImpacts = (event: SseEvent<DataEvent>, collector: ImpactCollector) => {
  const stix = event.data?.data as any;
  const extension = stix?.extensions?.[STIX_EXT_OCTI];
  if (!stix || !extension) return;
  if (extension.is_inferred) return;
  const type: string = extension.type;
  const id: string = extension.id;
  if (type === ENTITY_TYPE_TIMELINE_EVENT || type === ENTITY_TYPE_TIMELINE_SETTINGS) return;
  if (isTimelineContainerType(type)) {
    collector.containers.add(id);
    // A container is also knowledge of other timelines (an incident in a case): the cases containing it and the incidents
    // related to it read it too
    collector.contained.add(id);
    collector.related.add(id);
    return;
  }
  // Meta objects read by the derivation through other elements: a change reaches the cases through those elements, and
  // through the manual events pointing to them
  if (type === ENTITY_TYPE_LABEL || type === ENTITY_TYPE_KILL_CHAIN_PHASE) {
    // A new label or phase is used by nothing yet
    if (event.data?.type !== 'create') {
      (type === ENTITY_TYPE_LABEL ? collector.labels : collector.killChainPhases).add(id);
    }
    return;
  }
  // External references are read on the containers themselves: a change reaches the containers citing them, and the
  // cases of the manual events pointing to them
  if (type === ENTITY_TYPE_EXTERNAL_REFERENCE) {
    if (event.data?.type !== 'create') collector.externalReferences.add(id);
    return;
  }
  if (CONTAINERS_REFERENCING_TYPES.includes(type)) {
    (stix.object_refs ?? []).forEach((ref: string) => collector.references.add(ref));
    // A case removed from the refs by an update is impacted too: it is only in the version before the update
    previousObjectRefs(event).forEach((ref) => collector.references.add(ref));
  }
  if (stix.type === STIX_TYPE_RELATION) {
    if (isTimelineContainerType(extension.source_type)) collector.containers.add(extension.source_ref);
    if (isTimelineContainerType(extension.target_type)) collector.containers.add(extension.target_ref);
    collector.contained.add(id);
    // Deployments and timed relationships of contained elements impact the cases containing either endpoint
    if (extension.source_ref) collector.contained.add(extension.source_ref);
    if (extension.target_ref) collector.contained.add(extension.target_ref);
    // Deployments are also read for the indicators related to an incident: the incidents related to the deployed indicator are impacted
    if (type === SOFT_RELATION_DEPLOYED_ON && extension.source_ref) collector.related.add(extension.source_ref);
    // The has-covered relationships of a security coverage are read for the container it covers
    if (extension.source_type === ENTITY_TYPE_SECURITY_COVERAGE && extension.source_ref) collector.coverages.add(extension.source_ref);
    return;
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    collector.contained.add(id);
    // Sightings by security platforms are detections of the cases containing the indicator and of the incidents related to it
    if (extension.sighting_of_ref) {
      collector.contained.add(extension.sighting_of_ref);
      collector.related.add(extension.sighting_of_ref);
    }
    return;
  }
  // Soft-check sources, reached the way the loader selects them: Case Autopilot runs by their subject and their cases,
  // hunt runs by their incident and their hunt, security coverages by the container they cover and their results by
  // their coverage. The version before an update counts too: a run or a coverage moved away from a container leaves it
  [stix, previousVersion(event, SOFT_SOURCE_FIELDS)].forEach((version) => {
    if (!version) return;
    SOFT_SOURCE_CONTAINER_FIELDS.forEach((field) => idValues(version[field]).forEach((ref) => collector.references.add(ref)));
    // A hunt reaches the cases containing it and the incidents related to it, which read the runs of their related hunts
    idValues(version.hunt_id).forEach((ref) => {
      collector.contained.add(ref);
      collector.related.add(ref);
    });
    idValues(version[ATTRIBUTE_RESULT_OF]).forEach((ref) => collector.coverages.add(ref));
  });
  collector.contained.add(id);
  collector.related.add(id);
};

type ImpactedContainersSink = (containerIds: string[]) => Promise<void>;

/**
 * Queue every container impacted by the collected changes. A widely shared element can sit in thousands of cases:
 * they are read page by page and each page is queued before the next one is read, so none is dropped and the memory
 * stays bounded. The queue then regenerates them by bounded batches.
 */
const queueContainersContaining = async (context: AuthContext, elementIds: string[], enqueue: ImpactedContainersSink, relation = RELATION_OBJECT) => {
  if (elementIds.length === 0) return;
  await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, TIMELINE_CONTAINER_TYPES, {
    filters: { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(relation)], values: elementIds }], filterGroups: [] },
    noFiltersChecking: true,
    baseData: true,
    first: TIMELINE_MANAGER_IMPACTED_PAGE_SIZE,
    callback: async (containers: BasicStoreEntity[]) => {
      await enqueue(containers.map((c) => c.internal_id));
    },
  } as any);
};

/**
 * A manual event may point to an element, and name an author, its case does not contain, and so may the findings of an
 * investigation run: a change of either (its access above all, which decides whether the event is shown and whether it
 * and its author travel in the STIX exchange of the case) reaches the case through the event itself.
 */
const queueContainersOfEventsAbout = async (context: AuthContext, elementIds: string[], enqueue: ImpactedContainersSink) => {
  if (elementIds.length === 0) return;
  await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_TIMELINE_EVENT], {
    filters: {
      mode: FilterMode.And,
      filters: [],
      filterGroups: [{
        mode: FilterMode.Or,
        filters: [{ key: ['event_source'], values: ['manual'] }, { key: ['rule_id'], values: [RULE_INVESTIGATION_RUN] }],
        filterGroups: [],
      }, {
        mode: FilterMode.Or,
        filters: [{ key: ['element_id'], values: elementIds }, { key: [buildRefRelationKey(RELATION_CREATED_BY)], values: elementIds }],
        filterGroups: [],
      }],
    },
    noFiltersChecking: true,
    baseData: true,
    baseFields: ['container_id'],
    first: TIMELINE_MANAGER_IMPACTED_PAGE_SIZE,
    callback: async (events: Array<BasicStoreEntity & { container_id?: string }>) => {
      await enqueue(Array.from(new Set(events.map((event) => event.container_id).filter((id): id is string => !!id))));
    },
  } as any);
};

const queueReferencedContainers = async (context: AuthContext, references: string[], enqueue: ImpactedContainersSink) => {
  if (references.length === 0) return;
  const referenced = await internalFindByIds(context, SYSTEM_USER, references, { type: TIMELINE_CONTAINER_TYPES, baseData: true });
  await enqueue((referenced as unknown as BasicStoreEntity[]).map((c) => c.internal_id));
};

const queueContainersCoveredBy = async (context: AuthContext, coverageIds: string[], enqueue: ImpactedContainersSink) => {
  if (coverageIds.length === 0) return;
  // The covered container comes with every read, like the markings
  const coverages = await internalFindByIds(context, SYSTEM_USER, coverageIds, { type: ENTITY_TYPE_SECURITY_COVERAGE, baseData: true }) as unknown as BasicStoreEntity[];
  await queueReferencedContainers(context, Array.from(new Set(coverages.flatMap((coverage) => timelineRefIds(coverage, RELATION_COVERED)))), enqueue);
};

const queueImpactedContainers = async (context: AuthContext, collector: ImpactCollector, enqueue: ImpactedContainersSink) => {
  await enqueue(Array.from(collector.containers));
  await queueContainersContaining(context, Array.from(collector.contained), enqueue);
  // A manual event may point to any element, labels, kill chain phases and external references included
  await queueContainersOfEventsAbout(context, [
    ...collector.contained,
    ...collector.containers,
    ...collector.labels,
    ...collector.killChainPhases,
    ...collector.externalReferences,
  ], enqueue);
  await queueContainersContaining(context, Array.from(collector.externalReferences), enqueue, RELATION_EXTERNAL_REFERENCE);
  await queueReferencedContainers(context, Array.from(collector.references), enqueue);
  await queueContainersCoveredBy(context, Array.from(collector.coverages), enqueue);
  const killChainPhases = Array.from(collector.killChainPhases);
  if (killChainPhases.length > 0) {
    // Techniques are ordered by their phases: the cases containing them are impacted
    await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_ATTACK_PATTERN], {
      filters: { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(RELATION_KILL_CHAIN_PHASE)], values: killChainPhases }], filterGroups: [] },
      noFiltersChecking: true,
      baseData: true,
      first: TIMELINE_MANAGER_IMPACTED_PAGE_SIZE,
      callback: async (techniques: BasicStoreEntity[]) => {
        await queueContainersContaining(context, techniques.map((t) => t.internal_id), enqueue);
      },
    } as any);
  }
  const labels = Array.from(collector.labels);
  if (labels.length > 0) {
    // Tasks are read through their labels (a containment task): the cases they point to are impacted
    await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_CONTAINER_TASK], {
      filters: { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(RELATION_OBJECT_LABEL)], values: labels }], filterGroups: [] },
      noFiltersChecking: true,
      first: TIMELINE_MANAGER_IMPACTED_PAGE_SIZE,
      callback: async (tasks: BasicStoreEntity[]) => {
        const pointed = Array.from(new Set(tasks.flatMap((task) => timelineRefIds(task, RELATION_OBJECT))));
        await queueReferencedContainers(context, pointed, enqueue);
      },
    } as any);
  }
  const related = Array.from(collector.related);
  if (related.length > 0) {
    const relatedArgs = { baseData: true, first: TIMELINE_MANAGER_IMPACTED_PAGE_SIZE };
    await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, {
      ...relatedArgs,
      toId: related,
      fromTypes: [ENTITY_TYPE_INCIDENT],
      callback: async (relations: BasicStoreRelation[]) => {
        await enqueue(relations.map((r) => r.fromId));
      },
    } as any);
    await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, {
      ...relatedArgs,
      fromId: related,
      toTypes: [ENTITY_TYPE_INCIDENT],
      callback: async (relations: BasicStoreRelation[]) => {
        await enqueue(relations.map((r) => r.toId));
      },
    } as any);
  }
};

export const timelineStreamEventsHandler = async (context: AuthContext, streamEvents: Array<SseEvent<DataEvent>>) => {
  if (streamEvents.length === 0) return;
  const collector = newImpactCollector();
  streamEvents.forEach((event) => collectTimelineImpacts(event, collector));
  await queueImpactedContainers(context, collector, (ids) => enqueueTimelineRegeneration(ids));
};

const resolveStreamStart = async (): Promise<string> => {
  const state = await redisGetManagerEventState(TIMELINE_MANAGER_STATE);
  if (state) return state;
  // First start: listen from now on, the existing containers are backfilled by the first consistency pass. When the
  // stream position cannot be read, the error stops this run and the next run retries: never replay the whole stream
  const info = await fetchStreamInfo();
  return info.lastEventId ?? '0-0';
};

const consumeStream = async (context: AuthContext) => {
  let lastEventId = await resolveStreamStart();
  for (let batch = 0; batch < TIMELINE_MANAGER_MAX_STREAM_BATCHES; batch += 1) {
    const result = await fetchStreamEventsRangeFromEventId<DataEvent>(
      lastEventId,
      (events) => timelineStreamEventsHandler(context, events),
      { streamBatchSize: TIMELINE_MANAGER_STREAM_BATCH_SIZE },
    );
    const moved = result.lastEventId !== lastEventId;
    lastEventId = result.lastEventId;
    await redisSetManagerEventState(TIMELINE_MANAGER_STATE, lastEventId);
    if (!moved) break;
  }
};

export const processDueTimelineRegenerations = async (context: AuthContext) => {
  const { containerIds: due, lease } = await claimDueTimelineRegenerations(TIMELINE_MANAGER_REGENERATION_BATCH);
  await BluePromise.map(due, async (containerId) => {
    try {
      const result = await regenerateContainerTimeline(context, containerId);
      await clearTimelineRegenerationAttempts(containerId);
      if (result) {
        logApp.debug('[TIMELINE] Container timeline regenerated', { ...result, anchors: undefined });
      }
    } catch (error) {
      let retried: boolean;
      try {
        retried = await retryTimelineRegeneration(containerId);
      } catch (retryError) {
        // The retry could not be scheduled: the claim is kept, and its lease hands the container out again
        logApp.error('[TIMELINE] Container timeline regeneration failure, retry not scheduled', { cause: error, retryCause: retryError, containerId });
        return;
      }
      logApp.error('[TIMELINE] Container timeline regeneration failure', { cause: error, containerId, retried });
    }
    // Handled (regenerated, rescheduled or given up): the claim is released; until then its lease protects it
    try {
      if (!(await acknowledgeTimelineRegeneration(containerId, lease))) {
        logApp.warn('[TIMELINE] Regeneration outlived its claim, the later claim of the container is kept', { containerId });
      }
    } catch (error) {
      logApp.warn('[TIMELINE] Claim not released, it is reclaimed when its lease expires', { cause: error, containerId });
    }
  }, { concurrency: TIMELINE_MANAGER_MAX_CONCURRENCY });
};

/**
 * Once a day, the timeline containers that may be stale are scheduled for regeneration (spread by the queue batch size).
 * The very first pass runs at the first manager run: it is the backfill of the incidents and cases of an existing
 * platform (all never computed), scheduled in the background so that the startup never waits for it.
 */
export const isTimelineConsistencyPassDue = (lastRun: number | null, nowTime: number, hour: number): boolean => {
  if (lastRun === null) return true;
  const today = new Date(nowTime);
  const scheduled = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate(), hour);
  if (nowTime < scheduled) return false;
  return lastRun < scheduled;
};

/**
 * Containers of the consistency pass: changed since the previous pass, never computed, or not regenerated for the
 * max age. Its cost follows the activity of the platform, not the number of incidents and cases it holds.
 * Workflow statuses are not in the stream: when the workflow of a container type changed since the previous pass
 * (which status is final decides the closure), every container of that type is scheduled; a change of the task
 * workflow (which decides when a task is completed) schedules every container.
 */
export const buildTimelineConsistencyFilters = (lastRun: number | null, nowTime: number, maxAgeDays: number, changedWorkflowTypes: string[] = []) => {
  const changedSince = new Date(lastRun ?? nowTime - DAY_MS).toISOString();
  const staleBefore = new Date(nowTime - maxAgeDays * DAY_MS).toISOString();
  const computedAtKey = `${ATTRIBUTE_TIMELINE_ANCHORS}.computed_at`;
  const workflowTypes = changedWorkflowTypes.includes(ENTITY_TYPE_CONTAINER_TASK)
    ? TIMELINE_CONTAINER_TYPES
    : TIMELINE_CONTAINER_TYPES.filter((type) => changedWorkflowTypes.includes(type));
  return {
    mode: FilterMode.Or,
    filters: [
      { key: ['updated_at'], operator: FilterOperator.Gte, values: [changedSince] },
      { key: [computedAtKey], operator: FilterOperator.Nil, values: [] },
      { key: [computedAtKey], operator: FilterOperator.Lt, values: [staleBefore] },
      ...(workflowTypes.length > 0 ? [{ key: ['entity_type'], values: workflowTypes }] : []),
    ],
    filterGroups: [],
  };
};

interface WorkflowChangeSource {
  updated_at?: Date | string | null;
  created_at?: Date | string | null;
}

/**
 * Entity types whose final statuses may have moved since the previous pass: one of their workflow statuses was created
 * or changed, the workflow definition published for the type changed (a change of transitions only touches no status),
 * or the entity setting linking the type to its workflow changed.
 */
export const computeChangedWorkflowTypes = (
  lastRun: number,
  statuses: Array<WorkflowChangeSource & { type?: string }>,
  settings: Array<WorkflowChangeSource & { target_type: string; workflow_id?: string | null }>,
  definitions: Record<string, WorkflowChangeSource>,
): string[] => {
  const isChanged = (element: WorkflowChangeSource) => new Date(element.updated_at ?? element.created_at ?? 0).getTime() >= lastRun;
  const types = new Set(statuses.filter(isChanged).map((status) => status.type).filter((type): type is string => !!type));
  settings.forEach((setting) => {
    const definition = setting.workflow_id ? definitions[setting.workflow_id] : undefined;
    if (isChanged(setting) || (definition && isChanged(definition))) types.add(setting.target_type);
  });
  return Array.from(types);
};

const findChangedWorkflowTypes = async (context: AuthContext, lastRun: number | null): Promise<string[]> => {
  if (lastRun === null) return [];
  const statuses = await getEntitiesListFromCache<BasicStoreEntity & { type?: string }>(context, SYSTEM_USER, ENTITY_TYPE_STATUS);
  const workflowTargetTypes = [...TIMELINE_CONTAINER_TYPES, ENTITY_TYPE_CONTAINER_TASK];
  const settings = (await getEntitiesListFromCache<BasicStoreEntityEntitySetting>(context, SYSTEM_USER, ENTITY_TYPE_ENTITY_SETTING))
    .filter((setting) => workflowTargetTypes.includes(setting.target_type));
  const definitionIds = settings.map((setting) => setting.workflow_id).filter((id): id is string => !!id);
  const definitions = definitionIds.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, definitionIds, {
      type: ENTITY_TYPE_WORKFLOW_DEFINITION,
      baseData: true,
      baseFields: ['updated_at', 'created_at'],
      toMap: true,
    }) as unknown as Record<string, BasicStoreEntity>
    : {};
  return computeChangedWorkflowTypes(lastRun, statuses, settings, definitions);
};

const runConsistencyPass = async (context: AuthContext) => {
  const nowTime = Date.now();
  const lastRun = await getTimelineConsistencyLastRun();
  if (!isTimelineConsistencyPassDue(lastRun, nowTime, TIMELINE_MANAGER_CONSISTENCY_HOUR)) return;
  let scheduled = 0;
  const changedWorkflowTypes = await findChangedWorkflowTypes(context, lastRun);
  await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, TIMELINE_CONTAINER_TYPES, {
    baseData: true,
    filters: buildTimelineConsistencyFilters(lastRun, nowTime, TIMELINE_MANAGER_CONSISTENCY_MAX_AGE_DAYS, changedWorkflowTypes),
    noFiltersChecking: true,
    callback: async (containers: BasicStoreEntity[]) => {
      await enqueueTimelineRegeneration(containers.map((c) => c.internal_id));
      scheduled += containers.length;
    },
  } as any);
  // Recorded once every container is scheduled: an interrupted pass runs again at the next manager run
  await setTimelineConsistencyLastRun(nowTime);
  logApp.info('[TIMELINE] Consistency pass scheduled', { scheduled });
};

export const timelineManagerHandler = async () => {
  const context = executionContext(TIMELINE_MANAGER_CONTEXT);
  await consumeStream(context);
  await processDueTimelineRegenerations(context);
  await runConsistencyPass(context);
};

const TIMELINE_MANAGER_DEFINITION: ManagerDefinition = {
  id: TIMELINE_MANAGER_ID,
  label: TIMELINE_MANAGER_LABEL,
  executionContext: TIMELINE_MANAGER_CONTEXT,
  enabledByConfig: TIMELINE_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  cronSchedulerHandler: {
    handler: timelineManagerHandler,
    interval: TIMELINE_MANAGER_INTERVAL,
    lockKey: TIMELINE_MANAGER_LOCK_KEY,
  },
};

registerManager(TIMELINE_MANAGER_DEFINITION);
