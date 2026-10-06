import { elCount, elPaginate, elRawSearch } from '../../database/engine';
import { patchAttribute } from '../../database/middleware';
import { getEntitiesListFromCache } from '../../database/cache';
import {
  READ_INDEX_HISTORY,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  wait,
} from '../../database/utils';
import conf, { logApp } from '../../config/conf';
import { LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';
import { RULE_PREFIX } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_HISTORY, ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { RELATION_CREATED_BY } from '../../schema/stixRefRelationship';
import { RULE_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import type { AuthContext } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../../types/store';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { internalFindByIds } from '../../database/middleware-loader';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../managerConfiguration/managerConfiguration-types';
import { findByManagerId } from '../managerConfiguration/managerConfiguration-domain';
import { resolveSourceOfUser, sourceFromConnector, sourceFromRule } from './provenance-source';
import {
  type AssertionSource,
  DEFAULT_PROVENANCE_BACKFILL_STATE,
  PROVENANCE_BACKFILL_MANAGER_ID,
  type ProvenanceBackfillState,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_USER,
  type StoreAssertion,
} from './provenance-types';
import { applyProvenanceUpdate } from './provenance-write';
import { listProvenanceTrackedTypes } from './provenance-tracking';

// Inferred knowledge is included: its sources are the inference rules
const BACKFILL_INDICES = [
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
];
const CREATED_BY_FIELD = `rel_${RELATION_CREATED_BY}.internal_id`;
const BACKFILL_FIELDS = ['creator_id', 'created_at', 'updated_at', 'confidence', CREATED_BY_FIELD, `${RULE_PREFIX}*`];
const HISTORY_ASSERTION_SCOPES = ['create', 'update', 'merge'];
// Size of one request: writers, writes of shared users and work windows are all read page by page
const HISTORY_WRITERS_PER_REQUEST = 1000;
const HISTORY_WRITES_PER_REQUEST = 1000;
const WORKS_PER_REQUEST = 1000;
const BACKFILL_RETRY_DELAY_MS = 1000;
// Every batch of the backfill manager runs under this lock
export const PROVENANCE_BACKFILL_LOCK_KEY: string = conf.get('provenance_backfill_manager:lock_key') || 'provenance_backfill_manager_lock';

type BackfillElement = BasicStoreBase & {
  _index: string;
  creator_id?: string | string[];
  created_at?: string | Date;
  updated_at?: string | Date;
  confidence?: number | null;
  [key: string]: any;
};

export interface BackfillWriteSegment {
  first: string;
  last: string;
  count: number;
}

/**
 * Writes of one user on one element, as found in the history (or its creator list when the history was purged).
 * A count of 0 is a user whose writes all came after the backfill watermark: the live tracking recorded them.
 */
export interface BackfillUserActivity extends BackfillWriteSegment {
  user_id: string;
  /** Writes of a user shared by several connectors, grouped by the connector whose work was running at their date. */
  segments?: BackfillWriteSegment[];
}

/** One write of a user shared by several connectors, read from the history. */
export interface BackfillSharedUserWrite {
  element_id: string;
  user_id: string;
  at: string;
}

export interface BackfillWorkWindow {
  id: string;
  connector_id: string;
  start: string;
  end: string;
}

export type BackfillSourceResolver = (userId: string, at: string) => Promise<AssertionSource>;

const toIso = (date: string | Date | undefined | null, fallback: string) => {
  if (!date) {
    return fallback;
  }
  const parsed = new Date(date);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed.toISOString();
};

const toArray = (value: string | string[] | undefined | null) => {
  if (!value) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

/**
 * Connector whose work was running at the given date, among the connectors sharing a user.
 * Ambiguous or unknown dates resolve to nothing (the user stays the source).
 */
export const findRunningWorkConnector = (works: BackfillWorkWindow[], connectorIds: string[], at: string) => {
  const running = works.filter((work) => connectorIds.includes(work.connector_id) && work.start <= at && at <= work.end);
  const connectors = new Set(running.map((work) => work.connector_id));
  if (connectors.size !== 1) {
    return null;
  }
  const work = running.sort((a, b) => b.start.localeCompare(a.start))[0];
  return { connector_id: work.connector_id, work_id: work.id };
};

/**
 * Same answer as findRunningWorkConnector, for dates read in ascending order: the works are scanned once
 * and only those running at the current date are kept. A date earlier than the previous one restarts the scan.
 */
export const createRunningWorkIndex = (works: BackfillWorkWindow[]) => {
  const sorted = [...works].sort((a, b) => a.start.localeCompare(b.start));
  let next = 0;
  let active: BackfillWorkWindow[] = [];
  let previous = '';
  return (connectorIds: string[], at: string) => {
    if (at < previous) {
      next = 0;
      active = [];
    }
    previous = at;
    while (next < sorted.length && sorted[next].start <= at) {
      active.push(sorted[next]);
      next += 1;
    }
    active = active.filter((work) => work.end >= at);
    return findRunningWorkConnector(active, connectorIds, at);
  };
};

/**
 * Group the writes of the users shared by several connectors by the connector running at the date of each write,
 * so that alternating connectors (A, B, then A again) each keep their own writes.
 * Writes with no unique running connector form their own group: they stay attributed to the user.
 * Returns the segments by element id, then by user id.
 */
export const groupSharedUserWrites = (
  writes: BackfillSharedUserWrite[],
  works: BackfillWorkWindow[],
  connectorIdsByUser: Map<string, string[]>,
) => {
  const runningConnectorAt = createRunningWorkIndex(works);
  const ordered = [...writes].sort((a, b) => a.at.localeCompare(b.at));
  const segments = new Map<string, Map<string, Map<string, BackfillWriteSegment>>>();
  for (let index = 0; index < ordered.length; index += 1) {
    const write = ordered[index];
    const running = runningConnectorAt(connectorIdsByUser.get(write.user_id) ?? [], write.at);
    const groupKey = running?.connector_id ?? '';
    const byUser = segments.get(write.element_id) ?? new Map<string, Map<string, BackfillWriteSegment>>();
    const byGroup = byUser.get(write.user_id) ?? new Map<string, BackfillWriteSegment>();
    const segment = byGroup.get(groupKey);
    if (segment) {
      segment.last = write.at;
      segment.count += 1;
    } else {
      byGroup.set(groupKey, { first: write.at, last: write.at, count: 1 });
    }
    byUser.set(write.user_id, byGroup);
    segments.set(write.element_id, byUser);
  }
  const result = new Map<string, Map<string, BackfillWriteSegment[]>>();
  segments.forEach((byUser, elementId) => {
    result.set(elementId, new Map(Array.from(byUser.entries()).map(([userId, byGroup]) => [userId, Array.from(byGroup.values())])));
  });
  return result;
};

const mergeAssertion = (assertions: Map<string, StoreAssertion>, assertion: StoreAssertion) => {
  const existing = assertions.get(assertion.source_id);
  if (!existing) {
    assertions.set(assertion.source_id, assertion);
    return;
  }
  const isNewer = assertion.last_asserted_at >= existing.last_asserted_at;
  assertions.set(assertion.source_id, {
    ...(isNewer ? assertion : existing),
    first_asserted_at: assertion.first_asserted_at < existing.first_asserted_at ? assertion.first_asserted_at : existing.first_asserted_at,
    last_asserted_at: isNewer ? assertion.last_asserted_at : existing.last_asserted_at,
    assert_count: existing.assert_count + assertion.assert_count,
  });
};

const buildBackfillAssertion = (source: AssertionSource, first: string, last: string, count: number, confidence: number | null): StoreAssertion => ({
  source_id: source.source_id,
  source_kind: source.source_kind,
  source_name: source.source_name,
  first_asserted_at: first,
  last_asserted_at: last,
  assert_count: Math.max(1, count),
  confidence,
  work_id: source.work_id,
});

/**
 * Rebuild the assertions of an element from its past writers:
 * - every writer of the history (create, update, merge events) and every creator is a candidate source;
 * - a writer is resolved like a live write: inference rule, connector / feed / emulation, otherwise the user;
 * - when the first creator is a human user and the element has an author, the author is the source;
 * - an inferred element is asserted by each rule that inferred it.
 * With a watermark, only what happened before it is rebuilt: the live tracking recorded everything after it.
 */
export const computeBackfillAssertions = async (
  element: BackfillElement,
  history: BackfillUserActivity[],
  resolveSource: BackfillSourceResolver,
  authorNames: Map<string, string> = new Map(),
  watermark?: string,
): Promise<StoreAssertion[]> => {
  const reference = now();
  const createdAt = toIso(element.created_at, reference);
  const updatedAt = toIso(element.updated_at, createdAt);
  const isBeforeWatermark = (date: string) => !watermark || date < watermark;
  const confidence = element.confidence ?? null;
  const creators = toArray(element.creator_id);
  const activities = new Map(history.map((activity) => [activity.user_id, { ...activity }]));
  if (isBeforeWatermark(createdAt)) {
    creators.forEach((creatorId, index) => {
      // History purged by retention: creation date for the first creator, last update for the others. Only the first
      // creator is known to have written before the watermark: its creation is restored even if it wrote after it
      const activity = activities.get(creatorId);
      if (!activity || (index === 0 && activity.count === 0)) {
        const at = index === 0 || !isBeforeWatermark(updatedAt) ? createdAt : updatedAt;
        activities.set(creatorId, { user_id: creatorId, first: at, last: at, count: 1 });
      }
    });
  }
  const assertions = new Map<string, StoreAssertion>();
  const authorId: string | undefined = toArray(element[CREATED_BY_FIELD])[0];
  const author: AssertionSource | null = authorId
    ? { source_id: authorId, source_kind: SOURCE_KIND_AUTHOR, source_name: authorNames.get(authorId) ?? authorId, work_id: null }
    : null;
  const activityList = Array.from(activities.values());
  for (let index = 0; index < activityList.length; index += 1) {
    const activity = activityList[index];
    if (activity.user_id === RULE_MANAGER_USER.id) {
      continue; // inference sources come from the rules stored on the element
    }
    const segments = activity.segments && activity.segments.length > 0 ? activity.segments : [activity];
    for (let segmentIndex = 0; segmentIndex < segments.length; segmentIndex += 1) {
      const segment = segments[segmentIndex];
      if (segment.count === 0) {
        continue;
      }
      // Resolved at the last write of the segment, so the assertion keeps the latest work of its connector
      const source = await resolveSource(activity.user_id, segment.last);
      const isHumanCreator = source.source_kind === SOURCE_KIND_USER && activity.user_id === creators[0];
      const assertedBy = isHumanCreator && author ? author : source;
      mergeAssertion(assertions, buildBackfillAssertion(assertedBy, segment.first, segment.last, segment.count, confidence));
    }
  }
  const ruleKeys = isBeforeWatermark(createdAt)
    ? Object.keys(element).filter((key) => key.startsWith(RULE_PREFIX) && Array.isArray(element[key]) && element[key].length > 0)
    : [];
  const inferredUntil = isBeforeWatermark(updatedAt) ? updatedAt : createdAt;
  ruleKeys.forEach((key) => {
    mergeAssertion(assertions, buildBackfillAssertion(sourceFromRule(key), createdAt, inferredUntil, 1, confidence));
  });
  return Array.from(assertions.values());
};

// region data loading
const historyWritesFilter = (ids: string[], userIds?: string[], before?: string) => [
  { term: { 'entity_type.keyword': ENTITY_TYPE_HISTORY } },
  { terms: { 'context_data.id.keyword': ids } },
  { terms: { 'event_scope.keyword': HISTORY_ASSERTION_SCOPES } },
  ...(userIds ? [{ terms: { 'user_id.keyword': userIds } }] : []),
  ...(before ? [{ range: { timestamp: { lt: before } } }] : []),
];

/**
 * Every writer of every element of the batch, with the dates of its first and last writes before the watermark and
 * their count. Read page by page with a composite aggregation: no writer is left out, whatever their number.
 */
const aggregateHistoryActivities = async (context: AuthContext, ids: string[], watermark: string) => {
  const activities = new Map<string, BackfillUserActivity[]>();
  let after: Record<string, string> | undefined;
  do {
    const query = {
      index: READ_INDEX_HISTORY,
      body: {
        size: 0,
        query: { bool: { filter: historyWritesFilter(ids) } },
        aggs: {
          writers: {
            composite: {
              size: HISTORY_WRITERS_PER_REQUEST,
              sources: [
                { element: { terms: { field: 'context_data.id.keyword' } } },
                { user: { terms: { field: 'user_id.keyword' } } },
              ],
              ...(after ? { after } : {}),
            },
            aggs: {
              before_watermark: {
                filter: { range: { timestamp: { lt: watermark } } },
                aggs: { first: { min: { field: 'timestamp' } }, last: { max: { field: 'timestamp' } } },
              },
            },
          },
        },
      },
    };
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_HISTORY, query);
    const buckets = data.aggregations?.writers?.buckets ?? [];
    for (let index = 0; index < buckets.length; index += 1) {
      const bucket = buckets[index];
      const before = bucket.before_watermark;
      const elementActivities = activities.get(bucket.key.element) ?? [];
      elementActivities.push(before.doc_count > 0 ? {
        user_id: bucket.key.user,
        first: new Date(before.first.value).toISOString(),
        last: new Date(before.last.value).toISOString(),
        count: before.doc_count,
      } : { user_id: bucket.key.user, first: watermark, last: watermark, count: 0 });
      activities.set(bucket.key.element, elementActivities);
    }
    after = buckets.length === HISTORY_WRITERS_PER_REQUEST ? data.aggregations?.writers?.after_key : undefined;
  } while (after);
  return activities;
};

/**
 * Every write of the given users on the elements of the batch before the watermark, in date order, read page by page.
 */
const loadSharedUserWrites = async (context: AuthContext, ids: string[], userIds: string[], watermark: string): Promise<BackfillSharedUserWrite[]> => {
  const writes: BackfillSharedUserWrite[] = [];
  let searchAfter: unknown[] | undefined;
  do {
    const query = {
      index: READ_INDEX_HISTORY,
      body: {
        size: HISTORY_WRITES_PER_REQUEST,
        _source: ['context_data.id', 'user_id', 'timestamp'],
        sort: [{ timestamp: 'asc' }, { 'internal_id.keyword': 'asc' }],
        query: { bool: { filter: historyWritesFilter(ids, userIds, watermark) } },
        ...(searchAfter ? { search_after: searchAfter } : {}),
      },
    };
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_HISTORY, query);
    const hits = data.hits?.hits ?? [];
    for (let index = 0; index < hits.length; index += 1) {
      const write = hits[index]._source;
      if (write.context_data?.id && write.user_id && write.timestamp) {
        writes.push({ element_id: write.context_data.id, user_id: write.user_id, at: new Date(write.timestamp).toISOString() });
      }
    }
    searchAfter = hits.length === HISTORY_WRITES_PER_REQUEST ? hits[hits.length - 1].sort : undefined;
  } while (searchAfter);
  return writes;
};

/**
 * Every work of the given connectors running at some point between the two dates, read page by page.
 */
const loadWorkWindows = async (context: AuthContext, connectorIds: string[], from: string, to: string): Promise<BackfillWorkWindow[]> => {
  if (connectorIds.length === 0) {
    return [];
  }
  const reference = now();
  const works: BackfillWorkWindow[] = [];
  let searchAfter: unknown[] | undefined;
  do {
    const query = {
      index: READ_INDEX_HISTORY,
      body: {
        size: WORKS_PER_REQUEST,
        _source: ['internal_id', 'connector_id', 'timestamp', 'completed_time', 'updated_at'],
        sort: [{ timestamp: 'asc' }, { 'internal_id.keyword': 'asc' }],
        query: {
          bool: {
            filter: [
              { term: { 'entity_type.keyword': ENTITY_TYPE_WORK } },
              { terms: { 'connector_id.keyword': connectorIds } },
              { range: { timestamp: { lte: to } } },
            ],
            should: [
              { range: { completed_time: { gte: from } } },
              { bool: { must_not: { exists: { field: 'completed_time' } } } },
            ],
            minimum_should_match: 1,
          },
        },
        ...(searchAfter ? { search_after: searchAfter } : {}),
      },
    };
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_WORK, query);
    const hits = data.hits?.hits ?? [];
    for (let index = 0; index < hits.length; index += 1) {
      const work = hits[index]._source;
      works.push({
        id: work.internal_id,
        connector_id: work.connector_id,
        start: toIso(work.timestamp, reference),
        end: toIso(work.completed_time ?? work.updated_at, reference),
      });
    }
    searchAfter = hits.length === WORKS_PER_REQUEST ? hits[hits.length - 1].sort : undefined;
  } while (searchAfter);
  return works;
};

/**
 * Users shared by several connectors write for one connector or another depending on the date: their writes
 * are read one by one and split by the connector whose work was running at each date.
 * Also returns the works of these connectors, used to resolve each group of writes to its connector.
 */
const splitSharedUsersActivities = async (
  context: AuthContext,
  ids: string[],
  connectorsByUser: Map<string, BasicStoreEntityConnector[]>,
  activities: Map<string, BackfillUserActivity[]>,
  watermark: string,
): Promise<{ works: BackfillWorkWindow[]; activities: Map<string, BackfillUserActivity[]> }> => {
  const connectorIdsByUser = new Map(Array.from(connectorsByUser.entries())
    .filter(([, userConnectors]) => userConnectors.length > 1)
    .map(([userId, userConnectors]) => [userId, userConnectors.map((connector) => connector.internal_id)]));
  const sharedActivities = Array.from(activities.values()).flat()
    .filter((activity) => activity.count > 0 && connectorIdsByUser.has(activity.user_id));
  if (sharedActivities.length === 0) {
    return { works: [], activities };
  }
  const sharedUserIds = [...new Set(sharedActivities.map((activity) => activity.user_id))];
  const connectorIds = sharedUserIds.flatMap((userId) => connectorIdsByUser.get(userId) ?? []);
  const from = sharedActivities.reduce((min, activity) => (activity.first < min ? activity.first : min), sharedActivities[0].first);
  const to = sharedActivities.reduce((max, activity) => (activity.last > max ? activity.last : max), sharedActivities[0].last);
  const works = await loadWorkWindows(context, connectorIds, from, to);
  const writes = await loadSharedUserWrites(context, ids, sharedUserIds, watermark);
  const segments = groupSharedUserWrites(writes, works, connectorIdsByUser);
  const split = new Map(Array.from(activities.entries()).map(([elementId, elementActivities]) => [
    elementId,
    elementActivities.map((activity) => {
      const userSegments = segments.get(elementId)?.get(activity.user_id);
      return userSegments ? { ...activity, segments: userSegments } : activity;
    }),
  ]));
  return { works, activities: split };
};

const createBackfillSourceResolver = (
  context: AuthContext,
  connectorsByUser: Map<string, BasicStoreEntityConnector[]>,
  works: BackfillWorkWindow[],
): BackfillSourceResolver => {
  const userSources = new Map<string, AssertionSource>();
  return async (userId: string, at: string) => {
    const sharedConnectors = connectorsByUser.get(userId) ?? [];
    if (sharedConnectors.length > 1) {
      const running = findRunningWorkConnector(works, sharedConnectors.map((connector) => connector.internal_id), at);
      const connector = running ? sharedConnectors.find((candidate) => candidate.internal_id === running.connector_id) : undefined;
      if (connector && running) {
        return sourceFromConnector(context, connector, running.work_id);
      }
    }
    const cached = userSources.get(userId);
    if (cached) {
      return cached;
    }
    const resolved = await resolveSourceOfUser(context, userId);
    userSources.set(userId, resolved);
    return resolved;
  };
};
// endregion

// region state
const loadBackfillConfiguration = async (context: AuthContext) => {
  return findByManagerId(context, SYSTEM_USER, PROVENANCE_BACKFILL_MANAGER_ID);
};

export const readBackfillState = (setting: unknown): ProvenanceBackfillState => {
  return { ...DEFAULT_PROVENANCE_BACKFILL_STATE, ...((setting ?? {}) as Partial<ProvenanceBackfillState>) };
};

const saveBackfillState = async (context: AuthContext, configurationId: string, state: ProvenanceBackfillState, runStart: Date) => {
  await patchAttribute(context, SYSTEM_USER, configurationId, ENTITY_TYPE_MANAGER_CONFIGURATION, {
    manager_setting: state,
    manager_running: state.status === 'running',
    last_run_start_date: runStart,
    last_run_end_date: new Date(),
  });
};

export const getProvenanceBackfillState = async (context: AuthContext) => {
  const configuration = await loadBackfillConfiguration(context);
  return readBackfillState(configuration?.manager_setting);
};

/**
 * Restart the backfill from the beginning. Replays are idempotent: the history already counted is never added twice.
 * Taken under the lock of the backfill manager: a batch in progress finishes first, then the restart is saved,
 * and no batch can overwrite it with the state it started from.
 */
export const restartProvenanceBackfill = async (context: AuthContext) => {
  let lock;
  try {
    lock = await lockResources([PROVENANCE_BACKFILL_LOCK_KEY]);
    const configuration = await loadBackfillConfiguration(context);
    if (!configuration) {
      return DEFAULT_PROVENANCE_BACKFILL_STATE;
    }
    const state = { ...DEFAULT_PROVENANCE_BACKFILL_STATE };
    await saveBackfillState(context, configuration.id, state, new Date());
    return state;
  } catch (err: any) {
    if (err.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [PROVENANCE_BACKFILL_MANAGER_ID] }, 'A batch of the provenance backfill is still running, retry in a moment');
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};
// endregion

/**
 * One bounded, resumable step of the provenance backfill: the cursor is persisted after every batch.
 */
export const runProvenanceBackfillBatch = async (context: AuthContext, opts: { batchSize: number }): Promise<ProvenanceBackfillState | null> => {
  const runStart = new Date();
  const configuration = await loadBackfillConfiguration(context);
  if (!configuration) {
    return null;
  }
  const state = readBackfillState(configuration.manager_setting);
  if (state.status === 'completed') {
    return state;
  }
  // Only the types whose provenance is tracked are rebuilt (entity settings)
  const trackedTypes = await listProvenanceTrackedTypes(context);
  if (trackedTypes.length === 0) {
    const completed = { ...state, status: 'completed' as const, cursor: null, completed_at: now() };
    await saveBackfillState(context, configuration.id, completed, runStart);
    return completed;
  }
  if (state.status === 'pending') {
    state.status = 'running';
    state.started_at = null;
    state.cursor = null;
    state.processed = 0;
    state.updated = 0;
    state.errors = 0;
    state.expected = await elCount(context, SYSTEM_USER, BACKFILL_INDICES, { types: trackedTypes });
  }
  // The live tracking records every write after the start of the run: the history is only read before it.
  // A new watermark is saved before the first page: a run stopped before its first batch is saved restarts with the
  // same watermark, never a later one that would leave the live assertions recorded in between uncounted
  let watermark = state.started_at;
  if (!watermark) {
    watermark = runStart.toISOString();
    state.started_at = watermark;
    await saveBackfillState(context, configuration.id, state, runStart);
  }
  const page = await elPaginate<BackfillElement>(context, SYSTEM_USER, BACKFILL_INDICES, {
    types: trackedTypes,
    first: opts.batchSize,
    after: state.cursor,
    baseData: true,
    baseFields: BACKFILL_FIELDS,
    withoutRels: false,
    withResultMeta: true,
  }) as unknown as { elements: { edges: { node: BackfillElement }[]; pageInfo: { hasNextPage: boolean } }; endCursor: string | null };
  const elements = page.elements.edges.map((edge) => edge.node);
  if (elements.length > 0) {
    const ids = elements.map((element) => element.internal_id);
    const writers = await aggregateHistoryActivities(context, ids, watermark);
    const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
    const connectorsByUser = new Map<string, BasicStoreEntityConnector[]>();
    connectors.forEach((connector) => {
      if (connector.connector_user_id) {
        connectorsByUser.set(connector.connector_user_id, [...(connectorsByUser.get(connector.connector_user_id) ?? []), connector]);
      }
    });
    const { works, activities } = await splitSharedUsersActivities(context, ids, connectorsByUser, writers, watermark);
    const resolveSource = createBackfillSourceResolver(context, connectorsByUser, works);
    const authorIds = [...new Set(elements.flatMap((element) => toArray(element[CREATED_BY_FIELD])))];
    const authors = authorIds.length > 0
      ? await internalFindByIds<BasicStoreEntity & { name: string }>(context, SYSTEM_USER, authorIds, { baseData: true, baseFields: ['name'] }) as (BasicStoreEntity & { name: string })[]
      : [];
    const authorNames = new Map(authors.map((author) => [author.internal_id, author.name]));
    const rebuild = async (element: BackfillElement) => {
      const assertions = await computeBackfillAssertions(element, activities.get(element.internal_id) ?? [], resolveSource, authorNames, watermark);
      if (assertions.length > 0) {
        await applyProvenanceUpdate(context, element, { assertions, countMode: 'backfill', backfillWatermark: watermark });
        state.updated += 1;
      }
    };
    // A rebuild is replayed without counting anything twice (backfill count mode): a failed element is tried
    // again at the end of the batch, and only a second failure leaves it to a restart of the backfill
    const failed: BackfillElement[] = [];
    for (let index = 0; index < elements.length; index += 1) {
      const element = elements[index];
      try {
        await rebuild(element);
      } catch (err) {
        failed.push(element);
        logApp.warn('[PROVENANCE] Backfill of an element failed, tried again at the end of the batch', { cause: err, id: element.internal_id });
      }
    }
    if (failed.length > 0) {
      await wait(BACKFILL_RETRY_DELAY_MS);
    }
    for (let index = 0; index < failed.length; index += 1) {
      const element = failed[index];
      try {
        await rebuild(element);
      } catch (err) {
        state.errors += 1;
        logApp.error('[PROVENANCE] Unable to backfill the provenance of an element', { cause: err, id: element.internal_id });
      }
    }
  }
  state.processed += elements.length;
  state.cursor = page.endCursor ?? state.cursor;
  if (!page.elements.pageInfo.hasNextPage || elements.length === 0) {
    state.status = 'completed';
    state.completed_at = now();
    state.cursor = null;
  }
  await saveBackfillState(context, configuration.id, state, runStart);
  return state;
};
