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
} from '../../database/utils';
import { logApp } from '../../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, RULE_PREFIX } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_HISTORY, ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { RELATION_CREATED_BY } from '../../schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
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

// Inferred knowledge is included: its sources are the inference rules
const BACKFILL_INDICES = [
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
];
const BACKFILL_TYPES = [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP];
const CREATED_BY_FIELD = `rel_${RELATION_CREATED_BY}.internal_id`;
const BACKFILL_FIELDS = ['creator_id', 'created_at', 'updated_at', 'confidence', CREATED_BY_FIELD, `${RULE_PREFIX}*`];
const HISTORY_ASSERTION_SCOPES = ['create', 'update', 'merge'];
// Bounds of one batch: distinct writers kept per element, work windows loaded to disambiguate shared users
const MAX_USERS_PER_ELEMENT = 50;
const MAX_WORKS_PER_BATCH = 2000;

type BackfillElement = BasicStoreBase & {
  _index: string;
  creator_id?: string | string[];
  created_at?: string | Date;
  updated_at?: string | Date;
  confidence?: number | null;
  [key: string]: any;
};

/** Writes of one user on one element, as found in the history (or its creator list when the history was purged). */
export interface BackfillUserActivity {
  user_id: string;
  first: string;
  last: string;
  count: number;
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
 */
export const computeBackfillAssertions = async (
  element: BackfillElement,
  history: BackfillUserActivity[],
  resolveSource: BackfillSourceResolver,
  authorNames: Map<string, string> = new Map(),
): Promise<StoreAssertion[]> => {
  const reference = now();
  const createdAt = toIso(element.created_at, reference);
  const updatedAt = toIso(element.updated_at, createdAt);
  const confidence = element.confidence ?? null;
  const creators = toArray(element.creator_id);
  const activities = new Map(history.map((activity) => [activity.user_id, { ...activity }]));
  creators.forEach((creatorId, index) => {
    if (!activities.has(creatorId)) {
      // History purged by retention: creation date for the first creator, last update for the others
      const at = index === 0 ? createdAt : updatedAt;
      activities.set(creatorId, { user_id: creatorId, first: at, last: at, count: 1 });
    }
  });
  const assertions = new Map<string, StoreAssertion>();
  const authorId: string | undefined = toArray(element[CREATED_BY_FIELD])[0];
  const activityList = Array.from(activities.values()).slice(0, MAX_USERS_PER_ELEMENT);
  for (let index = 0; index < activityList.length; index += 1) {
    const activity = activityList[index];
    if (activity.user_id === RULE_MANAGER_USER.id) {
      continue; // inference sources come from the rules stored on the element
    }
    const firstSource = await resolveSource(activity.user_id, activity.first);
    const isHumanCreator = firstSource.source_kind === SOURCE_KIND_USER && activity.user_id === creators[0];
    if (isHumanCreator && authorId) {
      const author: AssertionSource = { source_id: authorId, source_kind: SOURCE_KIND_AUTHOR, source_name: authorNames.get(authorId) ?? authorId, work_id: null };
      mergeAssertion(assertions, buildBackfillAssertion(author, activity.first, activity.last, activity.count, confidence));
    } else if (activity.count > 1 && activity.last !== activity.first) {
      const lastSource = await resolveSource(activity.user_id, activity.last);
      if (lastSource.source_id === firstSource.source_id) {
        mergeAssertion(assertions, buildBackfillAssertion(lastSource, activity.first, activity.last, activity.count, confidence));
      } else {
        mergeAssertion(assertions, buildBackfillAssertion(firstSource, activity.first, activity.first, 1, confidence));
        mergeAssertion(assertions, buildBackfillAssertion(lastSource, activity.last, activity.last, activity.count - 1, confidence));
      }
    } else {
      mergeAssertion(assertions, buildBackfillAssertion(firstSource, activity.first, activity.last, activity.count, confidence));
    }
  }
  const ruleKeys = Object.keys(element).filter((key) => key.startsWith(RULE_PREFIX) && Array.isArray(element[key]) && element[key].length > 0);
  ruleKeys.forEach((key) => {
    mergeAssertion(assertions, buildBackfillAssertion(sourceFromRule(key), createdAt, updatedAt, 1, confidence));
  });
  return Array.from(assertions.values());
};

// region data loading
const aggregateHistoryActivities = async (context: AuthContext, ids: string[]) => {
  const query = {
    index: READ_INDEX_HISTORY,
    body: {
      size: 0,
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': ENTITY_TYPE_HISTORY } },
            { terms: { 'context_data.id.keyword': ids } },
            { terms: { 'event_scope.keyword': HISTORY_ASSERTION_SCOPES } },
          ],
        },
      },
      aggs: {
        elements: {
          terms: { field: 'context_data.id.keyword', size: ids.length },
          aggs: {
            users: {
              terms: { field: 'user_id.keyword', size: MAX_USERS_PER_ELEMENT },
              aggs: { first: { min: { field: 'timestamp' } }, last: { max: { field: 'timestamp' } } },
            },
          },
        },
      },
    },
  };
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_HISTORY, query);
  const activities = new Map<string, BackfillUserActivity[]>();
  const elementBuckets = data.aggregations?.elements?.buckets ?? [];
  for (let index = 0; index < elementBuckets.length; index += 1) {
    const bucket = elementBuckets[index];
    activities.set(bucket.key, (bucket.users?.buckets ?? []).map((userBucket: any) => ({
      user_id: userBucket.key,
      first: new Date(userBucket.first.value).toISOString(),
      last: new Date(userBucket.last.value).toISOString(),
      count: userBucket.doc_count,
    })));
  }
  return activities;
};

const loadWorkWindows = async (context: AuthContext, connectorIds: string[], from: string, to: string): Promise<BackfillWorkWindow[]> => {
  if (connectorIds.length === 0) {
    return [];
  }
  const query = {
    index: READ_INDEX_HISTORY,
    body: {
      size: MAX_WORKS_PER_BATCH,
      _source: ['internal_id', 'connector_id', 'timestamp', 'completed_time', 'updated_at'],
      sort: [{ timestamp: 'desc' }],
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
    },
  };
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_WORK, query);
  const reference = now();
  return (data.hits?.hits ?? []).map((hit: any) => {
    const work = hit._source;
    return {
      id: work.internal_id,
      connector_id: work.connector_id,
      start: toIso(work.timestamp, reference),
      end: toIso(work.completed_time ?? work.updated_at, reference),
    };
  });
};

/**
 * Works of the connectors sharing a user, in the time range of the writes of these users.
 */
const loadSharedUsersWorkWindows = async (
  context: AuthContext,
  connectorsByUser: Map<string, BasicStoreEntityConnector[]>,
  activities: BackfillUserActivity[],
) => {
  const sharedUsers = new Set(Array.from(connectorsByUser.entries()).filter(([, userConnectors]) => userConnectors.length > 1).map(([userId]) => userId));
  const sharedActivities = activities.filter((activity) => sharedUsers.has(activity.user_id));
  if (sharedActivities.length === 0) {
    return [];
  }
  const connectorIds = Array.from(sharedUsers).flatMap((userId) => (connectorsByUser.get(userId) ?? []).map((connector) => connector.internal_id));
  const from = sharedActivities.reduce((min, activity) => (activity.first < min ? activity.first : min), sharedActivities[0].first);
  const to = sharedActivities.reduce((max, activity) => (activity.last > max ? activity.last : max), sharedActivities[0].last);
  return loadWorkWindows(context, connectorIds, from, to);
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
 * Restart the backfill from the beginning. Replays are idempotent: counts are merged with a max.
 */
export const restartProvenanceBackfill = async (context: AuthContext) => {
  const configuration = await loadBackfillConfiguration(context);
  if (!configuration) {
    return DEFAULT_PROVENANCE_BACKFILL_STATE;
  }
  const state = { ...DEFAULT_PROVENANCE_BACKFILL_STATE };
  await saveBackfillState(context, configuration.id, state, new Date());
  return state;
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
  if (state.status === 'pending') {
    state.status = 'running';
    state.started_at = runStart.toISOString();
    state.cursor = null;
    state.processed = 0;
    state.updated = 0;
    state.errors = 0;
    state.expected = await elCount(context, SYSTEM_USER, BACKFILL_INDICES, { types: BACKFILL_TYPES });
  }
  const page = await elPaginate<BackfillElement>(context, SYSTEM_USER, BACKFILL_INDICES, {
    types: BACKFILL_TYPES,
    first: opts.batchSize,
    after: state.cursor,
    baseData: true,
    baseFields: BACKFILL_FIELDS,
    withoutRels: false,
    withResultMeta: true,
  }) as unknown as { elements: { edges: { node: BackfillElement }[]; pageInfo: { hasNextPage: boolean } }; endCursor: string | null };
  const elements = page.elements.edges.map((edge) => edge.node);
  if (elements.length > 0) {
    const activities = await aggregateHistoryActivities(context, elements.map((element) => element.internal_id));
    const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
    const connectorsByUser = new Map<string, BasicStoreEntityConnector[]>();
    connectors.forEach((connector) => {
      if (connector.connector_user_id) {
        connectorsByUser.set(connector.connector_user_id, [...(connectorsByUser.get(connector.connector_user_id) ?? []), connector]);
      }
    });
    const works = await loadSharedUsersWorkWindows(context, connectorsByUser, Array.from(activities.values()).flat());
    const resolveSource = createBackfillSourceResolver(context, connectorsByUser, works);
    const authorIds = [...new Set(elements.flatMap((element) => toArray(element[CREATED_BY_FIELD])))];
    const authors = authorIds.length > 0
      ? await internalFindByIds<BasicStoreEntity & { name: string }>(context, SYSTEM_USER, authorIds, { baseData: true, baseFields: ['name'] }) as (BasicStoreEntity & { name: string })[]
      : [];
    const authorNames = new Map(authors.map((author) => [author.internal_id, author.name]));
    for (let index = 0; index < elements.length; index += 1) {
      const element = elements[index];
      try {
        const assertions = await computeBackfillAssertions(element, activities.get(element.internal_id) ?? [], resolveSource, authorNames);
        if (assertions.length > 0) {
          await applyProvenanceUpdate(context, element, { assertions, countMode: 'max' });
          state.updated += 1;
        }
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
