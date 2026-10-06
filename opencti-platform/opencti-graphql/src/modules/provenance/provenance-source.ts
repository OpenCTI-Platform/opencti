import { v5 as uuidv5 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityConnector } from '../../types/connector';
import type { BasicStoreEntity } from '../../types/store';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { elRawSearch } from '../../database/engine';
import { READ_INDEX_HISTORY } from '../../database/utils';
import { fullEntitiesList } from '../../database/middleware-loader';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_USER, ENTITY_TYPE_WORK } from '../../schema/internalObject';
import { OPENCTI_NAMESPACE, RULE_PREFIX } from '../../schema/general';
import { INTERNAL_USERS, RULE_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { rule_definitions } from '../../rules/rules-definition';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../ingestion/ingestion-types';
import { ENTITY_TYPE_FORM } from '../form/form-types';
import { logApp } from '../../config/conf';
import { DatabaseError } from '../../config/errors';
import {
  type AssertionSource,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_EMULATION,
  SOURCE_KIND_FEED,
  SOURCE_KIND_INFERENCE,
  SOURCE_KIND_USER,
  type StoreAssertion,
} from './provenance-types';

const WORK_ID_PREFIX = 'work_';
const FEED_TYPES = [
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_FORM,
];
const FEED_INDEX_TTL_MS = 5 * 60 * 1000;
const FEED_INDEX_MISS_REFRESH_MS = 60 * 1000;
const OPENAEV_COVERAGE_CONNECTOR_PREFIX = 'openaev coverage';
const BUILT_IN_FEED_NAME_PREFIX = /^\[FEED - [^\]]+\]\s*/;

type FeedReference = { id: string; name: string };
const feedIndex: { byConnectorId: Map<string, FeedReference>; synchronizersByUser: Map<string, FeedReference[]>; loadedAt: number } = {
  byConnectorId: new Map(),
  synchronizersByUser: new Map(),
  loadedAt: 0,
};

/**
 * Work ids are generated as work_<connectorId>_<ISO timestamp>, the connector id is read without any lookup.
 */
export const connectorIdFromWorkId = (workId: string | undefined | null): string | null => {
  if (!workId || !workId.startsWith(WORK_ID_PREFIX)) {
    return null;
  }
  const lastSeparator = workId.lastIndexOf('_');
  if (lastSeparator <= WORK_ID_PREFIX.length) {
    return null;
  }
  return workId.substring(WORK_ID_PREFIX.length, lastSeparator);
};

export const isOpenAevCoverageConnector = (connector: Pick<BasicStoreEntityConnector, 'name'>) => {
  return (connector.name ?? '').toLowerCase().startsWith(OPENAEV_COVERAGE_CONNECTOR_PREFIX);
};

const loadFeedIndex = async (context: AuthContext) => {
  const feeds = await fullEntitiesList<BasicStoreEntity & { name: string }>(context, SYSTEM_USER, FEED_TYPES);
  const byConnectorId = new Map<string, FeedReference>();
  for (let index = 0; index < feeds.length; index += 1) {
    const feed = feeds[index];
    byConnectorId.set(uuidv5(feed.internal_id, OPENCTI_NAMESPACE), { id: feed.internal_id, name: feed.name });
  }
  // Synchronizers (remote OpenCTI streams) push their bundles without work, they are known by their user
  const synchronizers = await fullEntitiesList<BasicStoreEntity & { name: string; user_id?: string }>(context, SYSTEM_USER, [ENTITY_TYPE_SYNC]);
  const synchronizersByUser = new Map<string, FeedReference[]>();
  for (let index = 0; index < synchronizers.length; index += 1) {
    const synchronizer = synchronizers[index];
    if (synchronizer.user_id) {
      synchronizersByUser.set(synchronizer.user_id, [...(synchronizersByUser.get(synchronizer.user_id) ?? []), { id: synchronizer.internal_id, name: synchronizer.name }]);
    }
  }
  feedIndex.byConnectorId = byConnectorId;
  feedIndex.synchronizersByUser = synchronizersByUser;
  feedIndex.loadedAt = Date.now();
};

// Keys a load did not find, with the time of that load: they are looked up again only after FEED_INDEX_MISS_REFRESH_MS
const confirmedMisses = new Map<string, number>();
// One load at a time: a load only starts when none is in flight, and not before FEED_INDEX_MISS_REFRESH_MS after a failure
let feedIndexLoad: Promise<boolean> | undefined;
let feedIndexFailedAt = 0;

const startFeedIndexLoad = (context: AuthContext): Promise<boolean> => {
  const load: Promise<boolean> = loadFeedIndex(context)
    .then(() => true)
    .catch((err) => {
      feedIndexFailedAt = Date.now();
      logApp.warn('[PROVENANCE] Unable to refresh the ingestion feeds index', { cause: err });
      return false;
    })
    .finally(() => {
      if (feedIndexLoad === load) {
        feedIndexLoad = undefined;
      }
    });
  feedIndexLoad = load;
  return load;
};

// Whether a load ran and succeeded: the load in flight, otherwise a new one
const runFeedIndexLoad = (context: AuthContext): Promise<boolean> => {
  if (feedIndexLoad) {
    return feedIndexLoad;
  }
  return Date.now() - feedIndexFailedAt > FEED_INDEX_MISS_REFRESH_MS ? startFeedIndexLoad(context) : Promise.resolve(false);
};

/**
 * An expired index is refreshed by any load, the one in flight included. A key missing from the index is looked up in
 * a load started after the request: resolving a feed or a synchronizer created since the last load to another source
 * until the next refresh would count the same source twice. A key that such a load did not find either is not looked
 * up again before FEED_INDEX_MISS_REFRESH_MS.
 * Concurrent callers share the load in flight, and the callers it did not satisfy share the next one.
 * Returns false when the key is missing and no load could confirm it, the index being unavailable.
 */
const refreshFeedIndex = async (context: AuthContext, key: string, isIndexed: () => boolean): Promise<boolean> => {
  const expired = Date.now() - feedIndex.loadedAt > FEED_INDEX_TTL_MS;
  // Outcome of a load started after the request, undefined until one ran
  let loadedSinceRequest: boolean | undefined;
  if (feedIndexLoad && (expired || !isIndexed())) {
    // The load in flight refreshes an expired index and may already hold a missing key, but it started before the request
    await feedIndexLoad;
  } else if (expired) {
    loadedSinceRequest = await runFeedIndexLoad(context);
  }
  if (isIndexed()) {
    confirmedMisses.delete(key);
    return true;
  }
  const missedAt = confirmedMisses.get(key);
  if (missedAt !== undefined && Date.now() - missedAt <= FEED_INDEX_MISS_REFRESH_MS) {
    return true;
  }
  if (loadedSinceRequest === undefined) {
    // Any load in flight now started after the one awaited above ended, so after the request: it is shared
    loadedSinceRequest = await runFeedIndexLoad(context);
  }
  if (isIndexed()) {
    confirmedMisses.delete(key);
    return true;
  }
  if (loadedSinceRequest) {
    confirmedMisses.set(key, Date.now());
  }
  return loadedSinceRequest;
};

// A source keeps one identity: while the index cannot tell, the write gets no source rather than a temporary one
const throwFeedIndexUnavailable = (data: Record<string, string>): never => {
  throw DatabaseError('Ingestion feeds index unavailable, the source of this write cannot be resolved', data);
};

const resolveFeedOfConnector = async (context: AuthContext, connectorId: string): Promise<FeedReference | undefined> => {
  if (!(await refreshFeedIndex(context, `connector:${connectorId}`, () => feedIndex.byConnectorId.has(connectorId)))) {
    throwFeedIndexUnavailable({ connector_id: connectorId });
  }
  return feedIndex.byConnectorId.get(connectorId);
};

/**
 * Synchronizer behind a synchronized write, when its user is not shared with another synchronizer.
 */
const resolveSynchronizerOfUser = async (context: AuthContext, userId: string): Promise<FeedReference | undefined> => {
  if (!(await refreshFeedIndex(context, `user:${userId}`, () => feedIndex.synchronizersByUser.has(userId)))) {
    throwFeedIndexUnavailable({ user_id: userId });
  }
  const synchronizers = feedIndex.synchronizersByUser.get(userId) ?? [];
  return synchronizers.length === 1 ? synchronizers[0] : undefined;
};

const uniqueConnectorOfUser = (connectors: BasicStoreEntityConnector[], userId: string) => {
  const userConnectors = connectors.filter((c) => c.connector_user_id === userId);
  return userConnectors.length === 1 ? userConnectors[0] : undefined;
};

/**
 * Connector responsible for the write: the one of the work being processed if any,
 * otherwise the unique connector running with this user.
 */
const resolveWritingConnector = async (context: AuthContext, user: AuthUser) => {
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  const workConnectorId = connectorIdFromWorkId(context.workId);
  if (workConnectorId) {
    const workConnector = connectors.find((c) => c.internal_id === workConnectorId);
    if (workConnector) {
      return workConnector;
    }
  }
  return uniqueConnectorOfUser(connectors, user.id);
};

export const sourceFromConnector = async (context: AuthContext, connector: BasicStoreEntityConnector, workId: string | null): Promise<AssertionSource> => {
  if (isOpenAevCoverageConnector(connector)) {
    return { source_id: connector.internal_id, source_kind: SOURCE_KIND_EMULATION, source_name: connector.name, work_id: workId };
  }
  if (connector.built_in) {
    const feed = await resolveFeedOfConnector(context, connector.internal_id);
    const feedName = feed?.name ?? connector.name.replace(BUILT_IN_FEED_NAME_PREFIX, '');
    return { source_id: feed?.id ?? connector.internal_id, source_kind: SOURCE_KIND_FEED, source_name: feedName, work_id: workId };
  }
  return { source_id: connector.internal_id, source_kind: SOURCE_KIND_CONNECTOR, source_name: connector.name, work_id: workId };
};

export const sourceFromRule = (fromRule: string | undefined): AssertionSource => {
  const ruleId = fromRule?.startsWith(RULE_PREFIX) ? fromRule.substring(RULE_PREFIX.length) : (fromRule ?? RULE_MANAGER_USER.id);
  const definition = rule_definitions.find((rule) => rule.id === ruleId);
  return { source_id: ruleId, source_kind: SOURCE_KIND_INFERENCE, source_name: definition?.name ?? ruleId, work_id: null };
};

/**
 * Source behind a past write known only by its user id (attribute modifier, creator).
 */
export const resolveSourceOfUser = async (context: AuthContext, userId: string): Promise<AssertionSource> => {
  if (userId === RULE_MANAGER_USER.id) {
    return sourceFromRule(undefined);
  }
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  const connector = uniqueConnectorOfUser(connectors, userId);
  if (connector) {
    return sourceFromConnector(context, connector, null);
  }
  const internalUser = INTERNAL_USERS[userId];
  if (internalUser) {
    return { source_id: userId, source_kind: SOURCE_KIND_USER, source_name: internalUser.name, work_id: null };
  }
  const platformUsers = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return { source_id: userId, source_kind: SOURCE_KIND_USER, source_name: platformUsers.get(userId)?.name ?? userId, work_id: null };
};

/**
 * The connector among the given ones whose work was running at the date, when exactly one of them had one running.
 */
const findConnectorRunningAt = async (context: AuthContext, connectors: BasicStoreEntityConnector[], at: string) => {
  const query = {
    index: READ_INDEX_HISTORY,
    body: {
      size: 0,
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': ENTITY_TYPE_WORK } },
            { terms: { 'connector_id.keyword': connectors.map((connector) => connector.internal_id) } },
            { range: { timestamp: { lte: at } } },
          ],
          // A work that never completed ends at its last update
          should: [
            { range: { completed_time: { gte: at } } },
            { bool: { must_not: { exists: { field: 'completed_time' } }, filter: { range: { updated_at: { gte: at } } } } },
          ],
          minimum_should_match: 1,
        },
      },
      aggs: {
        connectors: {
          terms: { field: 'connector_id.keyword', size: 2 },
          aggs: { work: { top_hits: { size: 1, _source: ['internal_id'] } } },
        },
      },
    },
  };
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_WORK, query);
  const buckets = data.aggregations?.connectors?.buckets ?? [];
  if (buckets.length !== 1) {
    return null;
  }
  const connector = connectors.find((candidate) => candidate.internal_id === buckets[0].key);
  return connector ? { connector, workId: (buckets[0].work?.hits?.hits?.[0]?._source?.internal_id as string | undefined) ?? null } : null;
};

/**
 * Source behind a past write of a user at a known date (attribute modifier, creator), on an element with the given
 * assertions. A user shared by several connectors wrote for the connector whose work was running at that date, as the
 * backfill resolves it, otherwise for the only one of these connectors that asserted the element, provided the user
 * never asserted it directly; when neither tells, the write is resolved like resolveSourceOfUser.
 */
export const resolveSourceOfUserAt = async (
  context: AuthContext,
  userId: string,
  at: string | null,
  assertions: StoreAssertion[],
): Promise<AssertionSource> => {
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  const userConnectors = connectors.filter((connector) => connector.connector_user_id === userId);
  if (userConnectors.length > 1) {
    const running = at ? await findConnectorRunningAt(context, userConnectors, at) : null;
    if (running) {
      return sourceFromConnector(context, running.connector, running.workId);
    }
    if (!assertions.some((assertion) => assertion.source_id === userId)) {
      const candidates = await Promise.all(userConnectors.map((connector) => sourceFromConnector(context, connector, null)));
      const asserted = candidates.filter((candidate) => assertions.some((assertion) => assertion.source_id === candidate.source_id));
      if (asserted.length === 1) {
        return asserted[0];
      }
    }
  }
  return resolveSourceOfUser(context, userId);
};

type ResolvableInput = { createdBy?: { internal_id?: string; name?: string } | null } | null | undefined;

/**
 * Resolve who asserts the written fact.
 * Order: inference engine, OpenAEV coverage (emulation), connector, ingestion feed,
 * author (createdBy of a human write), then the human user itself.
 */
export const resolveAssertionSource = async (
  context: AuthContext,
  user: AuthUser,
  input: ResolvableInput,
  opts: { fromRule?: string } = {},
): Promise<AssertionSource> => {
  const workId = context.workId ?? null;
  if (opts.fromRule || user.id === RULE_MANAGER_USER.id) {
    return sourceFromRule(opts.fromRule);
  }
  const connector = await resolveWritingConnector(context, user);
  if (connector) {
    return sourceFromConnector(context, connector, workId);
  }
  if (context.synchronizedUpsert) {
    const synchronizer = await resolveSynchronizerOfUser(context, user.id);
    if (synchronizer) {
      return { source_id: synchronizer.id, source_kind: SOURCE_KIND_FEED, source_name: synchronizer.name, work_id: workId };
    }
  }
  const author = input?.createdBy;
  if (author?.internal_id) {
    return { source_id: author.internal_id, source_kind: SOURCE_KIND_AUTHOR, source_name: author.name ?? author.internal_id, work_id: workId };
  }
  return { source_id: user.id, source_kind: SOURCE_KIND_USER, source_name: user.name, work_id: workId };
};
