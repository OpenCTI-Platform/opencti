import { v5 as uuidv5 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityConnector } from '../../types/connector';
import type { BasicStoreEntity } from '../../types/store';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { fullEntitiesList } from '../../database/middleware-loader';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_USER } from '../../schema/internalObject';
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
import {
  type AssertionSource,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_EMULATION,
  SOURCE_KIND_FEED,
  SOURCE_KIND_INFERENCE,
  SOURCE_KIND_USER,
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

const refreshFeedIndex = async (context: AuthContext, isMiss: boolean) => {
  const age = Date.now() - feedIndex.loadedAt;
  if (age > FEED_INDEX_TTL_MS || (isMiss && age > FEED_INDEX_MISS_REFRESH_MS)) {
    try {
      await loadFeedIndex(context);
    } catch (err) {
      logApp.warn('[PROVENANCE] Unable to refresh the ingestion feeds index', { cause: err });
    }
  }
};

const resolveFeedOfConnector = async (context: AuthContext, connectorId: string): Promise<FeedReference | undefined> => {
  await refreshFeedIndex(context, !feedIndex.byConnectorId.has(connectorId));
  return feedIndex.byConnectorId.get(connectorId);
};

/**
 * Synchronizer behind a synchronized write, when its user is not shared with another synchronizer.
 */
const resolveSynchronizerOfUser = async (context: AuthContext, userId: string): Promise<FeedReference | undefined> => {
  await refreshFeedIndex(context, !feedIndex.synchronizersByUser.has(userId));
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
