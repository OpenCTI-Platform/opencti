import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreCommon, BasicStoreEntity } from '../../types/store';
import type { FieldAuthorityDecision, FieldAuthorityResolver } from '../../database/merge-hooks';
import { getEntitiesListFromCache } from '../../database/cache';
import { elUpdate } from '../../database/engine';
import { wait } from '../../database/utils';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { SYSTEM_USER } from '../../utils/access';
import { logApp } from '../../config/conf';
import { now } from '../../utils/format';
import { AUTHORITY_SOURCE_AUTHOR, AUTHORITY_SOURCE_CONNECTOR, type FieldAuthorityRule, type FieldAuthoritySource } from './curation-types';
import { getCurationSettings } from './curation-settings';

export const FIELD_AUTHORITY_ATTRIBUTE = 'i_field_authority';

export interface FieldAuthorityEntry {
  attribute: string;
  source_type: string;
  source_id: string;
  updated_at: string;
}

const UNRANKED = Number.MAX_SAFE_INTEGER;
// Writer recorded for a value written with neither an author nor a connector: no rule can rank it.
const UNRANKED_WRITER = { source_type: 'unranked', source_id: 'unranked' };

export const rankSource = (rule: FieldAuthorityRule, sources: FieldAuthoritySource[]): number => {
  let best = UNRANKED;
  sources.forEach((source) => {
    const position = rule.sources.findIndex((ruleSource) => ruleSource.source_type === source.source_type && ruleSource.source_id === source.source_id);
    if (position !== -1 && position < best) best = position;
  });
  return best;
};

export const isRankedSource = (rule: FieldAuthorityRule, sources: FieldAuthoritySource[]) => rankSource(rule, sources) !== UNRANKED;

/**
 * Field authority decision for one attribute: a strictly more authoritative incoming source is allowed whatever its
 * confidence, a strictly less authoritative one is denied whatever its confidence, otherwise (same rank or no ranked
 * source at all) the decision is left to the confidence comparison.
 */
export const decideFieldAuthority = (
  rule: FieldAuthorityRule,
  incoming: FieldAuthoritySource[],
  current: FieldAuthoritySource[],
): FieldAuthorityDecision | undefined => {
  const incomingRank = rankSource(rule, incoming);
  const currentRank = rankSource(rule, current);
  if (incomingRank === UNRANKED && currentRank === UNRANKED) return undefined;
  if (incomingRank < currentRank) return 'allow';
  if (incomingRank > currentRank) return 'deny';
  return undefined;
};

const refId = (value: unknown): string | undefined => {
  if (!value) return undefined;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return refId(value[0]);
  return (value as { internal_id?: string; id?: string }).internal_id ?? (value as { id?: string }).id;
};

type ConnectorUser = Pick<BasicStoreEntity, 'internal_id'> & { connector_user_id?: string };

const connectorSourcesOf = (connectors: ConnectorUser[], userId: string | undefined): FieldAuthoritySource[] => {
  if (!userId) return [];
  return connectors
    .filter((connector) => connector.connector_user_id && connector.connector_user_id === userId)
    .map((connector) => ({ source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: connector.internal_id }));
};

const incomingSources = (user: AuthUser, patch: Record<string, unknown>, connectors: ConnectorUser[]): FieldAuthoritySource[] => {
  const sources: FieldAuthoritySource[] = [];
  const authorId = refId(patch.createdBy);
  if (authorId) sources.push({ source_type: AUTHORITY_SOURCE_AUTHOR, source_id: authorId });
  sources.push(...connectorSourcesOf(connectors, user.id));
  return sources;
};

/**
 * Sources of the current values of an entity no listed source wrote yet: the author of the entity and the connector
 * that created it (its first creator), so a value created by a connector keeps that connector's rank.
 */
export const creationSources = (element: Record<string, any>, connectors: ConnectorUser[]): FieldAuthoritySource[] => {
  const sources: FieldAuthoritySource[] = [];
  const authorId = refId(element.createdBy) ?? refId(element['created-by']);
  if (authorId) sources.push({ source_type: AUTHORITY_SOURCE_AUTHOR, source_id: authorId });
  const creators = element.creator_id;
  const creatorId = Array.isArray(creators) ? creators[0] : creators;
  sources.push(...connectorSourcesOf(connectors, typeof creatorId === 'string' ? creatorId : undefined));
  return sources;
};

/** Sources of the current value of an attribute: the source recorded for it, else the sources the entity was created with. */
export const recordedSources = (element: BasicStoreCommon, attribute: string, connectors: ConnectorUser[]): FieldAuthoritySource[] => {
  const entries = ((element as Record<string, any>)[FIELD_AUTHORITY_ATTRIBUTE] ?? []) as FieldAuthorityEntry[];
  const entry = entries.find((e) => e.attribute === attribute);
  if (entry) {
    return [{ source_type: entry.source_type as FieldAuthoritySource['source_type'], source_id: entry.source_id }];
  }
  return creationSources(element as Record<string, any>, connectors);
};

/**
 * Sources of the value an update replaced, read once the update is done: an upsert records its own source right after
 * its write, so a record that is not older than the update is the one of the update itself, and the replaced value has
 * no known source.
 */
export const recordedSourcesBefore = (element: BasicStoreCommon, attribute: string, connectors: ConnectorUser[], updatedAt?: string): FieldAuthoritySource[] => {
  const entries = ((element as Record<string, any>)[FIELD_AUTHORITY_ATTRIBUTE] ?? []) as FieldAuthorityEntry[];
  const entry = entries.find((e) => e.attribute === attribute);
  if (entry && updatedAt && Date.parse(entry.updated_at) >= Date.parse(updatedAt)) return [];
  return recordedSources(element, attribute, connectors);
};

/**
 * Sources of the value an update wrote, as the write ranked them (its author or its connector): the record of the update
 * itself, only while the entity was not updated since, so that a later write never lends its source to an earlier one.
 */
export const recordedSourcesOfUpdate = (element: BasicStoreCommon, attribute: string, updatedAt?: string): FieldAuthoritySource[] => {
  if (!updatedAt || Date.parse((element as Record<string, any>).updated_at) !== Date.parse(updatedAt)) return [];
  const entries = ((element as Record<string, any>)[FIELD_AUTHORITY_ATTRIBUTE] ?? []) as FieldAuthorityEntry[];
  const entry = entries.find((e) => e.attribute === attribute);
  if (!entry || Date.parse(entry.updated_at) < Date.parse(updatedAt)) return [];
  return [{ source_type: entry.source_type as FieldAuthoritySource['source_type'], source_id: entry.source_id }];
};

const rulesFor = async (context: AuthContext, type: string) => {
  const settings = await getCurationSettings(context);
  if (!settings.field_authority_enabled) return [];
  return settings.field_authority_rules.filter((rule) => rule.entity_type === type);
};

const BOOKKEEPING_ATTEMPTS = 3;
const BOOKKEEPING_RETRY_MS = 200;

const EL_FIELD_AUTHORITY_SCRIPT = `
  if (ctx._source[params.field] == null) { ctx._source[params.field] = []; }
  for (entry in params.entries) {
    ctx._source[params.field].removeIf(item -> item.attribute == entry.attribute);
    ctx._source[params.field].add(entry);
  }`;

export const curationFieldAuthorityResolver: FieldAuthorityResolver = {
  governs: async (context, type, patch) => {
    if (context.synchronizedUpsert) return false;
    const rules = await rulesFor(context, type);
    return rules.some((rule) => rule.attribute in patch);
  },
  resolve: async (context, user, element, type, patch) => {
    const decisions = new Map<string, FieldAuthorityDecision>();
    if (context.synchronizedUpsert) return decisions;
    const rules = await rulesFor(context, type);
    if (rules.length === 0) return decisions;
    const ruled = rules.filter((rule) => rule.attribute in patch);
    if (ruled.length === 0) return decisions;
    const connectors = await getEntitiesListFromCache<BasicStoreEntity & { connector_user_id?: string }>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
    const incoming = incomingSources(user, patch, connectors);
    ruled.forEach((rule) => {
      const decision = decideFieldAuthority(rule, incoming, recordedSources(element, rule.attribute, connectors));
      if (decision) decisions.set(rule.attribute, decision);
    });
    return decisions;
  },
  recordApplied: async (context, user, element, type, patch, appliedKeys) => {
    if (context.synchronizedUpsert) return;
    const rules = (await rulesFor(context, type)).filter((rule) => appliedKeys.includes(rule.attribute));
    if (rules.length === 0) return;
    const connectors = await getEntitiesListFromCache<BasicStoreEntity & { connector_user_id?: string }>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
    const incoming = incomingSources(user, patch, connectors);
    // The writer of a value is recorded even when the rule does not rank it: the source recorded before, or the creation
    // sources, would otherwise be taken for the writer of the value once ranked again.
    const entries: FieldAuthorityEntry[] = rules.map((rule) => {
      const rank = rankSource(rule, incoming);
      const source = rank === UNRANKED ? (incoming[0] ?? UNRANKED_WRITER) : rule.sources[rank];
      return { attribute: rule.attribute, source_type: source.source_type, source_id: source.source_id, updated_at: now() };
    });
    // A stale record would let a less authoritative source overwrite the value: the write is retried, then the upsert
    // fails, so the bundle is processed again and the replay records the source (see the upsert without change).
    for (let attempt = 1; ; attempt += 1) {
      try {
        await elUpdate(context, element._index, element.internal_id, {
          script: { source: EL_FIELD_AUTHORITY_SCRIPT, lang: 'painless', params: { field: FIELD_AUTHORITY_ATTRIBUTE, entries } },
        });
        return;
      } catch (error) {
        if (attempt >= BOOKKEEPING_ATTEMPTS) {
          logApp.error('[CURATION] Cannot record field authority bookkeeping', { cause: error, id: element.internal_id, attempts: attempt });
          throw error;
        }
        await wait(BOOKKEEPING_RETRY_MS * attempt);
      }
    }
  },
};
