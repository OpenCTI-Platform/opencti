import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, StoreObject } from '../../types/store';
import type { FieldAuthorityDecision, FieldAuthorityResolver } from '../../database/merge-hooks';
import { getEntitiesListFromCache } from '../../database/cache';
import { elUpdate } from '../../database/engine';
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

export const rankSource = (rule: FieldAuthorityRule, sources: FieldAuthoritySource[]): number => {
  let best = UNRANKED;
  sources.forEach((source) => {
    const position = rule.sources.findIndex((ruleSource) => ruleSource.source_type === source.source_type && ruleSource.source_id === source.source_id);
    if (position !== -1 && position < best) best = position;
  });
  return best;
};

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

const incomingSources = async (context: AuthContext, user: AuthUser, patch: Record<string, unknown>): Promise<FieldAuthoritySource[]> => {
  const sources: FieldAuthoritySource[] = [];
  const authorId = refId(patch.createdBy);
  if (authorId) sources.push({ source_type: AUTHORITY_SOURCE_AUTHOR, source_id: authorId });
  const connectors = await getEntitiesListFromCache<BasicStoreEntity & { connector_user_id?: string }>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  connectors
    .filter((connector) => connector.connector_user_id && connector.connector_user_id === user.id)
    .forEach((connector) => sources.push({ source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: connector.internal_id }));
  return sources;
};

const currentSources = (element: StoreObject, attribute: string): FieldAuthoritySource[] => {
  const entries = ((element as Record<string, any>)[FIELD_AUTHORITY_ATTRIBUTE] ?? []) as FieldAuthorityEntry[];
  const entry = entries.find((e) => e.attribute === attribute);
  if (entry) {
    return [{ source_type: entry.source_type as FieldAuthoritySource['source_type'], source_id: entry.source_id }];
  }
  // Without bookkeeping yet, the author of the entity is considered as the source of its current values.
  const authorId = refId((element as Record<string, any>).createdBy) ?? refId((element as Record<string, any>)['created-by']);
  return authorId ? [{ source_type: AUTHORITY_SOURCE_AUTHOR, source_id: authorId }] : [];
};

const rulesFor = async (context: AuthContext, type: string) => {
  const settings = await getCurationSettings(context);
  if (!settings.field_authority_enabled) return [];
  return settings.field_authority_rules.filter((rule) => rule.entity_type === type);
};

const EL_FIELD_AUTHORITY_SCRIPT = `
  if (ctx._source[params.field] == null) { ctx._source[params.field] = []; }
  for (entry in params.entries) {
    ctx._source[params.field].removeIf(item -> item.attribute == entry.attribute);
    ctx._source[params.field].add(entry);
  }`;

export const curationFieldAuthorityResolver: FieldAuthorityResolver = {
  resolve: async (context, user, element, type, patch) => {
    const decisions = new Map<string, FieldAuthorityDecision>();
    if (context.synchronizedUpsert) return decisions;
    const rules = await rulesFor(context, type);
    if (rules.length === 0) return decisions;
    const ruled = rules.filter((rule) => rule.attribute in patch);
    if (ruled.length === 0) return decisions;
    const incoming = await incomingSources(context, user, patch);
    ruled.forEach((rule) => {
      const decision = decideFieldAuthority(rule, incoming, currentSources(element, rule.attribute));
      if (decision) decisions.set(rule.attribute, decision);
    });
    return decisions;
  },
  recordApplied: async (context, user, element, type, patch, appliedKeys) => {
    try {
      const rules = await rulesFor(context, type);
      const incoming = await incomingSources(context, user, patch);
      const entries: FieldAuthorityEntry[] = [];
      rules.filter((rule) => appliedKeys.includes(rule.attribute)).forEach((rule) => {
        const rank = rankSource(rule, incoming);
        if (rank === UNRANKED) return;
        const source = rule.sources[rank];
        entries.push({ attribute: rule.attribute, source_type: source.source_type, source_id: source.source_id, updated_at: now() });
      });
      if (entries.length > 0) {
        await elUpdate(context, element._index, element.internal_id, {
          script: { source: EL_FIELD_AUTHORITY_SCRIPT, lang: 'painless', params: { field: FIELD_AUTHORITY_ATTRIBUTE, entries } },
        });
      }
    } catch (error) {
      // Bookkeeping must never fail an ingestion: the next write of a ranked source records it again.
      logApp.warn('[CURATION] Cannot record field authority bookkeeping', { cause: error, id: element.internal_id });
    }
  },
};
