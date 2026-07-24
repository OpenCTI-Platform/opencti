import { type Filter, type FilterGroup, FilterOperator } from '../generated/graphql';
import { ASSIGNEE_FILTER, CREATOR_FILTER, PARTICIPANT_FILTER } from './filtering/filtering-constants';
import { isInternalId } from '../schema/schemaUtils';

/**
 * PoC #2 (merge users investigation) - distributed alias prototype.
 *
 * The iteration deliberately exposes separate operations because one global
 * source-to-target replacement is not correct in every context:
 * - display and new operational writes canonicalize to the target;
 * - searches expand the target to all physical aliases;
 * - aggregations coalesce physical buckets under the target;
 * - authorization and historical attribution are not passed through this module.
 *
 * It is opt-in only. With the env var unset, every operation is a no-op.
 *
 * Enable with:
 *   MERGE_POC_ALIAS_MAP='{"<sourceUserId>":"<targetUserId>"}'
 */

let cachedRawValue: string | undefined;
let cachedAliasMap: Map<string, string> = new Map();

const parseAliasMap = (raw: string | undefined): Map<string, string> => {
  if (!raw) {
    return new Map();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error('MERGE_POC_ALIAS_MAP must be a JSON object mapping source user ids to target user ids', { cause: error });
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('MERGE_POC_ALIAS_MAP must be a JSON object mapping source user ids to target user ids');
  }

  const aliasMap = new Map<string, string>();
  for (const [sourceId, targetId] of Object.entries(parsed)) {
    if (!sourceId || typeof targetId !== 'string' || !targetId) {
      throw new Error('MERGE_POC_ALIAS_MAP entries must contain non-empty string user ids');
    }
    if (!isInternalId(sourceId) || !isInternalId(targetId)) {
      throw new Error('MERGE_POC_ALIAS_MAP entries must contain internal user ids');
    }
    aliasMap.set(sourceId, targetId);
  }

  for (const sourceId of aliasMap.keys()) {
    const visited = new Set<string>();
    let currentId = sourceId;
    while (aliasMap.has(currentId)) {
      if (visited.has(currentId)) {
        throw new Error(`MERGE_POC_ALIAS_MAP contains a cycle involving user ${currentId}`);
      }
      visited.add(currentId);
      currentId = aliasMap.get(currentId) as string;
    }
  }

  return aliasMap;
};

// Lazily parsed (and re-parsed if the env var changes, e.g. between test cases).
const getMergeUsersPocAliasMap = (): Map<string, string> => {
  const raw = process.env.MERGE_POC_ALIAS_MAP;
  if (raw !== cachedRawValue) {
    const aliasMap = parseAliasMap(raw);
    cachedRawValue = raw;
    cachedAliasMap = aliasMap;
  }
  return cachedAliasMap;
};

/**
 * Canonicalizes an id for display or a new operational write.
 */
export const resolveMergeUsersPocAliasId = (id: string): string => {
  const aliasMap = getMergeUsersPocAliasMap();
  let resolvedId = id;
  while (aliasMap.has(resolvedId)) {
    resolvedId = aliasMap.get(resolvedId) as string;
  }
  return resolvedId;
};

export const canonicalizeMergeUsersPocAliasIds = (ids: string[]): string[] => {
  return [...new Set(ids.map((id) => resolveMergeUsersPocAliasId(id)))];
};

/**
 * Expands a logical user id to every id under which operational data may still
 * be physically stored.
 */
export const expandMergeUsersPocAliasIds = (ids: string[]): string[] => {
  const aliasMap = getMergeUsersPocAliasMap();
  const expandedIds = ids.flatMap((id) => {
    const targetId = resolveMergeUsersPocAliasId(id);
    const sourceIds = [...aliasMap.keys()].filter((sourceId) => resolveMergeUsersPocAliasId(sourceId) === targetId);
    return [targetId, ...sourceIds];
  });
  return [...new Set(expandedIds)];
};

export const getMergeUsersPocCanonicalAliasMap = (): Record<string, string> => {
  const canonicalAliases = [...getMergeUsersPocAliasMap().keys()].map((sourceId) => {
    return [sourceId, resolveMergeUsersPocAliasId(sourceId)];
  });
  return Object.fromEntries(canonicalAliases);
};

const USER_OPERATIONAL_FILTER_KEYS = new Set([
  CREATOR_FILTER,
  ASSIGNEE_FILTER,
  PARTICIPANT_FILTER,
  'creator_id',
  'rel_object-assignee.internal_id',
  'rel_object-participant.internal_id',
]);

const expandOperationalFilter = (filter: Filter): Filter => {
  const rawKey = filter.key as unknown as string | string[];
  const keys = Array.isArray(rawKey) ? rawKey : [rawKey];
  const isOperationalUserFilter = keys.length === 1 && USER_OPERATIONAL_FILTER_KEYS.has(keys[0]);
  const isEqualityFilter = filter.operator === undefined
    || filter.operator === null
    || filter.operator === FilterOperator.Eq
    || filter.operator === FilterOperator.NotEq;
  if (!isOperationalUserFilter || !isEqualityFilter) {
    return filter;
  }

  const expandedValues = filter.values.flatMap((value) => {
    return typeof value === 'string' ? expandMergeUsersPocAliasIds([value]) : [value];
  });
  return { ...filter, values: [...new Set(expandedValues)] };
};

interface MergeUsersPocAliasUpdateInput {
  key: string;
  value?: unknown[] | null;
  operation?: string | null;
}

const USER_OPERATIONAL_WRITE_KEYS = new Set([
  'creator_id',
  ASSIGNEE_FILTER,
  PARTICIPANT_FILTER,
]);

export const canonicalizeMergeUsersPocAliasUpdateInputs = <T extends MergeUsersPocAliasUpdateInput>(inputs: T[]): T[] => {
  return inputs.map((input) => {
    if (!USER_OPERATIONAL_WRITE_KEYS.has(input.key) || input.value === null || input.value === undefined) {
      return input;
    }
    const aliasAwareValues = input.value.flatMap((value) => {
      if (typeof value !== 'string') {
        return [value];
      }
      return input.operation === 'remove'
        ? expandMergeUsersPocAliasIds([value])
        : [resolveMergeUsersPocAliasId(value)];
    });
    return { ...input, value: [...new Set(aliasAwareValues)] };
  });
};

/**
 * Expands only operational user filters. Security filters such as
 * restricted_members and historical references such as createdBy remain exact.
 */
export const expandMergeUsersPocAliasFilterGroup = (filterGroup: FilterGroup): FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map(expandOperationalFilter),
    filterGroups: filterGroup.filterGroups.map(expandMergeUsersPocAliasFilterGroup),
  };
};

export interface MergeUsersPocAliasAggregationBucket {
  key: string;
  doc_count: number;
  [key: string]: unknown;
}

export const coalesceMergeUsersPocAliasAggregationBuckets = (
  buckets: MergeUsersPocAliasAggregationBucket[],
): MergeUsersPocAliasAggregationBucket[] => {
  const bucketsByTarget = new Map<string, MergeUsersPocAliasAggregationBucket>();
  for (const bucket of buckets) {
    const targetId = resolveMergeUsersPocAliasId(bucket.key);
    const existingBucket = bucketsByTarget.get(targetId);
    bucketsByTarget.set(targetId, {
      ...(existingBucket ?? bucket),
      key: targetId,
      doc_count: (existingBucket?.doc_count ?? 0) + bucket.doc_count,
    });
  }
  return [...bucketsByTarget.values()];
};

export const isMergeUsersPocAliasEnabled = (): boolean => getMergeUsersPocAliasMap().size > 0;
