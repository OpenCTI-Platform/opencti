import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import { elAggregationCount, elBulk, elCount, elRawDeleteByQuery, prepareElementForIndexing } from '../../../database/engine';
import { buildEntityData } from '../../../database/data-builder';
import { internalFindByIds, topEntitiesList } from '../../../database/middleware-loader';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../../database/utils';
import { generateStandardId } from '../../../schema/identifier';
import { FilterMode, FilterOperator, OrderingMode, type Filter, type FilterGroup } from '../../../generated/graphql';
import { HUNT_MANAGER_USER } from '../../../utils/access';
import { doYield } from '../../../utils/eventloop-utils';
import { withHuntLock } from '../hunt-lock';
import { findByIds } from '../hunt-loaders';
import { HUNT_PLATFORM_INTERNET } from '../hunt-types';
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, HUNT_RUN_MODE_EXECUTE } from '../huntRun/huntRun-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_HUNT_HIT_RECORD, type BasicStoreEntityHuntHitRecord } from './huntHitRecord-types';

const BULK_SIZE = 500;
const IDS_CHUNK_SIZE = 1000;
const LEDGER_LOCK = 'hunt_hit_ledger';
// A run is processed again when its completion report is sent again after an interruption, while the other runs of
// its hunt on the platform go on: far fewer of them complete in that time than the runs a record remembers
const COUNTED_RUNS_MAX = 50;
// Late evidence of a run adds the run to the records it finds only while fewer runs than this completed after it: fewer
// than COUNTED_RUNS_MAX other runs can then have been added to a record since the run counted it (the later runs, and
// the earlier ones still within their own window), so the record still tells whether the run counted it
const LATE_EVIDENCE_RUNS_WINDOW = COUNTED_RUNS_MAX / 2;
const RECORD_FIELDS = ['internal_id', 'hit_key', 'first_run_id', 'last_run_id', 'counted_run_ids', 'first_seen', 'times_seen'];

/** The record of a hit of a hunt on a security platform: its ids derive from the three, a run finds it without a search. */
export const huntHitRecordId = (huntId: string, securityPlatformId: string | null | undefined, hitKey: string) => {
  const standardId = generateStandardId(ENTITY_TYPE_HUNT_HIT_RECORD, {
    hunt_id: huntId,
    security_platform_id: securityPlatformId ?? HUNT_PLATFORM_INTERNET,
    hit_key: hitKey,
  });
  return { standardId, internalId: standardId.split('--')[1] };
};

type KnownHit = Pick<BasicStoreEntityHuntHitRecord, 'first_run_id' | 'last_run_id' | 'counted_run_ids'>;

/** The latest runs a record counted; a record written before they were kept knows its last run only. */
const countedRuns = (record: KnownHit) => record.counted_run_ids ?? (record.last_run_id ? [record.last_run_id] : []);

export interface HuntHitClassification {
  newCount: number;
  recurringCount: number;
  // Keys whose record the run creates or updates; a record that already counted the run is left as it is
  toWrite: string[];
}

/**
 * New and recurring hits of a run among its keys, against the records of the hits already known for the hunt on the
 * platform. A hit first recorded by this very run stays new and a record that already counted the run is not updated
 * again, whatever runs were recorded since, so that processing the same run again (its completion report sent again
 * after an interruption) gives the same counts and leaves the records as they are. With keepKnown, for a run the
 * records may have forgotten, only the hits never recorded get a record.
 */
export const classifyHuntHits = (runId: string, keys: string[], known: Map<string, KnownHit>, keepKnown = false): HuntHitClassification => {
  let newCount = 0;
  let recurringCount = 0;
  const toWrite: string[] = [];
  keys.forEach((key) => {
    const record = known.get(key);
    if (!record) {
      newCount += 1;
      toWrite.push(key);
    } else if (record.first_run_id === runId) {
      newCount += 1;
    } else {
      recurringCount += 1;
      if (!keepKnown && !countedRuns(record).includes(runId)) {
        toWrite.push(key);
      }
    }
  });
  return { newCount, recurringCount, toWrite };
};

/** The records of some hits of a hunt on a security platform, by hit key. */
export const findHuntHitRecords = async (context: AuthContext, huntId: string, securityPlatformId: string | null | undefined, keys: string[]) => {
  const byKey = new Map<string, BasicStoreEntityHuntHitRecord>();
  const ids = Array.from(new Set(keys)).map((key) => huntHitRecordId(huntId, securityPlatformId, key).internalId);
  const chunks = R.splitEvery(IDS_CHUNK_SIZE, ids);
  for (let index = 0; index < chunks.length; index += 1) {
    const records = await internalFindByIds<BasicStoreEntityHuntHitRecord>(context, HUNT_MANAGER_USER, chunks[index], {
      type: ENTITY_TYPE_HUNT_HIT_RECORD,
      indices: [READ_INDEX_INTERNAL_OBJECTS],
      baseData: true,
      baseFields: RECORD_FIELDS,
    }) as BasicStoreEntityHuntHitRecord[];
    records.forEach((record) => byKey.set(record.hit_key, record));
  }
  return byKey;
};

// A record found again: one more run, the latest run and date, the values merged. A record that already counted the
// run is left as it is: a hit reported twice by the same run, or by a run processed again after later runs, counts once.
// Late evidence can be older than the last sighting of the hit, so last_seen keeps the later instant (both are
// ISO-8601 UTC strings of the same format, compared as text). updated_at is when a run was last recorded, whatever
// the observation date: the retention reads it, so that evidence of an old event is not forgotten at the next purge
const RECORD_UPDATE_SCRIPT = `
  def runs = new ArrayList();
  def stored = ctx._source.counted_run_ids;
  if (stored instanceof List) { runs.addAll(stored); }
  else if (stored != null) { runs.add(stored); }
  else if (ctx._source.last_run_id != null) { runs.add(ctx._source.last_run_id); }
  if (runs.contains(params.run_id)) { ctx.op = 'noop'; }
  else {
    ctx._source.times_seen = (ctx._source.times_seen == null ? 1 : ctx._source.times_seen) + 1;
    if (ctx._source.last_seen == null || ctx._source.last_seen.compareTo(params.seen_at) < 0) {
      ctx._source.last_seen = params.seen_at;
    }
    ctx._source.updated_at = params.recorded_at;
    ctx._source.last_run_id = params.run_id;
    runs.add(params.run_id);
    while (runs.size() > params.counted_runs_max) { runs.remove(0); }
    ctx._source.counted_run_ids = runs;
    if (params.ioc_keys.size() > 0) {
      def keys = ctx._source.ioc_keys == null ? new ArrayList() : new ArrayList(ctx._source.ioc_keys);
      for (key in params.ioc_keys) { if (!keys.contains(key)) { keys.add(key); } }
      ctx._source.ioc_keys = keys;
    }
  }
`;

export interface HuntHitsRecordInput {
  huntId: string;
  securityPlatformId: string | null | undefined;
  runId: string;
  keys: string[];
  // Indicator hunts: the keys of the values each hit holds, by hit key
  iocKeysByHit?: Map<string, string[]>;
  seenAt: string;
  // Late evidence of a run the records may have forgotten (isHuntRunRemembered): the known records are left as they are
  keepKnown?: boolean;
}

/**
 * Whether the records of the hits of a run still tell whether the run counted them, for its late evidence. The later
 * runs are the execution runs that can have added themselves to a record since: those completed since the run, and
 * those not completed yet, whose late evidence is recorded as well. Translation previews never record hits.
 */
export const isHuntRunRemembered = async (context: AuthContext, run: BasicStoreEntityHuntRun) => {
  if (!run.completed_at) {
    return true;
  }
  const later = await elCount(context, HUNT_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_HUNT_RUN],
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_id'], values: [run.hunt_id] },
        run.security_platform_id
          ? { key: ['security_platform_id'], values: [run.security_platform_id] }
          : { key: ['security_platform_id'], values: [], operator: FilterOperator.Nil },
        { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] },
        { key: ['id'], values: [run.internal_id], operator: FilterOperator.NotEq },
      ],
      filterGroups: [{
        mode: FilterMode.Or,
        filters: [
          { key: ['completed_at'], values: [run.completed_at], operator: FilterOperator.Gte },
          { key: ['completed_at'], values: [], operator: FilterOperator.Nil },
        ],
        filterGroups: [],
      }],
    },
    noFiltersChecking: true,
  });
  return Number(later) < LATE_EVIDENCE_RUNS_WINDOW;
};

/**
 * Matches the hits of a run against the hits already known for its hunt on its security platform, then records them:
 * new hits get a record, known ones one more run. The records are platform bookkeeping written in bulk, without stream
 * event or history; the runs of a hunt on a platform are matched one at a time. Returns the new and recurring counts.
 */
export const recordHuntHits = async (context: AuthContext, input: HuntHitsRecordInput): Promise<{ newCount: number; recurringCount: number }> => {
  const keys = Array.from(new Set(input.keys));
  if (keys.length === 0) {
    return { newCount: 0, recurringCount: 0 };
  }
  const lockKey = `${LEDGER_LOCK}_${input.huntId}_${input.securityPlatformId ?? HUNT_PLATFORM_INTERNET}`;
  const seenAt = new Date(input.seenAt).toISOString();
  const recordedAt = new Date().toISOString();
  return withHuntLock(lockKey, async () => {
    const known = await findHuntHitRecords(context, input.huntId, input.securityPlatformId, keys);
    const { newCount, recurringCount, toWrite } = classifyHuntHits(input.runId, keys, known, input.keepKnown);
    const operations: unknown[] = [];
    for (let index = 0; index < toWrite.length; index += 1) {
      await doYield();
      const key = toWrite[index];
      const iocKeys = input.iocKeysByHit?.get(key) ?? [];
      const { standardId, internalId } = huntHitRecordId(input.huntId, input.securityPlatformId, key);
      const { element } = await buildEntityData(context, HUNT_MANAGER_USER, R.reject(R.isNil, {
        internal_id: internalId,
        standard_id: standardId,
        entity_type: ENTITY_TYPE_HUNT_HIT_RECORD,
        hunt_id: input.huntId,
        security_platform_id: input.securityPlatformId ?? null,
        hit_key: key,
        first_seen: seenAt,
        last_seen: seenAt,
        times_seen: 1,
        first_run_id: input.runId,
        last_run_id: input.runId,
        counted_run_ids: [input.runId],
        ioc_keys: iocKeys,
        created_at: recordedAt,
        updated_at: recordedAt,
      }), ENTITY_TYPE_HUNT_HIT_RECORD);
      const { _index: _ignored, ...upsert } = await prepareElementForIndexing(element);
      const params = { run_id: input.runId, seen_at: seenAt, recorded_at: recordedAt, ioc_keys: iocKeys, counted_runs_max: COUNTED_RUNS_MAX };
      operations.push(
        { update: { _index: INDEX_INTERNAL_OBJECTS, _id: internalId, retry_on_conflict: 5 } },
        { script: { source: RECORD_UPDATE_SCRIPT, lang: 'painless', params }, upsert },
      );
    }
    const groups = R.splitEvery(BULK_SIZE * 2, operations);
    for (let index = 0; index < groups.length; index += 1) {
      await elBulk(context, { refresh: index === groups.length - 1, body: groups[index] });
    }
    return { newCount, recurringCount };
  });
};

const recordFilters = (huntId: string, securityPlatformIds: (string | null)[] | null, iocKeys?: string[]): FilterGroup => {
  const filters: Filter[] = [{ key: ['hunt_id'], values: [huntId], mode: FilterMode.Or, operator: FilterOperator.Eq }];
  if (iocKeys) {
    filters.push({ key: ['ioc_keys'], values: iocKeys.length > 0 ? iocKeys : ['-'], mode: FilterMode.Or, operator: FilterOperator.Eq });
  }
  const filterGroups: FilterGroup[] = [];
  if (securityPlatformIds) {
    const platforms = securityPlatformIds.filter((id): id is string => !!id);
    const platformFilters: Filter[] = [];
    if (platforms.length > 0) {
      platformFilters.push({ key: ['security_platform_id'], values: platforms, mode: FilterMode.Or, operator: FilterOperator.Eq });
    }
    if (securityPlatformIds.includes(null)) {
      platformFilters.push({ key: ['security_platform_id'], values: [], mode: FilterMode.Or, operator: FilterOperator.Nil });
    }
    // No platform at all: nothing matches
    filterGroups.push({ mode: FilterMode.Or, filters: platformFilters.length > 0 ? platformFilters : [{ key: ['hunt_id'], values: ['-'], mode: FilterMode.Or, operator: FilterOperator.Eq }], filterGroups: [] });
  }
  return { mode: FilterMode.And, filters, filterGroups };
};

/**
 * Distinct hits known for a hunt, on the given security platforms (null for a hunt on the internet; every platform when
 * the list is null), restricted to the hits holding one of the given values for an indicator.
 */
export const countHuntHitRecords = async (context: AuthContext, huntId: string, securityPlatformIds: (string | null)[] | null, iocKeys?: string[]) => {
  return elCount(context, HUNT_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_HUNT_HIT_RECORD],
    filters: recordFilters(huntId, securityPlatformIds, iocKeys),
    noFiltersChecking: true,
  });
};

/** What a hunt knows of its hits on the given security platforms: distinct hits, and when the first and last new hits were found. */
export const summarizeHuntHitRecords = async (context: AuthContext, huntId: string, securityPlatformIds: (string | null)[] | null) => {
  const filters = recordFilters(huntId, securityPlatformIds);
  const first = (orderMode: OrderingMode) => topEntitiesList<BasicStoreEntityHuntHitRecord>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_HIT_RECORD], {
    first: 1,
    orderBy: 'first_seen',
    orderMode,
    filters,
    noFiltersChecking: true,
    baseData: true,
    baseFields: RECORD_FIELDS,
  } as never);
  const [count, earliest, latest] = await Promise.all([
    elCount(context, HUNT_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_HUNT_HIT_RECORD], filters, noFiltersChecking: true }),
    first(OrderingMode.Asc),
    first(OrderingMode.Desc),
  ]);
  return {
    distinct_count: Number(count) || 0,
    first_new_at: earliest[0]?.first_seen ?? null,
    last_new_at: latest[0]?.first_seen ?? null,
  };
};

/**
 * The sampled hits of a run, each telling whether this run found it first (new), how many runs found it so far and since
 * when; a hit without key, of a run whose hits are not identified, or forgotten since, says nothing.
 */
export const annotateHuntRunHits = async (context: AuthContext, run: BasicStoreEntityHuntRun) => {
  const hits = run.hits_sample ?? [];
  const keys = run.hits_identified === true ? hits.map((hit) => hit.hit_key).filter((key): key is string => !!key) : [];
  const records = keys.length > 0 ? await findHuntHitRecords(context, run.hunt_id, run.security_platform_id, keys) : new Map();
  return hits.map((hit) => {
    const record = hit.hit_key ? records.get(hit.hit_key) : undefined;
    return {
      ...hit,
      is_new: record ? record.first_run_id === run.internal_id : null,
      times_seen: record?.times_seen ?? null,
      known_since: record?.first_seen ?? null,
    };
  });
};

/**
 * What a hunt knows of its hits, over the security platforms the user can read (and the internet for an internet hunt):
 * the distinct hits, when the earliest known hit and the latest new hit were found.
 */
export const findHuntKnownHits = async (context: AuthContext, user: AuthUser, huntId: string) => {
  const buckets = await elAggregationCount(context, HUNT_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_HUNT_HIT_RECORD],
    field: 'security_platform_id',
    normalizeLabel: false,
    noFiltersChecking: true,
    filters: { mode: FilterMode.And, filters: [{ key: ['hunt_id'], values: [huntId] }], filterGroups: [] },
  }) as { label: string; count: number }[];
  if (buckets.length === 0) {
    return { distinct_count: 0, first_new_at: null, last_new_at: null };
  }
  const platformIds = buckets.map((bucket) => bucket.label).filter((label) => label !== 'unknown');
  const readable = platformIds.length > 0 ? await findByIds<BasicStoreEntity>(context, user, platformIds, { type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM }) : [];
  const scope: (string | null)[] = [...readable.map((platform) => platform.internal_id), ...(buckets.some((bucket) => bucket.label === 'unknown') ? [null] : [])];
  if (scope.length === 0) {
    return { distinct_count: 0, first_new_at: null, last_new_at: null };
  }
  return summarizeHuntHitRecords(context, huntId, scope);
};

/**
 * Retention of the known hits, the one of the runs: a hit no run was recorded finding since `before` is forgotten, a later
 * run counts it as new again. The time a run was recorded is read, never the observation date of its hits, which late
 * evidence can set far in the past. The records of a deleted hunt follow the same retention as its runs, kept for a hunt
 * restored from the trash.
 */
export const purgeExpiredHuntHitRecords = async (before: string) => {
  await elRawDeleteByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    wait_for_completion: true,
    body: {
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': ENTITY_TYPE_HUNT_HIT_RECORD } },
            { range: { updated_at: { lt: before } } },
          ],
        },
      },
    },
  });
};
