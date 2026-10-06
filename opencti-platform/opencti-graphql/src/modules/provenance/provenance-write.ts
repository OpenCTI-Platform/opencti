import conf, { booleanConf, logApp } from '../../config/conf';
import { elRawGet, elUpdate } from '../../database/engine';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../../schema/stixSightingRelationship';
import { getDraftContext } from '../../utils/draftContext';
import { now } from '../../utils/format';
import { isNotEmptyField } from '../../database/utils';
import type { AuthContext, AuthUser } from '../../types/user';
import { addProvenanceConflictDetectedCount } from '../../manager/telemetryManager';
import { PROVENANCE_ENABLED, PROVENANCE_REASSERTION_WINDOW_MS } from './provenance-config';
import { procedureMatchKey } from './provenance-procedures';
import { isProvenanceTrackedForType } from './provenance-tracking';
import { resolveAssertionSource } from './provenance-source';
import type { ConflictAddition, ConflictRemoval } from './provenance-conflicts';
import { hasProvenanceTriggers, notifyProvenanceChange, type ProvenanceChange as ProvenanceTriggerChange } from './provenance-notification';
import {
  type AssertionSource,
  ATTRIBUTE_ASSERTION_SOURCE_IDS,
  ATTRIBUTE_ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_CONFLICT_FIELDS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_FRESHNESS_STALE,
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_LAST_ASSERTED_AT,
  ATTRIBUTE_PROCEDURES,
  ATTRIBUTE_SINGLE_SOURCED,
  DEFAULT_MAX_CONFLICT_VALUES_PER_FIELD,
  MAX_ASSERTIONS_PER_ELEMENT,
  MAX_CONFLICT_FIELDS_PER_ELEMENT,
  MAX_PROCEDURES_PER_RELATIONSHIP,
  PROVENANCE_PROTECTED_INPUT_FIELDS,
  PROVENANCE_SIDE_CHANNEL_FIELDS,
  type StoreAssertion,
  type StoreConflictValue,
  type StoreProcedure,
  type StoreProvenanceFields,
} from './provenance-types';

const PROVENANCE_REFRESH_ON_WRITE = booleanConf('provenance:refresh_on_write', false);
export const MAX_CONFLICT_VALUES_PER_FIELD: number = conf.get('provenance:max_conflict_values_per_field') || DEFAULT_MAX_CONFLICT_VALUES_PER_FIELD;

export type ProvenanceTarget = { _index: string; _id?: string; internal_id: string; entity_type: string };

export type ProvenanceChange = ProvenanceTriggerChange & { newConflictValues?: number };

export interface FreshnessFlag {
  rule_id: string;
  at: string;
  // The flag is only written if no source asserted the element since it was selected as stale
  expected_last_asserted_at?: string | null;
}

export interface ProvenanceUpdate {
  assertions?: StoreAssertion[];
  // sum: live writes and merges add their counts. backfill: the counts rebuilt from the history older than
  // backfillWatermark are added to a source the live tracking only recorded from the watermark on; any other stored
  // source already counted that history (live tracking or an earlier pass) and keeps the larger count, so a replay is idempotent
  countMode?: 'sum' | 'backfill';
  backfillWatermark?: string;
  conflictsAdd?: ConflictAddition[];
  conflictsRemove?: ConflictRemoval[];
  // Retention: conflict values not re-asserted since this date are dropped
  conflictsPurgeBefore?: string;
  proceduresAdd?: StoreProcedure[];
  // Sources counted by merged elements beyond the assertions they still detail
  sourceIdsAdd?: string[];
  sourceKindsAdd?: string[];
  resetFreshness?: boolean;
  freshnessFlag?: FreshnessFlag;
}

// Single constant source so the engine compiles it once, every variation goes through params.
// Assertions detail the max_assertions most recently active sources, while the flat source ids and kinds keep every
// source that ever asserted the element: corroboration is counted from the ids, never from the bounded details.
export const PROVENANCE_UPDATE_SCRIPT = `
  List assertions = ctx._source.${ATTRIBUTE_ASSERTIONS};
  if (params.assertions.size() > 0 || params.source_ids_add.size() > 0 || assertions != null) {
    if (assertions == null) { assertions = new ArrayList(); ctx._source.${ATTRIBUTE_ASSERTIONS} = assertions; }
    for (def incoming : params.assertions) {
      def current = null;
      for (def item : assertions) { if (item.source_id == incoming.source_id) { current = item; break; } }
      if (current == null) {
        Map created = new HashMap();
        created.put('source_id', incoming.source_id);
        created.put('source_kind', incoming.source_kind);
        created.put('source_name', incoming.source_name);
        created.put('first_asserted_at', incoming.first_asserted_at);
        created.put('last_asserted_at', incoming.last_asserted_at);
        created.put('assert_count', incoming.assert_count);
        created.put('confidence', incoming.confidence);
        created.put('work_id', incoming.work_id);
        assertions.add(created);
      } else {
        boolean addsHistory = params.count_mode == 'backfill' && params.backfill_watermark != null
          && current.first_asserted_at != null && current.first_asserted_at.compareTo(params.backfill_watermark) >= 0;
        boolean isNewer = current.last_asserted_at == null || incoming.last_asserted_at.compareTo(current.last_asserted_at) >= 0;
        if (current.first_asserted_at == null || incoming.first_asserted_at.compareTo(current.first_asserted_at) < 0) {
          current.first_asserted_at = incoming.first_asserted_at;
        }
        if (isNewer) {
          current.last_asserted_at = incoming.last_asserted_at;
          current.source_kind = incoming.source_kind;
          current.source_name = incoming.source_name;
          current.confidence = incoming.confidence;
          if (incoming.work_id != null) { current.work_id = incoming.work_id; }
        }
        def currentCount = current.assert_count == null ? 0 : current.assert_count;
        if (params.count_mode == 'backfill' && !addsHistory) {
          current.assert_count = incoming.assert_count > currentCount ? incoming.assert_count : currentCount;
        } else {
          current.assert_count = currentCount + incoming.assert_count;
        }
      }
    }
    List sourceIds = new ArrayList();
    List sourceKinds = new ArrayList();
    def storedIds = ctx._source.${ATTRIBUTE_ASSERTION_SOURCE_IDS};
    if (storedIds instanceof List) { sourceIds.addAll(storedIds); } else if (storedIds != null) { sourceIds.add(storedIds); }
    def storedKinds = ctx._source.${ATTRIBUTE_ASSERTION_SOURCE_KINDS};
    if (storedKinds instanceof List) { sourceKinds.addAll(storedKinds); } else if (storedKinds != null) { sourceKinds.add(storedKinds); }
    for (def addedId : params.source_ids_add) { if (!sourceIds.contains(addedId)) { sourceIds.add(addedId); } }
    for (def addedKind : params.source_kinds_add) { if (!sourceKinds.contains(addedKind)) { sourceKinds.add(addedKind); } }
    for (def item : assertions) {
      if (!sourceIds.contains(item.source_id)) { sourceIds.add(item.source_id); }
      if (item.source_kind != null && !sourceKinds.contains(item.source_kind)) { sourceKinds.add(item.source_kind); }
    }
    if (assertions.size() > params.max_assertions) {
      int earliest = 0;
      String earliestAt = null;
      for (int i = 0; i < assertions.size(); ++i) {
        def firstAt = assertions.get(i).first_asserted_at;
        if (firstAt != null && (earliestAt == null || firstAt.compareTo(earliestAt) < 0)) { earliest = i; earliestAt = firstAt; }
      }
      def kept = assertions.get(earliest);
      while (assertions.size() > params.max_assertions) {
        int oldest = -1;
        for (int i = 0; i < assertions.size(); ++i) {
          if (assertions.get(i) !== kept && (oldest < 0 || assertions.get(i).last_asserted_at.compareTo(assertions.get(oldest).last_asserted_at) < 0)) { oldest = i; }
        }
        assertions.remove(oldest);
      }
    }
    String last = null;
    for (def item : assertions) {
      def date = item.last_asserted_at;
      if (date != null && (last == null || date.compareTo(last) > 0)) { last = date; }
    }
    ctx._source.${ATTRIBUTE_ASSERTION_SOURCE_IDS} = sourceIds;
    ctx._source.${ATTRIBUTE_ASSERTION_SOURCE_KINDS} = sourceKinds;
    ctx._source.${ATTRIBUTE_CORROBORATION_COUNT} = sourceIds.size();
    ctx._source.${ATTRIBUTE_SINGLE_SOURCED} = sourceIds.size() == 1;
    if (last != null) { ctx._source.${ATTRIBUTE_LAST_ASSERTED_AT} = last; }
  }
  if (params.reset_freshness && ctx._source.freshness_stale == true) {
    ctx._source.freshness_stale = false;
    ctx._source.remove('freshness_stale_at');
    ctx._source.remove('freshness_rule_id');
  }
  if (params.freshness_flag != null) {
    def expected = params.freshness_flag.expected_last_asserted_at;
    if (expected != null && ctx._source.${ATTRIBUTE_LAST_ASSERTED_AT} != expected) {
      ctx.op = 'noop';
    } else {
      ctx._source.freshness_stale = true;
      ctx._source.freshness_stale_at = params.freshness_flag.at;
      ctx._source.freshness_rule_id = params.freshness_flag.rule_id;
    }
  }
  if (params.procedures_add.size() > 0) {
    List procedures = ctx._source.${ATTRIBUTE_PROCEDURES};
    if (procedures == null) { procedures = new ArrayList(); ctx._source.${ATTRIBUTE_PROCEDURES} = procedures; }
    for (def procedure : params.procedures_add) {
      String key = procedure.text.trim().toLowerCase();
      def existing = null;
      for (def item : procedures) {
        if (item.text != null && item.text.trim().toLowerCase() == key && item.source_id == procedure.source_id) { existing = item; break; }
      }
      if (existing == null) {
        procedures.add(new HashMap(procedure));
      } else if (existing.last_asserted_at == null || procedure.last_asserted_at.compareTo(existing.last_asserted_at) > 0) {
        existing.last_asserted_at = procedure.last_asserted_at;
      }
    }
    while (procedures.size() > params.max_procedures) {
      int oldestProcedure = 0;
      for (int i = 1; i < procedures.size(); ++i) {
        if (procedures.get(i).last_asserted_at.compareTo(procedures.get(oldestProcedure).last_asserted_at) < 0) { oldestProcedure = i; }
      }
      procedures.remove(oldestProcedure);
    }
  }
  List conflicts = ctx._source.x_opencti_conflicts;
  boolean conflictsTouched = params.conflicts_add.size() > 0 || params.conflicts_remove.size() > 0 || params.conflicts_purge_before != null;
  if (conflictsTouched) {
    if (conflicts == null) { conflicts = new ArrayList(); }
    for (def removal : params.conflicts_remove) {
      String removedHash = removal.value_hash;
      for (def entry : conflicts) {
        if (entry.field == removal.field && entry.values != null) {
          Iterator valuesIterator = entry.values.iterator();
          while (valuesIterator.hasNext()) { if (valuesIterator.next().value_hash == removedHash) { valuesIterator.remove(); } }
        }
      }
    }
    if (params.conflicts_purge_before != null) {
      String purgeBefore = params.conflicts_purge_before;
      for (def entry : conflicts) {
        if (entry.values != null) {
          Iterator purgeIterator = entry.values.iterator();
          while (purgeIterator.hasNext()) {
            def purged = purgeIterator.next();
            if (purged.last_asserted_at == null || purged.last_asserted_at.compareTo(purgeBefore) < 0) { purgeIterator.remove(); }
          }
        }
      }
    }
    for (def addition : params.conflicts_add) {
      def entry = null;
      for (def candidate : conflicts) { if (candidate.field == addition.field) { entry = candidate; break; } }
      if (entry == null) {
        if (conflicts.size() >= params.max_conflict_fields) { continue; }
        entry = new HashMap();
        entry.put('field', addition.field);
        entry.put('values', new ArrayList());
        conflicts.add(entry);
      }
      if (entry.values == null) { entry.values = new ArrayList(); }
      def existing = null;
      for (def value : entry.values) {
        if (value.value_hash == addition.value.value_hash && value.source_id == addition.value.source_id) { existing = value; break; }
      }
      if (existing == null) {
        entry.values.add(new HashMap(addition.value));
      } else if (existing.last_asserted_at == null || addition.value.last_asserted_at.compareTo(existing.last_asserted_at) >= 0) {
        existing.putAll(addition.value);
      }
      while (entry.values.size() > params.max_conflict_values) {
        int oldestValue = 0;
        for (int i = 1; i < entry.values.size(); ++i) {
          if (entry.values.get(i).last_asserted_at.compareTo(entry.values.get(oldestValue).last_asserted_at) < 0) { oldestValue = i; }
        }
        entry.values.remove(oldestValue);
      }
    }
    Iterator conflictsIterator = conflicts.iterator();
    List conflictFields = new ArrayList();
    while (conflictsIterator.hasNext()) {
      def entry = conflictsIterator.next();
      if (entry.values == null || entry.values.size() == 0) { conflictsIterator.remove(); } else { conflictFields.add(entry.field); }
    }
    if (conflicts.size() > 0) {
      ctx._source.x_opencti_conflicts = conflicts;
      ctx._source.${ATTRIBUTE_CONFLICT_FIELDS} = conflictFields;
    } else {
      ctx._source.remove('x_opencti_conflicts');
      ctx._source.remove('${ATTRIBUTE_CONFLICT_FIELDS}');
    }
  }
  ctx._source.${ATTRIBUTE_HAS_CONFLICTS} = conflicts != null && conflicts.size() > 0;
`;

export const isProvenanceTrackedType = (type: string) => {
  return isStixCoreObject(type) || isStixCoreRelationship(type) || isStixSightingRelationship(type);
};

/**
 * Provenance is owned by the platform: clients can never inject assertions, conflicts or procedures.
 */
export const removeProvenanceInputs = <T extends Record<string, unknown>>(input: T): T => {
  for (let index = 0; index < PROVENANCE_PROTECTED_INPUT_FIELDS.length; index += 1) {
    delete input[PROVENANCE_PROTECTED_INPUT_FIELDS[index]];
  }
  return input;
};

export const isProvenanceRecordable = async (context: AuthContext, user: AuthUser, type: string) => {
  if (!PROVENANCE_ENABLED || !isProvenanceTrackedType(type) || getDraftContext(context, user)) {
    return false;
  }
  return isProvenanceTrackedForType(context, type);
};

export const buildStoreAssertion = (source: AssertionSource, confidence: number | null | undefined, at: string, assertCount = 1): StoreAssertion => ({
  source_id: source.source_id,
  source_kind: source.source_kind,
  source_name: source.source_name,
  first_asserted_at: at,
  last_asserted_at: at,
  assert_count: assertCount,
  confidence: confidence ?? null,
  work_id: source.work_id,
});

export const buildCreationProvenance = (source: AssertionSource, confidence: number | null | undefined, at: string): StoreProvenanceFields => ({
  [ATTRIBUTE_ASSERTIONS]: [buildStoreAssertion(source, confidence, at)],
  [ATTRIBUTE_ASSERTION_SOURCE_IDS]: [source.source_id],
  [ATTRIBUTE_ASSERTION_SOURCE_KINDS]: [source.source_kind],
  [ATTRIBUTE_CORROBORATION_COUNT]: 1,
  [ATTRIBUTE_LAST_ASSERTED_AT]: at,
  [ATTRIBUTE_SINGLE_SOURCED]: true,
  [ATTRIBUTE_HAS_CONFLICTS]: false,
});

export const buildProvenanceScriptParams = (update: ProvenanceUpdate) => ({
  assertions: update.assertions ?? [],
  count_mode: update.countMode ?? 'sum',
  backfill_watermark: update.backfillWatermark ?? null,
  conflicts_add: update.conflictsAdd ?? [],
  conflicts_remove: update.conflictsRemove ?? [],
  conflicts_purge_before: update.conflictsPurgeBefore ?? null,
  procedures_add: update.proceduresAdd ?? [],
  source_ids_add: update.sourceIdsAdd ?? [],
  source_kinds_add: update.sourceKindsAdd ?? [],
  reset_freshness: update.resetFreshness === true,
  freshness_flag: update.freshnessFlag ?? null,
  max_assertions: MAX_ASSERTIONS_PER_ELEMENT,
  max_conflict_fields: MAX_CONFLICT_FIELDS_PER_ELEMENT,
  max_conflict_values: MAX_CONFLICT_VALUES_PER_FIELD,
  max_procedures: MAX_PROCEDURES_PER_RELATIONSHIP,
});

export const buildProvenanceScript = (update: ProvenanceUpdate) => ({
  source: PROVENANCE_UPDATE_SCRIPT,
  lang: 'painless',
  params: buildProvenanceScriptParams(update),
});

/**
 * Side-channel update: no stream event, no history, no updated_at change.
 */
export const applyProvenanceUpdate = async (
  context: AuthContext,
  target: ProvenanceTarget,
  update: ProvenanceUpdate,
  opts: { refresh?: boolean; returnFields?: string[] } = {},
) => {
  const body = { script: buildProvenanceScript(update) };
  const refresh = opts.refresh ?? PROVENANCE_REFRESH_ON_WRITE;
  return elUpdate(context, target._index, target._id ?? target.internal_id, body, undefined, { refresh, sourceIncludes: opts.returnFields });
};

export const isNoopUpdate = (response: any) => (response?.result ?? response?.body?.result) === 'noop';

export const readUpdatedSource = (response: any): Partial<StoreProvenanceFields> | null => {
  return (response?.get ?? response?.body?.get)?._source ?? null;
};

const CONDITIONAL_WRITE_ATTEMPTS = 5;

const isVersionConflictError = (err: any) => {
  const cause = err?.extensions?.data?.cause ?? err;
  return (cause?.meta?.statusCode ?? cause?.statusCode) === 409;
};

// A conflict value is stored once per value and source: a second source proposing a known value is a new conflict value
const conflictValueKey = (field: string, value: Pick<StoreConflictValue, 'value_hash' | 'source_id'>) => `${field}:${value.value_hash}:${value.source_id}`;

const conflictValueKeys = (element: Partial<StoreProvenanceFields>) => {
  return new Set((element[ATTRIBUTE_CONFLICTS] ?? []).flatMap((conflict) => (conflict.values ?? []).map((value) => conflictValueKey(conflict.field, value))));
};

/** Conflict values of the additions that the element does not hold yet. */
export const newConflictAdditions = (element: Partial<StoreProvenanceFields>, conflictsAdd: ConflictAddition[]) => {
  const knownValues = conflictValueKeys(element);
  return conflictsAdd.filter((addition) => !knownValues.has(conflictValueKey(addition.field, addition.value)));
};

/**
 * Additions that the write kept: a value dropped by the caps (conflicting fields per element, values per field)
 * is not recorded, so it is never reported as a new conflict, however often a source proposes it again.
 */
export const keptConflictAdditions = (response: any, additions: ConflictAddition[]) => {
  if (additions.length === 0 || isNoopUpdate(response)) {
    return [];
  }
  const stored = readUpdatedSource(response);
  if (!stored) {
    return additions;
  }
  const storedValues = conflictValueKeys(stored);
  return additions.filter((addition) => storedValues.has(conflictValueKey(addition.field, addition.value)));
};

export interface ProvenanceWriteResult {
  response: any;
  /** Conflict values created by this write: never counted by two writes, even under concurrent writes. */
  newConflicts: ConflictAddition[];
  /** Provenance stored right after the write, when requested: exact without waiting for a refresh. */
  current: Partial<StoreProvenanceFields> | null;
}

/**
 * Apply a provenance update and report what it created. An update adding conflict values reads the
 * conflicts in real time with the document version and applies only on that same version, re-reading
 * after a concurrent write: a conflict value is reported as new by the one write that created it, or by
 * none when the element stays contended after every attempt.
 */
export const writeProvenanceUpdate = async (
  context: AuthContext,
  target: ProvenanceTarget,
  update: ProvenanceUpdate,
  opts: { refresh?: boolean; withCurrent?: boolean } = {},
): Promise<ProvenanceWriteResult> => {
  const conflictsAdd = update.conflictsAdd ?? [];
  const updateOpts = { refresh: opts.refresh, returnFields: opts.withCurrent ? PROVENANCE_SIDE_CHANNEL_FIELDS : undefined };
  const result = (response: any, newConflicts: ConflictAddition[]) => ({
    response,
    newConflicts,
    current: opts.withCurrent ? readUpdatedSource(response) : null,
  });
  if (conflictsAdd.length === 0) {
    return result(await applyProvenanceUpdate(context, target, update, updateOpts), []);
  }
  const id = target._id ?? target.internal_id;
  // The stored conflicts come back with the write, to tell the additions it kept from the ones the caps dropped
  const conflictUpdateOpts = { refresh: opts.refresh, returnFields: [...new Set([...(updateOpts.returnFields ?? []), ATTRIBUTE_CONFLICTS])] };
  for (let attempt = 0; attempt < CONDITIONAL_WRITE_ATTEMPTS; attempt += 1) {
    const snapshot = await elRawGet({ id, index: target._index, _source_includes: [ATTRIBUTE_CONFLICTS] } as { id: string; index: string });
    const newConflicts = newConflictAdditions((snapshot?._source ?? {}) as Partial<StoreProvenanceFields>, conflictsAdd);
    try {
      const response = await elUpdate(context, target._index, id, { script: buildProvenanceScript(update) }, undefined, {
        refresh: opts.refresh ?? PROVENANCE_REFRESH_ON_WRITE,
        sourceIncludes: conflictUpdateOpts.returnFields,
        ifSeqNo: snapshot._seq_no,
        ifPrimaryTerm: snapshot._primary_term,
      });
      return result(response, keptConflictAdditions(response, newConflicts));
    } catch (err) {
      if (!isVersionConflictError(err)) {
        throw err;
      }
    }
  }
  // Still contended after every attempt: the update is applied anyway, but without a version this write cannot
  // tell its conflict values from the ones a concurrent write added, so it reports none rather than one twice.
  logApp.warn('[PROVENANCE] Element under contention, conflict values recorded without being reported as new', { id: target.internal_id });
  const response = await applyProvenanceUpdate(context, target, update, conflictUpdateOpts);
  return result(response, []);
};

/**
 * Provenance fields indexed together with a newly created element.
 * A restored element (trash) keeps the provenance it had when deleted.
 */
export const computeCreationProvenance = async (
  context: AuthContext,
  user: AuthUser,
  type: string,
  input: Record<string, any>,
  opts: { fromRule?: string; restore?: boolean; procedures?: (source: AssertionSource, at: string) => StoreProcedure[] } = {},
): Promise<StoreProvenanceFields | null> => {
  if (!(await isProvenanceRecordable(context, user, type))) {
    return null;
  }
  if (opts.restore && isNotEmptyField(input[ATTRIBUTE_ASSERTIONS])) {
    const restored: Record<string, unknown> = {};
    for (let index = 0; index < PROVENANCE_PROTECTED_INPUT_FIELDS.length; index += 1) {
      const field = PROVENANCE_PROTECTED_INPUT_FIELDS[index];
      if (isNotEmptyField(input[field])) {
        restored[field] = input[field];
      }
    }
    return restored as StoreProvenanceFields;
  }
  let source: AssertionSource;
  try {
    source = await resolveAssertionSource(context, user, input, { fromRule: opts.fromRule });
  } catch (err) {
    // The element is created without provenance: the next assertion of its source records it
    logApp.warn('[PROVENANCE] Unable to resolve the source of a created element', { cause: err, type });
    return null;
  }
  const at = now();
  const provenance = buildCreationProvenance(source, input.confidence, at);
  const procedures = opts.procedures?.(source, at) ?? [];
  if (procedures.length > 0) {
    provenance[ATTRIBUTE_PROCEDURES] = procedures;
  }
  return provenance;
};

export interface UpsertProvenanceRecord {
  source?: AssertionSource;
  input: Record<string, any>;
  confidence?: number | null;
  fromRule?: string;
  at?: string;
  conflictsAdd?: ConflictAddition[];
  conflictsRemove?: ConflictRemoval[];
  proceduresAdd?: StoreProcedure[];
}

/**
 * Corroboration change produced by a write, computed from the element as loaded before it, and the
 * conflict change made of the conflict values the write created (see writeProvenanceUpdate).
 */
export const computeProvenanceChange = (
  element: Partial<StoreProvenanceFields>,
  sourceIds: string[],
  newConflicts: ConflictAddition[] = [],
): ProvenanceChange => {
  const storedSourceIds = element[ATTRIBUTE_ASSERTION_SOURCE_IDS] ?? [];
  const previousSources = new Set([...storedSourceIds, ...(element[ATTRIBUTE_ASSERTIONS] ?? []).map((assertion) => assertion.source_id)]);
  const from = previousSources.size;
  const to = new Set([...previousSources, ...sourceIds]).size;
  return {
    corroboration: to > from ? { from, to } : undefined,
    conflictFields: [...new Set(newConflicts.map((addition) => addition.field))],
    newConflictValues: newConflicts.length,
  };
};

/**
 * Count the new conflict values and notify the listening triggers. `current` is the provenance stored by
 * the write itself: triggers are evaluated on it, as the element may not be visible to searches yet.
 */
export const publishProvenanceChange = async (
  context: AuthContext,
  element: ProvenanceTarget,
  change: ProvenanceChange,
  current: Partial<StoreProvenanceFields> | null = null,
) => {
  await addProvenanceConflictDetectedCount(change.newConflictValues ?? 0);
  if (change.corroboration || (change.conflictFields ?? []).length > 0) {
    await notifyProvenanceChange(context, element, change, current);
  }
};

const PROVENANCE_SNAPSHOT_FIELDS = [`${ATTRIBUTE_ASSERTIONS}.source_id`, ATTRIBUTE_ASSERTION_SOURCE_IDS, ATTRIBUTE_CONFLICTS];

/**
 * Provenance of the element as currently stored (realtime get, not a search), so that trigger events
 * are computed from the exact state even when the previous write is not yet visible to searches.
 */
export const loadProvenanceSnapshot = async (element: ProvenanceTarget): Promise<Partial<StoreProvenanceFields>> => {
  const response = await elRawGet({
    id: element._id ?? element.internal_id,
    index: element._index,
    _source_includes: PROVENANCE_SNAPSHOT_FIELDS,
  } as { id: string; index: string });
  return (response?._source ?? {}) as Partial<StoreProvenanceFields>;
};

/**
 * State used to compute the provenance change of a merge: exact when provenance triggers are listening.
 */
export const resolveProvenanceBeforeWrite = async (context: AuthContext, element: ProvenanceTarget & Partial<StoreProvenanceFields>) => {
  if (!(await hasProvenanceTriggers(context))) {
    return element as Partial<StoreProvenanceFields>;
  }
  try {
    return await loadProvenanceSnapshot(element);
  } catch (err) {
    logApp.warn('[PROVENANCE] Unable to load the provenance snapshot, using the loaded element', { cause: err, id: element.internal_id });
    return element as Partial<StoreProvenanceFields>;
  }
};

const isWithinReassertionWindow = (lastAssertedAt: string | null | undefined, at: string, windowMs: number) => {
  if (!lastAssertedAt || windowMs <= 0) {
    return false;
  }
  return new Date(at).getTime() - new Date(lastAssertedAt).getTime() < windowMs;
};

export interface CoalescedReassertion {
  redundant: boolean;
  conflictsAdd: ConflictAddition[];
  proceduresAdd: StoreProcedure[];
}

/**
 * What a write still has to record once the element, as loaded, already holds it. A source repeating its
 * assertion within the re-assertion window, with no new conflict nor procedure, is redundant: no write at all.
 */
export const coalesceReassertion = (
  element: Partial<StoreProvenanceFields>,
  sourceId: string,
  at: string,
  record: Pick<UpsertProvenanceRecord, 'conflictsAdd' | 'conflictsRemove' | 'proceduresAdd'>,
  windowMs = PROVENANCE_REASSERTION_WINDOW_MS,
): CoalescedReassertion => {
  const isFresh = (stored: { source_id?: string; last_asserted_at?: string } | undefined, expectedSourceId: string) => {
    return stored !== undefined && stored.source_id === expectedSourceId && isWithinReassertionWindow(stored.last_asserted_at, at, windowMs);
  };
  const conflicts = element[ATTRIBUTE_CONFLICTS] ?? [];
  // A conflicting value is kept per source: the same value proposed by another source is a new proposal
  const findConflictValue = (field: string, valueHash: string, sourceId?: string) => {
    return conflicts.find((conflict) => conflict.field === field)?.values
      ?.find((value) => value.value_hash === valueHash && (sourceId === undefined || value.source_id === sourceId));
  };
  const conflictsAdd = (record.conflictsAdd ?? []).filter(({ field, value }) => !isFresh(findConflictValue(field, value.value_hash, value.source_id), value.source_id));
  const removesStoredConflict = (record.conflictsRemove ?? []).some(({ field, value_hash }) => findConflictValue(field, value_hash) !== undefined);
  const procedures = element[ATTRIBUTE_PROCEDURES] ?? [];
  // A procedure is kept per source: the same text asserted by another source is a new attribution
  const proceduresAdd = (record.proceduresAdd ?? []).filter((procedure) => {
    const key = procedureMatchKey(procedure.text);
    const stored = procedures.find((candidate) => candidate.text && procedureMatchKey(candidate.text) === key && candidate.source_id === procedure.source_id);
    return !isFresh(stored, procedure.source_id);
  });
  const assertion = (element[ATTRIBUTE_ASSERTIONS] ?? []).find((stored) => stored.source_id === sourceId);
  const redundant = isFresh(assertion, sourceId)
    && element[ATTRIBUTE_FRESHNESS_STALE] !== true
    && conflictsAdd.length === 0
    && !removesStoredConflict
    && proceduresAdd.length === 0;
  return { redundant, conflictsAdd, proceduresAdd };
};

/**
 * Corroboration change read from the element returned by the update itself, exact without any refresh:
 * the writing source is new when this write created its assertion and the loaded element did not count it.
 */
export const computeAssertedCorroboration = (
  updated: Partial<StoreProvenanceFields>,
  before: Partial<StoreProvenanceFields>,
  sourceId: string,
  at: string,
) => {
  const assertions = updated[ATTRIBUTE_ASSERTIONS] ?? [];
  const to = new Set([...(updated[ATTRIBUTE_ASSERTION_SOURCE_IDS] ?? []), ...assertions.map((assertion) => assertion.source_id)]).size;
  const wasCounted = (before[ATTRIBUTE_ASSERTION_SOURCE_IDS] ?? []).includes(sourceId)
    || (before[ATTRIBUTE_ASSERTIONS] ?? []).some((assertion) => assertion.source_id === sourceId);
  const isCreatedByWrite = assertions.some((assertion) => assertion.source_id === sourceId && assertion.first_asserted_at === at);
  return isCreatedByWrite && !wasCounted ? { from: to - 1, to } : undefined;
};

/**
 * Refresh the assertion of the writing source on an existing element after upsert resolution.
 * A provenance failure never fails the knowledge write itself.
 */
export const recordUpsertProvenance = async (
  context: AuthContext,
  user: AuthUser,
  element: ProvenanceTarget & Partial<StoreProvenanceFields>,
  record: UpsertProvenanceRecord,
  opts: { refresh?: boolean; force?: boolean } = {},
) => {
  if (!(await isProvenanceRecordable(context, user, element.entity_type))) {
    return null;
  }
  try {
    const source = record.source ?? await resolveAssertionSource(context, user, record.input, { fromRule: record.fromRule });
    const at = record.at ?? now();
    const assertion = buildStoreAssertion(source, record.confidence, at);
    const coalesced = opts.force
      ? { redundant: false, conflictsAdd: record.conflictsAdd ?? [], proceduresAdd: record.proceduresAdd ?? [] }
      : coalesceReassertion(element, source.source_id, at, record);
    if (coalesced.redundant) {
      return { source, assertion };
    }
    const isTriggerListening = await hasProvenanceTriggers(context);
    const { newConflicts, current } = await writeProvenanceUpdate(context, element, {
      assertions: [assertion],
      countMode: 'sum',
      conflictsAdd: coalesced.conflictsAdd,
      conflictsRemove: record.conflictsRemove,
      proceduresAdd: coalesced.proceduresAdd,
      resetFreshness: true,
    }, { refresh: opts.refresh, withCurrent: isTriggerListening });
    const change = computeProvenanceChange(element, [source.source_id], newConflicts);
    if (current) {
      change.corroboration = computeAssertedCorroboration(current, element, source.source_id, at);
    }
    await publishProvenanceChange(context, element, change, current);
    return { source, assertion };
  } catch (err) {
    logApp.error('[PROVENANCE] Unable to record the assertion', { cause: err, id: element.internal_id, type: element.entity_type });
    return null;
  }
};
