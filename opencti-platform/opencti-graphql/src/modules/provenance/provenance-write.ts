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
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_LAST_ASSERTED_AT,
  ATTRIBUTE_PROCEDURES,
  ATTRIBUTE_SINGLE_SOURCED,
  DEFAULT_MAX_CONFLICT_VALUES_PER_FIELD,
  MAX_ASSERTIONS_PER_ELEMENT,
  MAX_CONFLICT_FIELDS_PER_ELEMENT,
  MAX_PROCEDURES_PER_RELATIONSHIP,
  PROVENANCE_PROTECTED_INPUT_FIELDS,
  type StoreAssertion,
  type StoreProcedure,
  type StoreProvenanceFields,
} from './provenance-types';

export const PROVENANCE_ENABLED = booleanConf('provenance:enabled', true);
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
  // sum: live writes and merges add their counts, max: backfill stays idempotent when replayed
  countMode?: 'sum' | 'max';
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
        if (params.count_mode == 'max') {
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
      for (def item : procedures) { if (item.text != null && item.text.trim().toLowerCase() == key) { existing = item; break; } }
      if (existing == null) {
        procedures.add(new HashMap(procedure));
      } else if (existing.last_asserted_at == null || procedure.last_asserted_at.compareTo(existing.last_asserted_at) > 0) {
        existing.last_asserted_at = procedure.last_asserted_at;
        existing.source_id = procedure.source_id;
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
      for (def value : entry.values) { if (value.value_hash == addition.value.value_hash) { existing = value; break; } }
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

export const isProvenanceRecordable = (context: AuthContext, user: AuthUser, type: string) => {
  return PROVENANCE_ENABLED && isProvenanceTrackedType(type) && !getDraftContext(context, user);
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
  opts: { refresh?: boolean } = {},
) => {
  const body = { script: buildProvenanceScript(update) };
  const refresh = opts.refresh ?? PROVENANCE_REFRESH_ON_WRITE;
  return elUpdate(context, target._index, target._id ?? target.internal_id, body, undefined, { refresh });
};

export const isNoopUpdate = (response: any) => (response?.result ?? response?.body?.result) === 'noop';

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
  if (!isProvenanceRecordable(context, user, type)) {
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
  const source = await resolveAssertionSource(context, user, input, { fromRule: opts.fromRule });
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
 * Corroboration and conflicts change produced by a write, computed from the element as loaded before it.
 */
export const computeProvenanceChange = (
  element: Partial<StoreProvenanceFields>,
  sourceIds: string[],
  conflictsAdd: ConflictAddition[] = [],
): ProvenanceChange => {
  const storedSourceIds = element[ATTRIBUTE_ASSERTION_SOURCE_IDS] ?? [];
  const previousSources = new Set([...storedSourceIds, ...(element[ATTRIBUTE_ASSERTIONS] ?? []).map((assertion) => assertion.source_id)]);
  const from = previousSources.size;
  const to = new Set([...previousSources, ...sourceIds]).size;
  const knownValues = new Set((element[ATTRIBUTE_CONFLICTS] ?? []).flatMap((conflict) => (conflict.values ?? []).map((value) => `${conflict.field}:${value.value_hash}`)));
  const newConflicts = conflictsAdd.filter((addition) => !knownValues.has(`${addition.field}:${addition.value.value_hash}`));
  return {
    corroboration: to > from ? { from, to } : undefined,
    conflictFields: [...new Set(newConflicts.map((addition) => addition.field))],
    newConflictValues: newConflicts.length,
  };
};

export const publishProvenanceChange = async (context: AuthContext, element: ProvenanceTarget, change: ProvenanceChange) => {
  await addProvenanceConflictDetectedCount(change.newConflictValues ?? 0);
  if (change.corroboration || (change.conflictFields ?? []).length > 0) {
    await notifyProvenanceChange(context, element, change);
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
 * State used to compute the provenance change of a write: exact when provenance triggers are listening.
 * When they are, the write must be refreshed so that the notification reads the updated provenance.
 */
export const resolveProvenanceBeforeWrite = async (context: AuthContext, element: ProvenanceTarget & Partial<StoreProvenanceFields>) => {
  if (!(await hasProvenanceTriggers(context))) {
    return { before: element as Partial<StoreProvenanceFields>, writeOpts: {} };
  }
  const writeOpts = { refresh: true };
  try {
    return { before: await loadProvenanceSnapshot(element), writeOpts };
  } catch (err) {
    logApp.warn('[PROVENANCE] Unable to load the provenance snapshot, using the loaded element', { cause: err, id: element.internal_id });
    return { before: element as Partial<StoreProvenanceFields>, writeOpts };
  }
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
  opts: { refresh?: boolean } = {},
) => {
  if (!isProvenanceRecordable(context, user, element.entity_type)) {
    return null;
  }
  try {
    const source = record.source ?? await resolveAssertionSource(context, user, record.input, { fromRule: record.fromRule });
    const assertion = buildStoreAssertion(source, record.confidence, record.at ?? now());
    const { before, writeOpts } = await resolveProvenanceBeforeWrite(context, element);
    await applyProvenanceUpdate(context, element, {
      assertions: [assertion],
      countMode: 'sum',
      conflictsAdd: record.conflictsAdd,
      conflictsRemove: record.conflictsRemove,
      proceduresAdd: record.proceduresAdd,
      resetFreshness: true,
    }, { ...opts, ...writeOpts });
    await publishProvenanceChange(context, element, computeProvenanceChange(before, [source.source_id], record.conflictsAdd));
    return { source, assertion };
  } catch (err) {
    logApp.error('[PROVENANCE] Unable to record the assertion', { cause: err, id: element.internal_id, type: element.entity_type });
    return null;
  }
};
