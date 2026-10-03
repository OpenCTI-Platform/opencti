import conf, { booleanConf, logApp } from '../../config/conf';
import { elUpdate } from '../../database/engine';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../../schema/stixSightingRelationship';
import { getDraftContext } from '../../utils/draftContext';
import { now } from '../../utils/format';
import { isNotEmptyField } from '../../database/utils';
import type { AuthContext, AuthUser } from '../../types/user';
import { resolveAssertionSource } from './provenance-source';
import {
  type AssertionSource,
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_LAST_ASSERTED_AT,
  ATTRIBUTE_SINGLE_SOURCED,
  DEFAULT_MAX_CONFLICT_VALUES_PER_FIELD,
  MAX_ASSERTIONS_PER_ELEMENT,
  MAX_CONFLICT_FIELDS_PER_ELEMENT,
  PROVENANCE_PROTECTED_INPUT_FIELDS,
  type StoreAssertion,
  type StoreConflictValue,
  type StoreProvenanceFields,
} from './provenance-types';

export const PROVENANCE_ENABLED = booleanConf('provenance:enabled', true);
const PROVENANCE_REFRESH_ON_WRITE = booleanConf('provenance:refresh_on_write', false);
export const MAX_CONFLICT_VALUES_PER_FIELD: number = conf.get('provenance:max_conflict_values_per_field') || DEFAULT_MAX_CONFLICT_VALUES_PER_FIELD;

export type ProvenanceTarget = { _index: string; _id?: string; internal_id: string; entity_type: string };

export interface ConflictAddition {
  field: string;
  value: StoreConflictValue;
}

export interface ConflictRemoval {
  field: string;
  value_hash: string;
}

export interface ProvenanceUpdate {
  assertions?: StoreAssertion[];
  // sum: live writes and merges add their counts, max: backfill stays idempotent when replayed
  countMode?: 'sum' | 'max';
  conflictsAdd?: ConflictAddition[];
  conflictsRemove?: ConflictRemoval[];
  resetFreshness?: boolean;
}

// Single constant source so the engine compiles it once, every variation goes through params.
export const PROVENANCE_UPDATE_SCRIPT = `
  List assertions = ctx._source.${ATTRIBUTE_ASSERTIONS};
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
  while (assertions.size() > params.max_assertions) {
    int oldest = 0;
    for (int i = 1; i < assertions.size(); ++i) {
      if (assertions.get(i).last_asserted_at.compareTo(assertions.get(oldest).last_asserted_at) < 0) { oldest = i; }
    }
    assertions.remove(oldest);
  }
  String last = null;
  for (def item : assertions) {
    def date = item.last_asserted_at;
    if (date != null && (last == null || date.compareTo(last) > 0)) { last = date; }
  }
  ctx._source.${ATTRIBUTE_CORROBORATION_COUNT} = assertions.size();
  ctx._source.${ATTRIBUTE_SINGLE_SOURCED} = assertions.size() == 1;
  if (last != null) { ctx._source.${ATTRIBUTE_LAST_ASSERTED_AT} = last; }
  if (params.reset_freshness && ctx._source.freshness_stale == true) {
    ctx._source.freshness_stale = false;
    ctx._source.remove('freshness_stale_at');
    ctx._source.remove('freshness_rule_id');
  }
  List conflicts = ctx._source.x_opencti_conflicts;
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
  while (conflictsIterator.hasNext()) {
    def entry = conflictsIterator.next();
    if (entry.values == null || entry.values.size() == 0) { conflictsIterator.remove(); }
  }
  if (conflicts.size() > 0) { ctx._source.x_opencti_conflicts = conflicts; } else { ctx._source.remove('x_opencti_conflicts'); }
  ctx._source.${ATTRIBUTE_HAS_CONFLICTS} = conflicts.size() > 0;
`;

export const isProvenanceTrackedType = (type: string) => {
  return isStixCoreObject(type) || isStixCoreRelationship(type) || isStixSightingRelationship(type);
};

/**
 * Provenance is owned by the platform: clients can never inject assertions, conflicts or procedures.
 */
export const removeProvenanceInputs = (input: Record<string, unknown>) => {
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
  [ATTRIBUTE_CORROBORATION_COUNT]: 1,
  [ATTRIBUTE_LAST_ASSERTED_AT]: at,
  [ATTRIBUTE_SINGLE_SOURCED]: true,
  [ATTRIBUTE_HAS_CONFLICTS]: false,
});

/**
 * Side-channel update: no stream event, no history, no updated_at change.
 */
export const applyProvenanceUpdate = async (context: AuthContext, target: ProvenanceTarget, update: ProvenanceUpdate) => {
  const params = {
    assertions: update.assertions ?? [],
    count_mode: update.countMode ?? 'sum',
    conflicts_add: update.conflictsAdd ?? [],
    conflicts_remove: update.conflictsRemove ?? [],
    reset_freshness: update.resetFreshness === true,
    max_assertions: MAX_ASSERTIONS_PER_ELEMENT,
    max_conflict_fields: MAX_CONFLICT_FIELDS_PER_ELEMENT,
    max_conflict_values: MAX_CONFLICT_VALUES_PER_FIELD,
  };
  const body = { script: { source: PROVENANCE_UPDATE_SCRIPT, lang: 'painless', params } };
  return elUpdate(context, target._index, target._id ?? target.internal_id, body, undefined, { refresh: PROVENANCE_REFRESH_ON_WRITE });
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
  opts: { fromRule?: string; restore?: boolean } = {},
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
  return buildCreationProvenance(source, input.confidence, now());
};

/**
 * Refresh the assertion of the writing source on an existing element after upsert resolution.
 * A provenance failure never fails the knowledge write itself.
 */
export const recordUpsertProvenance = async (
  context: AuthContext,
  user: AuthUser,
  element: ProvenanceTarget,
  opts: { input: Record<string, any>; confidence?: number | null; fromRule?: string; conflictsAdd?: ConflictAddition[]; conflictsRemove?: ConflictRemoval[] },
) => {
  if (!isProvenanceRecordable(context, user, element.entity_type)) {
    return null;
  }
  try {
    const source = await resolveAssertionSource(context, user, opts.input, { fromRule: opts.fromRule });
    const assertion = buildStoreAssertion(source, opts.confidence, now());
    await applyProvenanceUpdate(context, element, {
      assertions: [assertion],
      countMode: 'sum',
      conflictsAdd: opts.conflictsAdd,
      conflictsRemove: opts.conflictsRemove,
      resetFreshness: true,
    });
    return { source, assertion };
  } catch (err) {
    logApp.error('[PROVENANCE] Unable to record the assertion', { cause: err, id: element.internal_id, type: element.entity_type });
    return null;
  }
};
