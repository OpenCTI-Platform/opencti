/**
 * Rewriting of a user reference inside a stored filter.
 *
 * Every filter field of the platform is a serialized JSON string, not a structured document, so
 * the remapping happens in memory: parse, walk, rewrite, re-serialize.
 *
 * The walk selects by value rather than by filter key. An `internal_id` is a random v4 with no
 * derivation anywhere in the schema, so a value equal to the source id is a reference to the
 * source user, whichever key carries it. Selecting by key would need a list of the keys that
 * accept a User, which the platform does not expose, and would miss the composite keys whose
 * values are nested filter objects.
 */

interface RemappedValue {
  value: unknown;
  changed: boolean;
}

interface RemapCounters {
  /** Values rewritten from the source id to the target id. */
  rewritten: number;
  /** Values dropped because the rewrite made them a duplicate of a sibling. */
  deduplicated: number;
}

export interface FilterRemapResult {
  filters: string;
  changed: boolean;
  /** Whether the field could be read back at all. A field that does not parse is left alone. */
  parsed: boolean;
  counters: RemapCounters;
}

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

/**
 * A value can be a plain id, a nested filter group, or the `{ key, values }` sub-object the
 * composite keys carry — `regardingOf` and `dynamicFrom` / `dynamicTo`. All three are walked.
 */
const remapValue = (value: unknown, sourceId: string, targetId: string, counters: RemapCounters): RemappedValue => {
  if (typeof value === 'string') {
    if (value !== sourceId) {
      return { value, changed: false };
    }
    counters.rewritten += 1;
    return { value: targetId, changed: true };
  }
  if (Array.isArray(value)) {
    return remapArray(value, sourceId, targetId, counters);
  }
  if (isRecord(value)) {
    return remapObject(value, sourceId, targetId, counters);
  }
  return { value, changed: false };
};

/**
 * Rewrite, then collapse the repetitions of the target id the rewrite produced.
 *
 * A filter naming both users ends up holding the target id twice. Under `or` the repetition is
 * inert, but the platform is not indifferent to it: `computePirScore` divides by the sum of
 * every criterion weight while counting matches once per distinct filter, so a repetition
 * deflates every score of that PIR, and the filter chips of the UI use the value itself as a
 * React key.
 *
 * Only the target id is collapsed — any other value is untouched by the merge. The collapse
 * applies to the whole list once a rewrite happened, so a list that already repeated the target
 * id comes out canonical rather than half-cleaned; a repeated value in an `or` list carries no
 * meaning to preserve.
 */
const remapArray = (values: unknown[], sourceId: string, targetId: string, counters: RemapCounters): RemappedValue => {
  let changed = false;
  const remapped = values.map((value) => {
    const result = remapValue(value, sourceId, targetId, counters);
    changed = changed || result.changed;
    return result.value;
  });
  if (!changed) {
    return { value: values, changed: false };
  }
  let targetSeen = false;
  const kept = remapped.filter((value) => {
    if (value !== targetId) {
      return true;
    }
    if (targetSeen) {
      counters.deduplicated += 1;
      return false;
    }
    targetSeen = true;
    return true;
  });
  return { value: kept, changed: true };
};

const remapObject = (
  holder: Record<string, unknown>,
  sourceId: string,
  targetId: string,
  counters: RemapCounters,
): RemappedValue => {
  let changed = false;
  const remapped: Record<string, unknown> = {};
  Object.entries(holder).forEach(([key, value]) => {
    const result = remapValue(value, sourceId, targetId, counters);
    changed = changed || result.changed;
    remapped[key] = result.value;
  });
  return { value: changed ? remapped : holder, changed };
};

/**
 * Remap a parsed filter group. Exported for the callers that already hold the parsed form.
 */
export const remapUserInFilterGroup = <T>(
  filterGroup: T,
  sourceId: string,
  targetId: string,
): { filterGroup: T; changed: boolean; counters: RemapCounters } => {
  const counters: RemapCounters = { rewritten: 0, deduplicated: 0 };
  const result = remapValue(filterGroup, sourceId, targetId, counters);
  return { filterGroup: result.value as T, changed: result.changed, counters };
};

/**
 * Remap a serialized filter field.
 *
 * Returns the input untouched when the field does not parse, and says so: a filter the platform
 * cannot read is not something to rewrite blindly, and the caller reports it rather than
 * confusing it with a field that parsed but carried no reference.
 */
export const remapUserInSerializedFilters = (raw: string, sourceId: string, targetId: string): FilterRemapResult => {
  const unchanged: FilterRemapResult = { filters: raw, changed: false, parsed: true, counters: { rewritten: 0, deduplicated: 0 } };
  if (!raw.includes(sourceId)) {
    return unchanged;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ...unchanged, parsed: false };
  }
  const { filterGroup, changed, counters } = remapUserInFilterGroup(parsed, sourceId, targetId);
  if (!changed) {
    return unchanged;
  }
  return { filters: JSON.stringify(filterGroup), changed: true, parsed: true, counters };
};
