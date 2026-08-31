/**
 * Rewriting of a user reference inside a JSON payload the platform stores as an opaque blob:
 * stored filters, dashboard manifests, playbook and workflow definitions, draft patches.
 *
 * None of them is a structured document Elasticsearch can update in place, so the remapping
 * happens in memory: parse, walk, rewrite, re-serialize.
 *
 * The walk selects by value rather than by key. An `internal_id` is a random v4 with no
 * derivation anywhere in the schema, so a value equal to the source id is a reference to the
 * source user, whichever key carries it. Selecting by key would need the list of keys that
 * accept a User in every one of these payload shapes, which none of them declares.
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

export interface JsonRemapResult {
  json: string;
  changed: boolean;
  /** Whether the payload could be read back at all. One that does not parse is left alone. */
  parsed: boolean;
  counters: RemapCounters;
}

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

/**
 * A value can be a plain id, a nested group, or the `{ key, values }` sub-object the composite
 * filter keys carry — `regardingOf` and `dynamicFrom` / `dynamicTo`. All three are walked.
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
 * A payload naming both users ends up holding the target id twice, and the platform is not
 * indifferent to it: `computePirScore` divides by the sum of every criterion weight while
 * counting matches once per distinct filter, so a repetition deflates every score of that PIR;
 * the filter chips of the UI use the value itself as a React key; and a draft patch replaying
 * `added_value` twice would add the same member twice.
 *
 * Only the target id is collapsed — any other value is untouched by the merge. The collapse
 * applies to the whole list once a rewrite happened, so a list that already repeated the target
 * id comes out canonical rather than half-cleaned; a repeated id in a list of references carries
 * no meaning to preserve.
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
 * Remap an already parsed payload. Exported for the callers that hold the parsed form, either
 * because they decoded it themselves or because the platform stores it as an object.
 */
export const remapUserInJsonValue = <T>(
  payload: T,
  sourceId: string,
  targetId: string,
): { payload: T; changed: boolean; counters: RemapCounters } => {
  const counters: RemapCounters = { rewritten: 0, deduplicated: 0 };
  const result = remapValue(payload, sourceId, targetId, counters);
  return { payload: result.value as T, changed: result.changed, counters };
};

/**
 * Remap a serialized payload.
 *
 * Returns the input untouched when it does not parse, and says so: a payload the platform cannot
 * read is not something to rewrite blindly, and the caller reports it rather than confusing it
 * with one that parsed but carried no reference.
 */
export const remapUserInJsonString = (raw: string, sourceId: string, targetId: string): JsonRemapResult => {
  const unchanged: JsonRemapResult = { json: raw, changed: false, parsed: true, counters: { rewritten: 0, deduplicated: 0 } };
  if (!raw.includes(sourceId)) {
    return unchanged;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ...unchanged, parsed: false };
  }
  const { payload, changed, counters } = remapUserInJsonValue(parsed, sourceId, targetId);
  if (!changed) {
    return unchanged;
  }
  return { json: JSON.stringify(payload), changed: true, parsed: true, counters };
};
