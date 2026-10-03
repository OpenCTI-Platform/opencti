// Provenance, corroboration and freshness: every fact knows who said it.
// Assertions are recorded on stored Stix Core Objects, Stix Core Relationships and sightings,
// after upsert resolution. They are written through side-channel updates that never emit
// stream events nor touch updated_at.

export const ATTRIBUTE_ASSERTIONS = 'x_opencti_assertions';
export const ATTRIBUTE_CORROBORATION_COUNT = 'corroboration_count';
export const ATTRIBUTE_LAST_ASSERTED_AT = 'last_asserted_at';
export const ATTRIBUTE_SINGLE_SOURCED = 'single_sourced';
export const ATTRIBUTE_HAS_CONFLICTS = 'has_conflicts';
export const ATTRIBUTE_CONFLICTS = 'x_opencti_conflicts';
export const ATTRIBUTE_PROCEDURES = 'procedures';
export const ATTRIBUTE_FRESHNESS_STALE = 'freshness_stale';
export const ATTRIBUTE_FRESHNESS_STALE_AT = 'freshness_stale_at';
export const ATTRIBUTE_FRESHNESS_RULE_ID = 'freshness_rule_id';
// Flat denormalizations of the nested lists, for keyword filtering (including negations)
export const ATTRIBUTE_ASSERTION_SOURCE_IDS = 'assertion_source_ids';
export const ATTRIBUTE_ASSERTION_SOURCE_KINDS = 'assertion_source_kinds';
export const ATTRIBUTE_CONFLICT_FIELDS = 'conflict_fields';

// Virtual key: computed from last_asserted_at at query time (filters, sorts and resolvers),
// so that it never needs a daily rewrite of every document.
export const VIRTUAL_FRESHNESS_DAYS = 'freshness_days';

// Fields owned by the provenance side channel. Regular element updates never overwrite them
// and clients can never set them through creation, upsert or update inputs.
export const PROVENANCE_SIDE_CHANNEL_FIELDS = [
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_ASSERTION_SOURCE_IDS,
  ATTRIBUTE_ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_CONFLICT_FIELDS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_LAST_ASSERTED_AT,
  ATTRIBUTE_SINGLE_SOURCED,
  ATTRIBUTE_HAS_CONFLICTS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_PROCEDURES,
  ATTRIBUTE_FRESHNESS_STALE,
  ATTRIBUTE_FRESHNESS_STALE_AT,
  ATTRIBUTE_FRESHNESS_RULE_ID,
];

export const PROVENANCE_PROTECTED_INPUT_FIELDS = PROVENANCE_SIDE_CHANNEL_FIELDS;

export const SOURCE_KIND_CONNECTOR = 'connector';
export const SOURCE_KIND_FEED = 'feed';
export const SOURCE_KIND_AUTHOR = 'author';
export const SOURCE_KIND_USER = 'user';
export const SOURCE_KIND_INFERENCE = 'inference';
export const SOURCE_KIND_EMULATION = 'emulation';

export const ASSERTION_SOURCE_KINDS = [
  SOURCE_KIND_CONNECTOR,
  SOURCE_KIND_FEED,
  SOURCE_KIND_AUTHOR,
  SOURCE_KIND_USER,
  SOURCE_KIND_INFERENCE,
  SOURCE_KIND_EMULATION,
] as const;

export type AssertionSourceKind = typeof ASSERTION_SOURCE_KINDS[number];

// Upper bound of distinct sources kept on one element. Beyond it, the least recently
// asserted source is evicted (bounded nested documents per element).
export const MAX_ASSERTIONS_PER_ELEMENT = 200;
// Default upper bound of alternative values kept per conflicting field.
export const DEFAULT_MAX_CONFLICT_VALUES_PER_FIELD = 10;
// Upper bound of conflicting fields tracked on one element.
export const MAX_CONFLICT_FIELDS_PER_ELEMENT = 50;
// Upper bound of distinct procedures kept on one uses relationship.
export const MAX_PROCEDURES_PER_RELATIONSHIP = 50;
// Values longer than this are kept as a truncated display only (adoption then unavailable).
export const MAX_CONFLICT_RAW_VALUE_LENGTH = 32768;
export const MAX_CONFLICT_DISPLAY_LENGTH = 512;

/** Resolved identity of whoever asserted a fact during a write. */
export interface AssertionSource {
  source_id: string;
  source_kind: AssertionSourceKind;
  source_name: string;
  work_id: string | null;
}

/** One entry per distinct source, refreshed on repeated assertions. */
export interface StoreAssertion {
  source_id: string;
  source_kind: AssertionSourceKind;
  source_name: string;
  first_asserted_at: string;
  last_asserted_at: string;
  assert_count: number;
  confidence: number | null;
  work_id: string | null;
}

/** Alternative value proposed by a source for a scalar attribute. */
export interface StoreConflictValue {
  value_hash: string;
  display: string;
  value: string | null; // JSON serialized raw value, null when too large to be adopted
  source_id: string;
  source_kind: AssertionSourceKind;
  source_name: string;
  confidence: number | null;
  last_asserted_at: string;
}

export interface StoreConflict {
  field: string;
  values: StoreConflictValue[];
}

/** Distinct procedure description preserved on a uses relationship to an Attack Pattern. */
export interface StoreProcedure {
  text: string;
  source_id: string;
  last_asserted_at: string;
}

// Backfill of the assertions of the knowledge that existed before provenance tracking,
// its state is stored in the manager configuration of the backfill manager.
export const PROVENANCE_BACKFILL_MANAGER_ID = 'PROVENANCE_BACKFILL_MANAGER';
export const BACKFILL_STATUSES = ['pending', 'running', 'completed'] as const;
export type ProvenanceBackfillStatus = typeof BACKFILL_STATUSES[number];

export interface ProvenanceBackfillState {
  status: ProvenanceBackfillStatus;
  cursor: string | null;
  processed: number;
  updated: number;
  expected: number;
  errors: number;
  started_at: string | null;
  completed_at: string | null;
}

export const DEFAULT_PROVENANCE_BACKFILL_STATE: ProvenanceBackfillState = {
  status: 'pending',
  cursor: null,
  processed: 0,
  updated: 0,
  expected: 0,
  errors: 0,
  started_at: null,
  completed_at: null,
};

export interface StoreProvenanceFields {
  [ATTRIBUTE_ASSERTIONS]?: StoreAssertion[];
  [ATTRIBUTE_ASSERTION_SOURCE_IDS]?: string[];
  [ATTRIBUTE_ASSERTION_SOURCE_KINDS]?: AssertionSourceKind[];
  [ATTRIBUTE_CONFLICT_FIELDS]?: string[];
  [ATTRIBUTE_CORROBORATION_COUNT]?: number;
  [ATTRIBUTE_LAST_ASSERTED_AT]?: string;
  [ATTRIBUTE_SINGLE_SOURCED]?: boolean;
  [ATTRIBUTE_HAS_CONFLICTS]?: boolean;
  [ATTRIBUTE_CONFLICTS]?: StoreConflict[];
  [ATTRIBUTE_PROCEDURES]?: StoreProcedure[];
  [ATTRIBUTE_FRESHNESS_STALE]?: boolean;
  [ATTRIBUTE_FRESHNESS_STALE_AT]?: string;
  [ATTRIBUTE_FRESHNESS_RULE_ID]?: string;
}
