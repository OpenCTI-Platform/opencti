import type { PayloadError } from 'relay-runtime';
import type { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';

// useApiMutation hands GraphQL payload errors to onCompleted, never to onError.
export const notifyPayloadErrors = (errors: readonly PayloadError[] | null | undefined): boolean => {
  if (errors && errors.length > 0) {
    MESSAGING$.notifyError(errors[0].message);
    return true;
  }
  return false;
};

export type AssertionSourceKind = 'connector' | 'feed' | 'author' | 'user' | 'inference' | 'emulation';

export const ASSERTION_SOURCE_KINDS: AssertionSourceKind[] = ['connector', 'feed', 'author', 'user', 'inference', 'emulation'];

export interface ProvenanceAssertion {
  readonly source_id: string;
  readonly source_kind: string;
  readonly source_name: string;
  readonly first_asserted_at: string;
  readonly last_asserted_at: string;
  readonly assert_count: number;
  readonly confidence?: number | null;
}

export interface ProvenanceConflictValue {
  readonly value_hash: string;
  readonly display: string;
  readonly adoptable: boolean;
  readonly source_id: string;
  readonly source_kind?: string | null;
  readonly source_name?: string | null;
  readonly confidence?: number | null;
  readonly last_asserted_at: string;
}

export interface ProvenanceConflict {
  readonly field: string;
  // Schema label of the field, translated by the caller (t_i18n)
  readonly field_label?: string | null;
  readonly values: ReadonlyArray<ProvenanceConflictValue>;
}

export interface ProvenanceProcedure {
  readonly text: string;
  readonly source_id?: string | null;
  readonly last_asserted_at?: string | null;
}

/** Provenance of a Stix core object, Stix core relationship or sighting, as read through the API. */
export interface ProvenanceData {
  readonly id: string;
  readonly entity_type: string;
  readonly description?: string | null;
  readonly corroboration_count?: number | null;
  readonly single_sourced?: boolean | null;
  readonly has_conflicts?: boolean | null;
  readonly last_asserted_at?: string | null;
  readonly freshness_days?: number | null;
  readonly freshness_stale?: boolean | null;
  readonly freshness_stale_at?: string | null;
  readonly x_opencti_assertions?: ReadonlyArray<ProvenanceAssertion> | null;
  readonly x_opencti_conflicts?: ReadonlyArray<ProvenanceConflict> | null;
  readonly procedures?: ReadonlyArray<ProvenanceProcedure> | null;
}

// Labels are translated by the caller (t_i18n)
export const SOURCE_KIND_LABELS: Record<AssertionSourceKind, string> = {
  connector: 'Connector',
  feed: 'Ingestion feed',
  author: 'Author',
  user: 'User',
  inference: 'Inference rule',
  emulation: 'Emulation',
};

export const sourceKindLabel = (kind: string | null | undefined) => {
  return SOURCE_KIND_LABELS[(kind ?? '') as AssertionSourceKind] ?? 'Unknown';
};

// The warning palette is optional in the theme typing
export const warningColor = (theme: Theme) => (theme.palette.warning as { main?: string } | undefined)?.main ?? theme.palette.error.main;

export type CorroborationLevel = 'none' | 'single' | 'corroborated' | 'strong';

/** Single sourced knowledge is a warning, 2-3 sources is corroborated, 4 sources or more is strongly corroborated. */
export const corroborationLevel = (count: number | null | undefined): CorroborationLevel => {
  if (!count || count <= 0) {
    return 'none';
  }
  if (count === 1) {
    return 'single';
  }
  return count >= 4 ? 'strong' : 'corroborated';
};

export const corroborationColor = (theme: Theme, count: number | null | undefined) => {
  switch (corroborationLevel(count)) {
    case 'single':
      return warningColor(theme);
    case 'corroborated':
      return theme.palette.primary.main;
    case 'strong':
      return theme.palette.success.main;
    default:
      return theme.palette.text.disabled ?? theme.palette.text.secondary;
  }
};

// Freshness buckets, in days since the last assertion of any source
export const FRESHNESS_BUCKET_LABELS: Record<string, string> = {
  '0-30': '0-30 days',
  '31-90': '31-90 days',
  '91-180': '91-180 days',
  '181-365': '181-365 days',
  '366+': 'Over 365 days',
  unknown: 'Never asserted',
};

export const freshnessColor = (theme: Theme, days: number | null | undefined, stale?: boolean | null) => {
  if (stale) {
    return theme.palette.error.main;
  }
  if (days === null || days === undefined) {
    return theme.palette.text.secondary;
  }
  if (days <= 90) {
    return theme.palette.success.main;
  }
  return days <= 365 ? warningColor(theme) : theme.palette.error.main;
};

// Compared on the instants, never on the formatted dates: two assertions months apart can both read "3 months ago".
export const isAssertedOnce = (assertion: Pick<ProvenanceAssertion, 'first_asserted_at' | 'last_asserted_at'>) => {
  return new Date(assertion.first_asserted_at).getTime() === new Date(assertion.last_asserted_at).getTime();
};

export const sortAssertionsByRecency = (assertions: ReadonlyArray<ProvenanceAssertion> | null | undefined) => {
  return [...(assertions ?? [])].sort((a, b) => b.last_asserted_at.localeCompare(a.last_asserted_at));
};

export interface ConflictValueGroup {
  readonly value_hash: string;
  readonly display: string;
  readonly adoptable: boolean;
  readonly proposals: ProvenanceConflictValue[];
}

/**
 * Conflicting values are kept per source: the same value proposed by several sources is shown once, with every
 * proposal (source, date, confidence). Adopting or dismissing the value acts on all of them.
 */
export const groupConflictValues = (values: ReadonlyArray<ProvenanceConflictValue>): ConflictValueGroup[] => {
  const groups = new Map<string, { value_hash: string; display: string; adoptable: boolean; proposals: ProvenanceConflictValue[] }>();
  values.forEach((value) => {
    const group = groups.get(value.value_hash) ?? { value_hash: value.value_hash, display: value.display, adoptable: false, proposals: [] };
    group.adoptable = group.adoptable || value.adoptable;
    group.proposals.push(value);
    groups.set(value.value_hash, group);
  });
  return [...groups.values()];
};

export interface ProcedureGroup {
  readonly text: string;
  readonly sourceNames: string[];
  readonly lastAssertedAt: string | null;
}

/**
 * Procedures are kept per source: the same text asserted by several sources is shown once, with the name of every
 * source that asserted it (sources beyond the bounded details have no name and are not listed).
 */
export const groupProceduresByText = (
  procedures: ReadonlyArray<ProvenanceProcedure>,
  assertions: ReadonlyArray<Pick<ProvenanceAssertion, 'source_id' | 'source_name'>>,
): ProcedureGroup[] => {
  const sourceNames = new Map(assertions.map((assertion) => [assertion.source_id, assertion.source_name]));
  const groups = new Map<string, { text: string; sourceNames: string[]; lastAssertedAt: string | null }>();
  procedures.forEach((procedure) => {
    const key = procedure.text.trim().toLowerCase();
    const group = groups.get(key) ?? { text: procedure.text, sourceNames: [], lastAssertedAt: null };
    const name = procedure.source_id ? sourceNames.get(procedure.source_id) : undefined;
    if (name && !group.sourceNames.includes(name)) {
      group.sourceNames.push(name);
    }
    if (procedure.last_asserted_at && (!group.lastAssertedAt || procedure.last_asserted_at > group.lastAssertedAt)) {
      group.lastAssertedAt = procedure.last_asserted_at;
    }
    groups.set(key, group);
  });
  return [...groups.values()];
};

export const SOURCES_CARD_MAX_SOURCES = 5;

export interface SourcesCardModel {
  readonly sources: ProvenanceAssertion[];
  // Every source of the element, including the ones beyond the bounded details
  readonly totalSourcesCount: number;
  readonly hiddenSourcesCount: number;
  readonly conflictingFields: string[];
}

/**
 * Content of the Sources card: the most recent sources first, the number of sources left to the panel and the labels
 * of the fields on which sources disagree. The corroboration counts every source, including the ones whose detail is
 * no longer kept. Null when no source asserted the element, so that the card is not rendered.
 */
export const buildSourcesCardModel = (
  assertions: ReadonlyArray<ProvenanceAssertion> | null | undefined,
  conflicts: ReadonlyArray<Pick<ProvenanceConflict, 'field' | 'field_label'> & { readonly values: ReadonlyArray<unknown> }> | null | undefined,
  corroborationCount?: number | null,
  maxSources = SOURCES_CARD_MAX_SOURCES,
): SourcesCardModel | null => {
  const sorted = sortAssertionsByRecency(assertions);
  if (sorted.length === 0) {
    return null;
  }
  const sources = sorted.slice(0, maxSources);
  const totalSourcesCount = Math.max(sorted.length, corroborationCount ?? 0);
  return {
    sources,
    totalSourcesCount,
    hiddenSourcesCount: totalSourcesCount - sources.length,
    conflictingFields: (conflicts ?? []).filter((conflict) => conflict.values.length > 0).map((conflict) => conflict.field_label ?? conflict.field),
  };
};
