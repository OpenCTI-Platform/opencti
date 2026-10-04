import type { StixProvenanceExtension } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI_PROVENANCE } from '../../types/stix-2-1-extensions';
import {
  ASSERTION_SOURCE_KINDS,
  ATTRIBUTE_ASSERTIONS,
  ATTRIBUTE_CONFLICTS,
  ATTRIBUTE_CORROBORATION_COUNT,
  ATTRIBUTE_FRESHNESS_STALE,
  type StoreAssertion,
  type StoreConflict,
} from './provenance-types';
import { PROVENANCE_ENABLED } from './provenance-config';

type ProvenanceSource = {
  entity_type: string;
  [ATTRIBUTE_ASSERTIONS]?: StoreAssertion[] | null;
  [ATTRIBUTE_CONFLICTS]?: StoreConflict[] | null;
  [ATTRIBUTE_CORROBORATION_COUNT]?: number | null;
  [ATTRIBUTE_FRESHNESS_STALE]?: boolean | null;
};

const toStixDate = (date: string | undefined) => (date ? new Date(date).toISOString() : undefined);

/**
 * Provenance travelling through streams, bundles and exports: counts, dates and flags only.
 * Source names and identifiers stay inside the platform.
 * corroboration_count and single_sourced count every source; assertions_count and sources_by_kind are computed
 * from the sources whose details are kept (MAX_ASSERTIONS_PER_ELEMENT per element).
 */
export const buildProvenanceStixExtension = (instance: ProvenanceSource): StixProvenanceExtension | undefined => {
  const assertions = instance[ATTRIBUTE_ASSERTIONS] ?? [];
  if (assertions.length === 0) {
    return undefined;
  }
  const sourcesByKind: Record<string, number> = {};
  ASSERTION_SOURCE_KINDS.forEach((kind) => {
    sourcesByKind[kind] = 0;
  });
  let firstAsserted: string | undefined;
  let lastAsserted: string | undefined;
  let assertionsCount = 0;
  for (let index = 0; index < assertions.length; index += 1) {
    const assertion = assertions[index];
    sourcesByKind[assertion.source_kind] = (sourcesByKind[assertion.source_kind] ?? 0) + 1;
    assertionsCount += assertion.assert_count ?? 0;
    if (!firstAsserted || assertion.first_asserted_at < firstAsserted) {
      firstAsserted = assertion.first_asserted_at;
    }
    if (!lastAsserted || assertion.last_asserted_at > lastAsserted) {
      lastAsserted = assertion.last_asserted_at;
    }
  }
  const conflictingFields = (instance[ATTRIBUTE_CONFLICTS] ?? [])
    .filter((conflict) => (conflict.values ?? []).length > 0)
    .map((conflict) => conflict.field);
  // Every source ever counted, including the ones whose detail was dropped from the bounded assertions
  const corroborationCount = Math.max(instance[ATTRIBUTE_CORROBORATION_COUNT] ?? 0, assertions.length);
  return {
    extension_type: 'property-extension',
    corroboration_count: corroborationCount,
    assertions_count: assertionsCount,
    first_asserted: toStixDate(firstAsserted),
    last_asserted: toStixDate(lastAsserted),
    single_sourced: corroborationCount === 1,
    has_conflicts: conflictingFields.length > 0,
    conflicting_fields: conflictingFields,
    freshness_stale: instance[ATTRIBUTE_FRESHNESS_STALE] === true,
    sources_by_kind: sourcesByKind,
  };
};

export const withProvenanceStixExtension = <T extends { extensions: Record<string, unknown> }>(instance: ProvenanceSource, stix: T): T => {
  if (!PROVENANCE_ENABLED) {
    return stix;
  }
  const extension = buildProvenanceStixExtension(instance);
  if (!extension) {
    return stix;
  }
  return { ...stix, extensions: { ...stix.extensions, [STIX_EXT_OCTI_PROVENANCE]: extension } };
};
