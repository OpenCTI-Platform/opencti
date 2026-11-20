import { GqlFilterGroup, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';

export const ALL_RESULTS_VALUE = 'all-results';

export interface ScopableSecurityCoverageResult {
  readonly id: string;
  readonly name: string;
  readonly external_uri?: string | null;
}

export interface ResultOption {
  value: string;
  label: string;
}

export interface ResultScopeVariables {
  id: string;
  filters: GqlFilterGroup;
  fromId: string[];
}

/**
 * Options of the result selector, in the order of `securityCoverageResults`.
 * The "All results" option is not part of the list: its label is translated, the component adds it.
 * Results sharing the same name are told apart by their external uri (or their id when it is missing),
 * and by their id when the name and the external uri are both shared.
 */
export const buildResultOptions = (securityCoverageResults: ReadonlyArray<ScopableSecurityCoverageResult>): ResultOption[] => {
  const countBy = (labels: string[]) => {
    const counts = new Map<string, number>();
    labels.forEach((label) => counts.set(label, (counts.get(label) ?? 0) + 1));
    return counts;
  };
  const nameCounts = countBy(securityCoverageResults.map((securityCoverageResult) => securityCoverageResult.name));
  const withExternalUri = securityCoverageResults.map((securityCoverageResult) => {
    const isDuplicated = (nameCounts.get(securityCoverageResult.name) ?? 0) > 1;
    return isDuplicated ? `${securityCoverageResult.name} – ${securityCoverageResult.external_uri || securityCoverageResult.id}` : securityCoverageResult.name;
  });
  const labelCounts = countBy(withExternalUri);
  return securityCoverageResults.map((securityCoverageResult, index) => {
    const isStillAmbiguous = (labelCounts.get(withExternalUri[index]) ?? 0) > 1;
    return {
      value: securityCoverageResult.id,
      label: isStillAmbiguous ? `${securityCoverageResult.name} – ${securityCoverageResult.id}` : withExternalUri[index],
    };
  });
};

export const toResultId = (value: string): string | null => {
  return value === ALL_RESULTS_VALUE ? null : value;
};

export const resolveSelectedResult = <T extends { readonly id: string }>(
  securityCoverageResults: ReadonlyArray<T>,
  selectedId: string | null,
): T | null => {
  if (!selectedId) return null;
  return securityCoverageResults.find((securityCoverageResult) => securityCoverageResult.id === selectedId) ?? null;
};

export const buildResultScopeVariables = (securityCoverageId: string, securityCoverageResultId: string): ResultScopeVariables => ({
  id: securityCoverageId,
  filters: normalizeFilterGroupForBackend({
    mode: 'and',
    filters: [{ key: 'fromId', values: [securityCoverageResultId], operator: 'eq', mode: 'or' }],
    filterGroups: [],
  }),
  fromId: [securityCoverageResultId],
});

/**
 * Changes whenever the subscription pushes an update of the coverage or of one of its security coverage results,
 * so that the query of the selected result can be refetched.
 */
export const buildScopeRefreshKey = (
  updatedAt: string | null | undefined,
  securityCoverageResults: ReadonlyArray<{ readonly id: string; readonly coverage_last_result?: string | null }>,
): string => {
  const securityCoverageResultsKey = securityCoverageResults.map((securityCoverageResult) => `${securityCoverageResult.id}:${securityCoverageResult.coverage_last_result ?? ''}`).join('|');
  return `${updatedAt ?? ''}#${securityCoverageResultsKey}`;
};
