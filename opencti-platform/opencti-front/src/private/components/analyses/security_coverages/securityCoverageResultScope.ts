export const ALL_RESULTS_VALUE = 'all-results';

export interface ResultOption {
  value: string;
  label: string;
}

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
