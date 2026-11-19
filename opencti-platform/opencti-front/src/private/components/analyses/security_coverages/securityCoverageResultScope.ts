export const ALL_RESULTS_VALUE = 'all-results';

export interface ResultOption {
  value: string;
  label: string;
}

export const toResultId = (value: string): string | null => {
  return value === ALL_RESULTS_VALUE ? null : value;
};
