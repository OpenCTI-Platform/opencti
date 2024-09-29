import { FilterGroup as RelayFilterGroup, Filter as RelayFilter } from '../../private/components/settings/metrics/__generated__/MetricsWeeklyQuery.graphql';

// eslint-disable-next-line import/prefer-default-export
export function convertToRelayFilterGroup(input?: unknown): RelayFilterGroup | undefined {
  if (!input || typeof input !== 'object'
        || !('mode' in input)
        || !('filters' in input)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        || !Array.isArray((input as any).filters)
  ) {
    return undefined;
  }

  const castedInput = input as {
    mode: 'and' | 'or';
    filters: Array<{ key: string | string[]; values: string[] }>;
    filterGroups?: unknown;
  };

  return {
    mode: castedInput.mode,
    filters: castedInput.filters.map((f: { key: unknown; values: unknown; }) => ({
      ...f,
      key: Array.isArray(f.key) ? f.key : [f.key],
      values: f.values,
    })) as readonly RelayFilter[],
    filterGroups: (castedInput.filterGroups ?? []) as RelayFilterGroup['filterGroups'],
  };
}
