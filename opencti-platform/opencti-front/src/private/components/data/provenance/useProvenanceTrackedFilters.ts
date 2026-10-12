import { useMemo } from 'react';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';

/**
 * Filters of a Curation list restricted to the types whose provenance is tracked: the provenance kept on a type
 * switched off in "Settings > Customization" is no longer displayed. Each setting lists the types it governs that are
 * not tracked (an abstract setting such as relationships or observables lists its inheriting concrete types).
 */
const useProvenanceTrackedFilters = (filters: FilterGroup): FilterGroup => {
  const untrackedKey = [...new Set(useEntitySettings()
    .filter((setting) => setting.availableSettings.includes('provenance_tracking'))
    .flatMap((setting) => setting.provenance_untracked_types))]
    .sort()
    .join(',');
  return useMemo(() => (untrackedKey.length === 0 ? filters : {
    ...filters,
    filters: [...filters.filters, { key: 'entity_type', values: untrackedKey.split(','), operator: 'not_eq', mode: 'and' }],
  }), [filters, untrackedKey]);
};

export default useProvenanceTrackedFilters;
