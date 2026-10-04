import { useMemo } from 'react';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';

/**
 * Filters of a Curation list restricted to the types whose provenance is tracked: the provenance kept on a type
 * switched off in "Settings > Customization" is no longer displayed. An abstract type (relationships, sightings,
 * observables) excludes every type below it.
 */
const useProvenanceTrackedFilters = (filters: FilterGroup): FilterGroup => {
  const untrackedKey = useEntitySettings()
    .filter((setting) => setting.availableSettings.includes('provenance_tracking') && !setting.provenance_tracking)
    .map((setting) => setting.target_type)
    .sort()
    .join(',');
  return useMemo(() => (untrackedKey.length === 0 ? filters : {
    ...filters,
    filters: [...filters.filters, { key: 'entity_type', values: untrackedKey.split(','), operator: 'not_eq', mode: 'and' }],
  }), [filters, untrackedKey]);
};

export default useProvenanceTrackedFilters;
