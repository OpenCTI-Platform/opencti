import { FunctionComponent, useEffect } from 'react';
import { UseLocalStorageHelpers } from '../utils/hooks/useLocalStorage';
import { directFilters, FilterGroup, getDefaultFilterObject } from '../utils/filters/filtersUtils';

interface GenerateDefaultDirectFiltersProps {
  filters?: FilterGroup;
  availableFilterKeys: string[];
  helpers: UseLocalStorageHelpers;
}
const GenerateDefaultDirectFilters: FunctionComponent<GenerateDefaultDirectFiltersProps> = ({ filters, availableFilterKeys, helpers }) => {
  const displayedFilters = {
    ...filters,
    filters:
      filters?.filters.filter(
        (f) => !availableFilterKeys || availableFilterKeys?.some((k) => f.key === k),
      ) || [],
  };
  useEffect(() => {
    if (displayedFilters.filters.length === 0) {
      const dFilter = availableFilterKeys?.filter((n) => directFilters.includes(n)) ?? [];
      if (dFilter.length > 0) {
        helpers?.handleClearAllFilters();
      }
    }
  }, []);
  return null;
};

export default GenerateDefaultDirectFilters;
