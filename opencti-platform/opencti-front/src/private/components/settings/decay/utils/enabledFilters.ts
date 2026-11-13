import { useMemo } from 'react';
import { useCustomFieldStixFilterKeys } from '../../../../../utils/filters/filtersUtils';

export const enabledFilters = ['creator_id', 'createdBy', 'objectMarking', 'objectLabel', 'pattern_type', 'indicator_types', 'x_opencti_main_observable_type'];

// The decay rules and their exclusions select indicators on these keys, plus the custom fields attached to Indicator
export const useDecayFilterKeys = (): string[] => {
  const customFieldFilterKeys = useCustomFieldStixFilterKeys('Indicator');
  return useMemo(() => [...enabledFilters, ...customFieldFilterKeys], [customFieldFilterKeys]);
};
