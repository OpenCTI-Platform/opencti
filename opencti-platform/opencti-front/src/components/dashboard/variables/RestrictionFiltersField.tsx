import { useEffect, useRef } from 'react';
import { Text } from '@filigran/design-system';
import Filters from '@components/common/lists/Filters';
import FilterIconButton from '../../FilterIconButton';
import useFiltersState from '../../../utils/filters/useFiltersState';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup, useAvailableFilterKeysForEntityTypes } from '../../../utils/filters/filtersUtils';
import { DashboardVariablesProvider } from '../DashboardVariablesContext';

export interface RestrictionFiltersFieldProps {
  // Types of the entity variable: the rule only offers the filter keys of these types.
  entityTypes: string[];
  value: FilterGroup | undefined;
  onChange: (filters: FilterGroup) => void;
  label: string;
  error?: string;
}

/**
 * Editor of the rule of an entity variable restricted by filters: the same filters as the dynamic sources of a widget,
 * without saved filters (a restriction stores a filter group only).
 */
const RestrictionFiltersField = ({ entityTypes, value, onChange, label, error }: RestrictionFiltersFieldProps) => {
  const [filters, helpers] = useFiltersState(value ?? emptyFilterGroup);
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(entityTypes);
  const searchContext = { entityTypes };
  // The rule is reported on each of its changes, not on mount: the dialog would read the first render as an edit.
  const isMounted = useRef(false);
  useEffect(() => {
    if (isMounted.current) onChange(filters);
    else isMounted.current = true;
  }, [filters]);

  return (
    // The dialog lives in the dashboard: without this, the filters would offer its variables as values,
    // while a variable cannot restrict another one.
    <DashboardVariablesProvider variables={undefined}>
      <div className="flex flex-col gap-2" role="group" aria-label={label}>
        <Text as="span" variant="body-sm">{label}</Text>
        <div className="flex items-center">
          <Filters
            availableFilterKeys={availableFilterKeys}
            availableEntityTypes={entityTypes}
            helpers={helpers}
            searchContext={searchContext}
          />
        </div>
        <FilterIconButton
          filters={filters}
          helpers={helpers}
          availableFilterKeys={availableFilterKeys}
          availableEntityTypes={entityTypes}
          searchContext={searchContext}
          entityTypes={entityTypes}
        />
        {error && <Text as="span" variant="caption" className="text-input-error">{error}</Text>}
      </div>
    </DashboardVariablesProvider>
  );
};

export default RestrictionFiltersField;
