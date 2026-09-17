import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { addDays, subDays } from 'date-fns';
import { CSSProperties, Dispatch, FunctionComponent, SetStateAction } from 'react';
import { Filter, handleFilterHelpers, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import { getAvailableOperatorForFilter, useFilterDefinition } from '../../../utils/filters/filtersUtils';
import { FilterDefinition } from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../i18n';

const OperatorKeyValues: {
  [key: string]: string;
} = {
  eq: 'Equals',
  not_eq: 'Not equals',
  nil: 'Empty',
  not_nil: 'Not empty',
  gt: 'Greater than',
  gte: 'Greater than/ Equals',
  lt: 'Lower than',
  lte: 'Lower than/ Equals',
  contains: 'Contains',
  not_contains: 'Not contains',
  starts_with: 'Starts with',
  not_starts_with: 'Not starts with',
  ends_with: 'Ends with',
  not_ends_with: 'Not ends with',
  search: 'Search',
  within: 'Within',
  only_eq_to: 'Only equal to',
  not_only_eq_to: 'Not only equal to',
  has_changed: 'Has changed',
  not_has_changed: 'Has not changed',
};

export interface FilterOperatorSelectProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
  entityTypes?: string[];
  subKey?: string;
  disabled?: boolean;
  /** Accessible name of the operator select. */
  label?: string;
  /** DOM id of the operator trigger. */
  triggerId?: string;
  style?: CSSProperties;
}

/**
 * Operator select of a single filter (or of one sub-key of a composite filter).
 * Renders nothing when the filter definition allows no operator choice.
 *
 * Callers own their own layout: place this where it belongs in your DOM. That is why
 * there is no wrapper, no `data-testid` and no `hide` prop here.
 */
const FilterOperatorSelect: FunctionComponent<FilterOperatorSelectProps> = ({
  filter,
  filterKey,
  helpers,
  setInputValues,
  entityTypes,
  subKey,
  disabled = false,
  label,
  triggerId = 'change-operator-select',
  style,
}) => {
  const { t_i18n } = useFormatter();
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const finalFilterDefinition = useFilterDefinition(filterKey, entityTypes, subKey);

  const isStixFiltering = entityTypes?.includes('Stix-Filtering');
  const availableOperators = getAvailableOperatorForFilter(filterDefinition, subKey, { isStixFiltering });
  const accessibleLabel = label ?? t_i18n('Operator');

  if (availableOperators.length === 0) return null;

  const handleChangeOperator = (newOperator: string, fDef?: FilterDefinition) => {
    const filterType = fDef?.type;
    // for date check (date in days, operator) correspond to (timestamp in seconds, operator)
    if (filterType === 'date' && filter && filter.values.length > 0) {
      const formerOperator = filter?.operator;
      const formerDate = filter.values[0]; // dates filters have a single value
      if (formerOperator && ['lte', 'gt'].includes(formerOperator) && ['lt', 'gte'].includes(newOperator)) {
        const newDate = subDays(new Date(formerDate), -1).toISOString();
        const newInputValue = { key: filterKey, values: [newDate], newOperator };
        setInputValues([newInputValue]);
        helpers?.handleAddSingleValueFilter(filter?.id ?? '', newDate);
      } else if (formerOperator && ['lt', 'gte'].includes(formerOperator) && ['lte', 'gt'].includes(newOperator)) {
        const newDate = addDays(new Date(formerDate), 1).toISOString();
        const newInputValue = { key: filterKey, values: [newDate], newOperator };
        setInputValues([newInputValue]);
        helpers?.handleAddSingleValueFilter(filter?.id ?? '', newDate);
      }
    }
    // modify the operator
    helpers?.handleChangeOperatorFilters(filter?.id ?? '', newOperator);
  };

  return (
    <Select
      value={filter?.operator ?? ''}
      onValueChange={(value) => handleChangeOperator(value, finalFilterDefinition)}
      disabled={disabled}
    >
      {/* The MUI version pointed labelId at a label that does not exist, so
          the trigger had no accessible name at all. Named here. */}
      <SelectTrigger id={triggerId} aria-label={accessibleLabel} style={style}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={accessibleLabel}>
        {availableOperators.map((value) => (
          <SelectItem key={value} value={value}>
            {t_i18n(OperatorKeyValues[value])}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};

export default FilterOperatorSelect;
