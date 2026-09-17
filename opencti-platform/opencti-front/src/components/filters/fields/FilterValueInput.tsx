import FilterDate from '@components/common/lists/FilterDate';
import { addDays } from 'date-fns';
import { Dispatch, FunctionComponent, ReactNode, SetStateAction } from 'react';
import { Filter, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import {
  DEFAULT_WITHIN_FILTER_VALUES,
  emptyFilterGroup,
  isBasicTextFilter,
  isNumericFilter,
  NO_VALUES_FILTER_OPERATORS,
  useFilterDefinition,
} from '../../../utils/filters/filtersUtils';
import { FilterDefinition } from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../i18n';
import BasicFilterInput from '../BasicFilterInput';
import DateRangeFilter from '../DateRangeFilter';
import FilterFiltersInput from '../FilterFiltersInput';
import { useFilterEditorContext } from './FilterEditorContext';
import FilterEntityAutocomplete from './FilterEntityAutocomplete';

export interface FilterValueInputProps {
  filter?: Filter;
  filterKey: string;
  inputValues: FilterEditorInputValue[];
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
  subKey?: string;
  disabled?: boolean;
  /** Shows relative-date shortcuts (Last 7 days, ...) on the From field of a `within` date
   * filter. Only makes sense in the nested-filter-group row layout, not the root chip popover. */
  showRelativeDateShortcuts?: boolean;
}

/**
 * Value editor of a single filter (or of one sub-key of a composite filter): picks the widget
 * matching the filter type — date, date range, nested filter group, number, text — and falls back
 * to the entity autocomplete for everything else.
 *
 * Renders nothing when the current operator takes no value (`nil`, `not_nil`, ...).
 * Callers own their own layout and `data-testid`s.
 */
const FilterValueInput: FunctionComponent<FilterValueInputProps> = ({
  filter,
  filterKey,
  inputValues,
  setInputValues,
  subKey,
  disabled = false,
  showRelativeDateShortcuts = false,
}) => {
  const { t_i18n } = useFormatter();
  const { helpers, entityTypes, host } = useFilterEditorContext();

  const filterOperator = filter?.operator ?? '';
  const filterValues = filter?.values ?? [];
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const filterLabel = filterKey ? t_i18n(filterDefinition?.label ?? filterKey) : '';
  const finalFilterDefinition = useFilterDefinition(filterKey, entityTypes, subKey);

  const handleDateChange = (_: string, value: string) => {
    // convert the date to handle comparison with a timestamp
    const date = new Date(value);
    let filterDate = date;
    if (filter?.operator === 'lte' || filter?.operator === 'gt') { // lte date <=> lte (date+1 0:0:0)  /// gt date <=> gt (date+1 0:0:0)
      filterDate = addDays(date, 1);
    }
    helpers?.handleAddSingleValueFilter(filter?.id ?? '', filterDate.toISOString());
  };

  const isSpecificFilter = (fDef?: FilterDefinition) => {
    const filterType = fDef?.type;
    return (
      filterType === 'date'
      || filterType === 'filters'
      || isNumericFilter(filterType)
      || isBasicTextFilter(fDef)
    );
  };

  const BasicFilterDate = ({ value }: { value?: string }) => (
    <FilterDate
      defaultHandleAddFilter={handleDateChange}
      filterKey={filterKey}
      operator={filterOperator}
      inputValues={inputValues}
      setInputValues={setInputValues}
      filterLabel={filterLabel}
      filterValue={value}
    />
  );

  const getSpecificFilter = (fDefinition?: FilterDefinition, fSubKey?: string, isDisabled = false): ReactNode => {
    const computedValues = filterValues.find((f) => f.key === fDefinition?.filterKey)?.values ?? filterValues;
    if (fDefinition?.type === 'date') {
      if (filterOperator === 'within') {
        const values = computedValues.length > 0 ? computedValues : DEFAULT_WITHIN_FILTER_VALUES;
        return (
          <DateRangeFilter
            key={values.join('|')}
            filter={filter}
            filterKey={filterKey}
            filterValues={values}
            helpers={helpers}
            showRelativeDateShortcuts={showRelativeDateShortcuts}
          />
        );
      }
      return <BasicFilterDate value={computedValues.length > 0 ? computedValues[0] : undefined} />;
    }
    if (fDefinition?.type === 'filters') {
      const finalComputedValues = computedValues.filter((v: object) => 'filters' in v); // we keep values of type FilterGroup
      const values = finalComputedValues.length > 0 ? finalComputedValues[0] : emptyFilterGroup;
      return (
        <FilterFiltersInput
          filter={filter}
          filterKey={filterKey}
          childKey={fSubKey}
          filterValues={values}
          helpers={helpers}
          disabled={isDisabled}
          host={host}
        />
      );
    }
    if (isNumericFilter(fDefinition?.type)) {
      return (
        <BasicFilterInput
          filter={filter}
          filterKey={filterKey}
          filterValues={computedValues}
          helpers={helpers}
          label={filterLabel}
          type="number"
        />
      );
    }
    if (isBasicTextFilter(filterDefinition)) {
      return (
        <BasicFilterInput
          filter={filter}
          filterKey={filterKey}
          filterValues={filterValues}
          helpers={helpers}
          label={filterLabel}
        />
      );
    }
    return null;
  };

  const isOperatorRequiringValue = !NO_VALUES_FILTER_OPERATORS.includes(filterOperator);
  if (!isOperatorRequiringValue) return null;

  if (isSpecificFilter(finalFilterDefinition)) {
    return <>{getSpecificFilter(finalFilterDefinition, subKey, disabled)}</>;
  }

  return (
    <FilterEntityAutocomplete
      filter={filter}
      filterKey={filterKey}
      setInputValues={setInputValues}
      subKey={subKey}
      disabled={disabled}
      label={finalFilterDefinition?.label ?? t_i18n(filterKey)}
    />
  );
};

export default FilterValueInput;
