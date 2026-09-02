import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import FilterDate from '@components/common/lists/FilterDate';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import { Autocomplete, AutocompleteChangeReason, AutocompleteInputChangeReason, MenuItem, Select } from '@mui/material';
import Checkbox from '@mui/material/Checkbox';
import Chip from '@mui/material/Chip';
import Popover from '@mui/material/Popover';
import { SelectChangeEvent } from '@mui/material/Select';
import { useTheme } from '@mui/material/styles';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import { addDays, subDays } from 'date-fns';
import { Dispatch, FunctionComponent, ReactNode, SyntheticEvent, useState } from 'react';
import { Filter, FilterValue, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import {
  DEFAULT_WITHIN_FILTER_VALUES,
  emptyFilterGroup,
  FilterSearchContext,
  getAvailableOperatorForFilter,
  getSelectedOptions,
  isBasicTextFilter,
  isNumericFilter,
  isStixObjectTypes,
  SELF_ID,
  SELF_ID_VALUE,
  useFilterDefinition,
} from '../../utils/filters/filtersUtils';
import { getOptionsFromEntities } from '../../utils/filters/SearchEntitiesUtil';
import useSearchEntities from '../../utils/filters/useSearchEntities';
import useAttributes from '../../utils/hooks/useAttributes';
import { FilterDefinition } from '../../utils/hooks/useAuth';
import type { WidgetHost } from '../../utils/widget/widget';
import { useFormatter } from '../i18n';
import ItemIcon from '../ItemIcon';
import BasicFilterInput from './BasicFilterInput';
import DateRangeFilter from './DateRangeFilter';
import { FilterRepresentative } from './FiltersModel';
import QuickRelativeDateFiltersButtons from './QuickRelativeDateFiltersButtons';
import { useDashboardVariables } from '../../private/components/workspaces/dashboards/variables/DashboardVariablesContext';
import { useFilterVariableSelection } from '../../private/components/widgets/FilterVariableSelectionContext';

import FilterFiltersInput from './FilterFiltersInput';

interface FilterChipMenuProps {
  handleClose: () => void;
  open: boolean;
  params: FilterChipsParameter;
  filters: Filter[];
  helpers?: handleFilterHelpers;
  availableRelationFilterTypes?: Record<string, string[]>;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  entityTypes?: string[];
  searchContext?: FilterSearchContext;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  host?: WidgetHost;
}

export interface FilterChipsParameter {
  filterId?: string;
  anchorEl?: HTMLElement;
  anchorPosition?: { top: number; left: number };
}

const AUTOCOMPLETE_KEY_ACTIONS: { [k: string]: AutocompleteChangeReason | AutocompleteInputChangeReason } = {
  SELECT_OPTION: 'selectOption',
  REMOVE_OPTION: 'removeOption',
  CLEAR: 'clear',
  INPUT: 'input',
  RESET: 'reset',
};

/** Multiset difference: values present in `from` that are not matched by an occurrence in `subtracted`. */
const arrayDiffRespectingDuplicates = (from: FilterValue[], subtracted: FilterValue[]): FilterValue[] => {
  const remainingCounts = new Map<FilterValue, number>();
  subtracted.forEach((value) => remainingCounts.set(value, (remainingCounts.get(value) ?? 0) + 1));
  return from.filter((value) => {
    const count = remainingCounts.get(value) ?? 0;
    if (count > 0) {
      remainingCounts.set(value, count - 1);
      return false;
    }
    return true;
  });
};

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

export const FilterChipPopover: FunctionComponent<FilterChipMenuProps> = ({
  params,
  handleClose,
  open,
  filters,
  helpers,
  availableRelationFilterTypes,
  availableEntityTypes,
  availableRelationshipTypes,
  filtersRepresentativesMap,
  entityTypes,
  searchContext,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const filter = filters.find((f) => f.id === params.filterId);
  const filterKey = filter?.key ?? '';
  const filterOperator = filter?.operator ?? '';
  const filterValues = filter?.values ?? [];
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const filterLabel = filterKey ? t_i18n(filterDefinition?.label ?? filterKey) : '';
  const { typesWithFintelTemplates } = useAttributes();

  // ── Dashboard variable injection ──────────────────────────────────────────
  const { variables: dashboardVariables } = useDashboardVariables();
  const { onVariableSelected } = useFilterVariableSelection();
  const resolveVariableTypeForFilter = (filterDef?: FilterDefinition): string | null => {
    const defType = filterDef?.type;
    if (defType === 'id') {
      // 'id' filters can target very different kinds of objects; use the declared
      // target entity types to route to the matching variable type instead of
      // always falling back to a generic entity selector.
      const elements = filterDef?.elementsForFilterValuesSearch ?? [];
      if (elements.includes('Label')) return 'label';
      if (elements.includes('Marking-Definition')) return 'marking';
      if (elements.includes('User')) return 'user';
      if (elements.includes('Group')) return 'group';
      if (elements.includes('StatusTemplate')) return 'status';
      return 'entity_ref';
    }
    switch (defType) {
      case 'vocabulary':
      case 'enum': return 'vocabulary';
      case 'boolean': return 'boolean';
      case 'integer':
      case 'float': return 'numeric';
      case 'string':
      case 'text': return 'text';
      case 'date': return 'date';
      default: return null;
    }
  };
  const buildVariableOptions = (filterDef?: FilterDefinition): FilterOptionValue[] => {
    const matchedVarType = resolveVariableTypeForFilter(filterDef);
    if (!onVariableSelected || !matchedVarType) return [];
    return dashboardVariables
      .filter((v) => v.filterKeyType === matchedVarType)
      .map((v) => ({
        value: `__var__:${v.id}`,
        label: v.name,
        type: 'Variable',
        group: t_i18n('Variables'),
      }));
  };
  // ─────────────────────────────────────────────────────────────────────────
  const [autocompleteInputValues, setAutocompleteInputValues] = useState<Record<string, string>>({});
  const [numericUseVariable, setNumericUseVariable] = useState<Record<string, boolean>>({});
  const [textUseVariable, setTextUseVariable] = useState<Record<string, boolean>>({});

  const [inputValues, setInputValues] = useState<{
    key: string;
    values: string[];
    operator?: string;
  }[]>(filter ? [filter] : []);

  const [cacheEntities, setCacheEntities] = useState<Record<string, FilterOptionValue[]>>({});
  const [searchScope, setSearchScope] = useState<Record<string, string[]>>(
    availableRelationFilterTypes || {
      targets: [
        'Region',
        'Country',
        'Administrative-Area',
        'City',
        'Position',
        'Sector',
        'Organization',
        'Individual',
        'System',
        'Event',
        'Vulnerability',
      ],
    },
  );

  const [entities, searchEntities] = useSearchEntities({
    availableEntityTypes,
    availableRelationshipTypes,
    setInputValues,
    searchContext: { ...searchContext, entityTypes: [...(searchContext?.entityTypes ?? []), ...(entityTypes ?? [])] },
    searchScope,
  }) as [Record<string, FilterOptionValue[]>, (
    filterKey: string,
    cacheEntities: Record<string, FilterOptionValue[]>,
    setCacheEntities: Dispatch<Record<string, FilterOptionValue[]>>,
    event: SyntheticEvent,
    isSubKey?: boolean,
  ) => Record<string, FilterOptionValue[]>,
  ];

  const handleChange = (checked: boolean, value: string | null, childKey?: string) => {
    if (childKey) {
      const childFilters = filter?.values.filter((val) => val.key === childKey) as Filter[];
      const childFilter = childFilters && childFilters.length > 0 ? childFilters[0] : undefined;
      const alreadySelectedValues = childFilter?.values ?? [];
      let representationToAdd;
      if (checked) {
        // the representation to add = the former values + the added value
        representationToAdd = { key: childKey, values: [...alreadySelectedValues, value] };
      } else {
        // remove a single occurrence of the value, not every matching duplicate
        const cleanedValues = arrayDiffRespectingDuplicates(alreadySelectedValues, [value]);
        // the representation to add = the former values - the removed value
        representationToAdd = cleanedValues.length > 0 ? { key: childKey, values: cleanedValues } : undefined;
      }
      helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, representationToAdd);
    } else if (checked) {
      helpers?.handleAddRepresentationFilter(filter?.id ?? '', value);
    } else {
      helpers?.handleRemoveRepresentationFilter(filter?.id ?? '', value);
    }
  };

  const handleChangeOperator = (event: SelectChangeEvent, fDef?: FilterDefinition) => {
    const filterType = fDef?.type;
    const newOperator = event.target.value;
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

  const noValueOperator = !['not_nil', 'nil', 'has_changed', 'not_has_changed'].includes(filterOperator);
  const renderSearchScopeSelection = (key: string) => (
    <SearchScopeElement
      name={key}
      searchScope={searchScope}
      setSearchScope={setSearchScope}
      availableRelationFilterTypes={availableRelationFilterTypes}
    />
  );

  const buildAutocompleteFilter = (
    fKey: string,
    fLabel?: string,
    subKey?: string,
    disabled = false,
    effectiveFilterDefinition?: FilterDefinition,
  ): ReactNode => {
    const getEntitiesOptions = getOptionsFromEntities(entities, searchScope, fKey);
    const optionsValues = subKey ? (filterValues.find((f) => f.key === subKey)?.values ?? []) : filterValues;
    const variableOptions = buildVariableOptions(effectiveFilterDefinition);
    const hasVariableTypeMatch = variableOptions.length > 0;

    const completedTypesWithFintelTemplates = typesWithFintelTemplates.concat(['Container', 'Stix-Domain-Object', 'Stix-Core-Object']);
    const shouldAddSelfIdInFintelTemplates = host?.kind === 'fintelTemplate'
      && (filterDefinition?.type === 'id' || (filterDefinition?.filterKey === 'regardingOf' && subKey === 'id'))
      && (filterDefinition?.elementsForFilterValuesSearch ?? []).every((type) => completedTypesWithFintelTemplates.includes(type));
    const shouldAddSelfIdInCustomViews = host?.kind === 'custom-view'
      && (filterDefinition?.type === 'id' || (filterDefinition?.filterKey === 'regardingOf' && subKey === 'id'));
    const shouldAddSelfId = shouldAddSelfIdInFintelTemplates || shouldAddSelfIdInCustomViews;

    const getOptions = shouldAddSelfId
      ? [
          {
            value: SELF_ID,
            label: SELF_ID_VALUE,
            group: 'Instance',
            parentTypes: [],
            color: 'primary',
            type: 'Instance',
          },
          ...getEntitiesOptions,
        ]
      : getEntitiesOptions;

    const entitiesOptions = getOptions.filter((option) => !optionsValues.includes(option.value));
    const selectedOptionsRaw: FilterOptionValue[] = getSelectedOptions(
      [...variableOptions, ...getOptions],
      optionsValues,
      filtersRepresentativesMap,
      t_i18n,
    );
    const sourceOptionsByValue = new Map(
      [...variableOptions, ...getOptions].map((option) => [option.value, option]),
    );
    const selectedOptions: FilterOptionValue[] = selectedOptionsRaw.map((option) => {
      const sourceOption = sourceOptionsByValue.get(option.value);
      if (!sourceOption) {
        return option;
      }
      return {
        ...option,
        label: sourceOption.label ?? option.label,
        type: sourceOption.type ?? option.type,
        color: sourceOption.color ?? option.color,
        group: sourceOption.group ?? option.group,
      };
    });

    const selectedValues = new Set(selectedOptions.map((option) => option.value));
    const remainingVariableOptions = variableOptions.filter((option) => !selectedValues.has(option.value));
    const remainingEntityOptions = entitiesOptions.filter((option) => !selectedValues.has(option.value));

    const options = [...selectedOptions, ...remainingVariableOptions, ...remainingEntityOptions];

    const groupByEntities = (option: FilterOptionValue, label?: string) => {
      return t_i18n(option?.group ? option?.group : label);
    };

    const handleAutocompleteChange = (_event: SyntheticEvent, newValue: FilterOptionValue[], reason: AutocompleteChangeReason) => {
      // Handle dashboard variable selection
      if (reason === AUTOCOMPLETE_KEY_ACTIONS.SELECT_OPTION && onVariableSelected && hasVariableTypeMatch) {
        const varOption = newValue.find((v) => v.value?.startsWith('__var__:'));
        if (varOption) {
          const variableId = varOption.value.slice('__var__:'.length);
          const variable = dashboardVariables.find((v) => v.id === variableId);
          const fkt = variable?.filterKeyType ?? (effectiveFilterDefinition ? resolveVariableTypeForFilter(effectiveFilterDefinition) : null);
          // Set a sentinel filter value so the runtime substitution in resolveDataSelection
          // can replace it with the variable's current value.
          handleChange(true, `__var__:${variableId}`, subKey);
          if (variable && fkt) {
            onVariableSelected(variableId, variable.name, fkt);
          }
          return;
        }
      }
      const newValues = newValue.map((v) => v.value);

      if (reason === AUTOCOMPLETE_KEY_ACTIONS.CLEAR) {
        if (subKey) {
          const childFilters = (filter?.values ?? []).filter((val) => val.key === subKey) as Filter[];
          const childFilter = childFilters.length > 0 ? childFilters[0] : undefined;
          helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, undefined);
        } else {
          helpers?.handleReplaceFilterValues(filter?.id ?? '', []);
        }
        return;
      }

      if (reason !== AUTOCOMPLETE_KEY_ACTIONS.SELECT_OPTION && reason !== AUTOCOMPLETE_KEY_ACTIONS.REMOVE_OPTION) {
        return;
      }

      if (reason === AUTOCOMPLETE_KEY_ACTIONS.SELECT_OPTION) {
        setAutocompleteInputValues((prev) => ({ ...prev, [fKey]: '' }));
      }

      const actualFilterValues: FilterValue[] = subKey
        ? filterValues.filter((filterValue) => filterValue && filterValue.key === subKey).at(0)?.values ?? []
        : filterValues;

      // Diff as multisets (not sets) so that removing one occurrence of a duplicated
      // value (e.g. the same value/variable referenced several times) is detected —
      // a plain `.includes()` diff would consider the value still present as long as
      // at least one duplicate remains, silently dropping the removal.
      const added = arrayDiffRespectingDuplicates(newValues, actualFilterValues);
      const removed = arrayDiffRespectingDuplicates(actualFilterValues, newValues);

      if (added.length === 1) {
        const value = added[0];
        const disabledOption = disabled && actualFilterValues.length === 1 && actualFilterValues.includes(value);
        if (!disabledOption) {
          handleChange(true, value, subKey);
        }
      } else if (removed.length === 1) {
        const value = removed[0];
        const disabledOption = disabled && actualFilterValues.length === 1;
        if (!disabledOption) {
          handleChange(false, value, subKey);
        }
      }
    };

    return (
      <Autocomplete
        multiple
        key={fKey}
        value={selectedOptions}
        inputValue={autocompleteInputValues[fKey] || ''}
        getOptionLabel={(option) => option.label ?? ''}
        noOptionsText={t_i18n('No available options')}
        options={options}
        groupBy={(option) => groupByEntities(option, fLabel)}
        onInputChange={(event, newInputValue, reason: AutocompleteInputChangeReason) => {
          if (reason === AUTOCOMPLETE_KEY_ACTIONS.INPUT || reason === AUTOCOMPLETE_KEY_ACTIONS.CLEAR) {
            setAutocompleteInputValues((prev) => ({ ...prev, [fKey]: newInputValue }));
          }
          if (event && reason === AUTOCOMPLETE_KEY_ACTIONS.INPUT) {
            const syntheticEvent = { target: { value: newInputValue } } as unknown as SyntheticEvent;
            searchEntities(fKey, cacheEntities, setCacheEntities, syntheticEvent, !!subKey);
          }
        }}
        onChange={handleAutocompleteChange}
        disableCloseOnSelect
        isOptionEqualToValue={(option, val) => option.value === val.value}
        renderInput={(paramsInput) => (
          <TextField
            {...paramsInput}
            slotProps={{
              input: {
                ...paramsInput.InputProps,
                endAdornment: isStixObjectTypes.includes(fKey)
                  ? renderSearchScopeSelection(fKey)
                  : paramsInput.InputProps.endAdornment,
              },
            }}
            label={t_i18n(fLabel)}
            variant="outlined"
            size="small"
            fullWidth={true}
            autoFocus={true}
            onFocus={(event) => {
              searchEntities(
                fKey,
                cacheEntities,
                setCacheEntities,
                event,
                !!subKey,
              );
            }}
          />
        )}
        renderOption={(props, option) => {
          const actualFilterValues = subKey ? filterValues.filter((fVal) => fVal && fVal.key === subKey).at(0)?.values ?? [] : filterValues;
          const checked = actualFilterValues.includes(option.value);
          const disabledOptions = disabled && checked && actualFilterValues.length === 1;

          // Extract key from props to avoid React warning
          const { key, ...otherProps } = props;

          return (
            <Tooltip title={option.label} key={key || option.value} followCursor>
              <li
                {...otherProps}
                aria-disabled={disabledOptions}
                style={{
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  padding: 0,
                  margin: 0,
                  pointerEvents: disabledOptions ? 'none' : undefined,
                }}
              >
                <Checkbox checked={checked} disabled={disabledOptions} />
                <ItemIcon type={option.type} color={option.color} />
                <span style={{ padding: '0 4px 0 4px' }}>
                  {option.label}
                </span>
              </li>
            </Tooltip>
          );
        }}
      />
    );
  };
  const getSpecificFilter = (fDefinition?: FilterDefinition, subKey?: string, disabled = false): ReactNode => {
    const computedValues = filterValues.find((f) => f.key === fDefinition?.filterKey)?.values ?? filterValues;
    if (fDefinition?.type === 'date') {
      if (filterOperator === 'within') {
        const values = computedValues.length > 0 ? computedValues : DEFAULT_WITHIN_FILTER_VALUES;
        return (
          <DateRangeFilter
            filter={filter}
            filterKey={filterKey}
            filterValues={values}
            helpers={helpers}
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
          childKey={subKey}
          filterValues={values}
          helpers={helpers}
          disabled={disabled}
        />
      );
    }
    if (isNumericFilter(fDefinition?.type)) {
      const numericModeKey = `${filter?.id ?? filterKey}:${subKey ?? fDefinition?.filterKey ?? filterKey}`;
      const firstValue = computedValues[0];
      const currentValue = typeof firstValue === 'string' ? firstValue : '';
      const isVariableSentinel = currentValue.startsWith('__var__:');
      const variableOptions = buildVariableOptions(fDefinition);
      const canUseVariable = variableOptions.length > 0 && !!onVariableSelected;
      const useVariableMode = canUseVariable && (numericUseVariable[numericModeKey] ?? isVariableSentinel);

      const clearCurrentNumericValue = () => {
        if (subKey) {
          const childFilters = (filter?.values ?? []).filter((val) => val.key === subKey) as Filter[];
          const childFilter = childFilters.length > 0 ? childFilters[0] : undefined;
          helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, undefined);
        } else {
          helpers?.handleReplaceFilterValues(filter?.id ?? '', []);
        }
      };

      const selectedVariableOption = variableOptions.find((option) => option.value === currentValue) ?? null;

      return (
        <>
          {canUseVariable && (
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: 8 }}>
              <Checkbox
                size="small"
                checked={useVariableMode}
                onChange={(event) => {
                  const checked = event.target.checked;
                  setNumericUseVariable((prev) => ({ ...prev, [numericModeKey]: checked }));
                  if (checked && !isVariableSentinel && computedValues.length > 0) {
                    clearCurrentNumericValue();
                  }
                  if (!checked && isVariableSentinel) {
                    clearCurrentNumericValue();
                  }
                }}
              />
              <span>{t_i18n('Use variable')}</span>
            </div>
          )}

          {useVariableMode ? (
            <Autocomplete
              key={`${numericModeKey}-variable`}
              value={selectedVariableOption}
              options={variableOptions}
              getOptionLabel={(option) => option.label ?? ''}
              noOptionsText={t_i18n('No available options')}
              isOptionEqualToValue={(option, val) => option.value === val.value}
              onChange={(_event, option) => {
                if (!option) {
                  clearCurrentNumericValue();
                  return;
                }
                const variableId = option.value.slice('__var__:'.length);
                const variable = dashboardVariables.find((v) => v.id === variableId);
                const fkt = variable?.filterKeyType ?? (fDefinition ? resolveVariableTypeForFilter(fDefinition) : null);
                handleChange(true, `__var__:${variableId}`, subKey);
                if (variable && fkt) {
                  onVariableSelected?.(variableId, variable.name, fkt);
                }
              }}
              renderInput={(paramsInput) => (
                <TextField
                  {...paramsInput}
                  label={t_i18n('Variable')}
                  variant="outlined"
                  size="small"
                  fullWidth={true}
                />
              )}
            />
          ) : (
            <BasicFilterInput
              filter={filter}
              filterKey={filterKey}
              filterValues={computedValues}
              helpers={helpers}
              label={filterLabel}
              type="number"
            />
          )}
        </>
      );
    }
    if (isBasicTextFilter(filterDefinition)) {
      const textModeKey = `${filter?.id ?? filterKey}:${subKey ?? fDefinition?.filterKey ?? filterKey}`;
      const computedValues = filterValues.find((f) => f.key === fDefinition?.filterKey)?.values ?? filterValues;
      const firstValue = computedValues[0];
      const currentValue = typeof firstValue === 'string' ? firstValue : '';
      const isVariableSentinel = currentValue.startsWith('__var__:');
      const variableOptions = buildVariableOptions(fDefinition);
      const canUseVariable = variableOptions.length > 0 && !!onVariableSelected;
      const useVariableMode = canUseVariable && (textUseVariable[textModeKey] ?? isVariableSentinel);

      const clearCurrentTextValue = () => {
        if (subKey) {
          const childFilters = (filter?.values ?? []).filter((val) => val.key === subKey) as Filter[];
          const childFilter = childFilters.length > 0 ? childFilters[0] : undefined;
          helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, undefined);
        } else {
          helpers?.handleReplaceFilterValues(filter?.id ?? '', []);
        }
      };

      const selectedVariableOption = variableOptions.find((option) => option.value === currentValue) ?? null;

      return (
        <>
          {canUseVariable && (
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: 8 }}>
              <Checkbox
                size="small"
                checked={useVariableMode}
                onChange={(event) => {
                  const checked = event.target.checked;
                  setTextUseVariable((prev) => ({ ...prev, [textModeKey]: checked }));
                  if (checked && !isVariableSentinel && computedValues.length > 0) {
                    clearCurrentTextValue();
                  }
                  if (!checked && isVariableSentinel) {
                    clearCurrentTextValue();
                  }
                }}
              />
              <span>{t_i18n('Use variable')}</span>
            </div>
          )}

          {useVariableMode ? (
            <Autocomplete
              key={`${textModeKey}-variable`}
              value={selectedVariableOption}
              options={variableOptions}
              getOptionLabel={(option) => option.label ?? ''}
              noOptionsText={t_i18n('No available options')}
              isOptionEqualToValue={(option, val) => option.value === val.value}
              onChange={(_event, option) => {
                if (!option) {
                  clearCurrentTextValue();
                  return;
                }
                const variableId = option.value.slice('__var__:'.length);
                const variable = dashboardVariables.find((v) => v.id === variableId);
                const fkt = variable?.filterKeyType ?? (fDefinition ? resolveVariableTypeForFilter(fDefinition) : null);
                handleChange(true, `__var__:${variableId}`, subKey);
                if (variable && fkt) {
                  onVariableSelected?.(variableId, variable.name, fkt);
                }
              }}
              renderInput={(paramsInput) => (
                <TextField
                  {...paramsInput}
                  label={t_i18n('Variable')}
                  variant="outlined"
                  size="small"
                  fullWidth={true}
                />
              )}
            />
          ) : (
            <BasicFilterInput
              filter={filter}
              filterKey={filterKey}
              filterValues={filterValues}
              helpers={helpers}
              label={filterLabel}
            />
          )}
        </>
      );
    }
    return null;
  };

  const displayOperatorAndFilter = (fKey: string, subKey?: string, disabled = false) => {
    const isStixFiltering = entityTypes?.includes('Stix-Filtering');
    const availableOperators = getAvailableOperatorForFilter(filterDefinition, subKey, { isStixFiltering });
    const finalFilterDefinition = useFilterDefinition(fKey, entityTypes, subKey);
    return (
      <>
        { availableOperators.length > 0 && (
          <Select
            labelId="change-operator-select-label"
            id="change-operator-select"
            value={filterOperator}
            label="Operator"
            fullWidth={true}
            onChange={(event) => handleChangeOperator(event, finalFilterDefinition)}
            style={{ marginBottom: 15 }}
            disabled={disabled}
          >
            {availableOperators.map((value) => (
              <MenuItem key={value} value={value}>
                {t_i18n(OperatorKeyValues[value])}
              </MenuItem>
            ))}
          </Select>
        )}
        {noValueOperator && isSpecificFilter(finalFilterDefinition) && (
          <>{getSpecificFilter(finalFilterDefinition, subKey, disabled)}</>
        )}
        {noValueOperator && !isSpecificFilter(finalFilterDefinition) && (
          <>{buildAutocompleteFilter(
            subKey ?? fKey,
            finalFilterDefinition?.label ?? t_i18n(fKey),
            subKey,
            disabled,
            finalFilterDefinition,
          )}</>
        )}
      </>
    );
  };

  let disableSubfilter1 = false;
  let disableSubfilter2 = false;
  if (filterDefinition?.subFilters
    && filterDefinition.subFilters.length > 1
    && filterDefinition?.subFilters[1].filterKey === 'dynamic'
    && filter?.values.filter((f) => f.key === 'relationship_type').length === 0
  ) {
    disableSubfilter2 = true;
  } else if (filterDefinition?.subFilters
    && filterDefinition.subFilters.length > 1
    && filterDefinition?.subFilters[1].filterKey === 'dynamic'
    && (filter?.values.filter((f) => f.key === 'dynamic')?.length ?? 0) > 0) {
    disableSubfilter1 = true;
  }
  return (
    <Popover
      open={open}
      anchorReference="anchorPosition"
      anchorPosition={params.anchorPosition ?? { top: 0, left: 0 }}
      onClose={handleClose}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'left',
      }}
      slotProps={{
        paper: {
          elevation: 1,
          style: { marginTop: 10 },
        },
      }}
    >
      {filterDefinition?.subFilters && filterDefinition.subFilters.length > 1
        ? (
            <div
              style={{
                width: 250,
                padding: 8,
              }}
            >
              {displayOperatorAndFilter(filterKey, filterDefinition?.subFilters[0].filterKey, disableSubfilter1)}
              <Chip
                style={{
                  fontFamily: 'Consolas, monaco, monospace',
                  margin: '10px 10px 15px 0',
                }}
                label={t_i18n('WITH')}
              />
              {displayOperatorAndFilter(filterKey, filterDefinition.subFilters[1].filterKey, disableSubfilter2)}
            </div>
          )
        : (
            <div style={{ display: 'inline-flex' }}>
              <div
                style={{
                  width: 250,
                  padding: 8,
                }}
              >
                {displayOperatorAndFilter(filterKey)}
              </div>
              {filterOperator === 'within'
                && (
                  <div style={{ width: 150, display: 'inline-flex' }}>
                    <div style={{
                      color: theme.palette.text.disabled,
                      borderLeft: '0.5px solid',
                      marginLeft: '10px',
                      marginTop: '10px',
                      marginBottom: '10px',
                    }}
                    />
                    <QuickRelativeDateFiltersButtons filter={filter} helpers={helpers} handleClose={handleClose} />
                  </div>
                )
              }
            </div>
          )
      }
    </Popover>
  );
};
