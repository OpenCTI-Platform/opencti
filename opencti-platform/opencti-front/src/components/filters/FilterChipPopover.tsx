import React, { Dispatch, FunctionComponent, ReactNode, SyntheticEvent, useState } from 'react';
import Popover from '@mui/material/Popover';
import TextField from '@mui/material/TextField';
import Checkbox from '@mui/material/Checkbox';
import Tooltip from '@mui/material/Tooltip';
import FilterDate from '@components/common/lists/FilterDate';
import { Autocomplete, MenuItem, Select } from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import Chip from '@mui/material/Chip';
import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { addDays, subDays } from 'date-fns';
import { useTheme } from '@mui/material/styles';
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
import { useFormatter } from '../i18n';
import ItemIcon from '../ItemIcon';
import { getOptionsFromEntities } from '../../utils/filters/SearchEntitiesUtil';
import { FilterDefinition } from '../../utils/hooks/useAuth';
import { FilterRepresentative } from './FiltersModel';
import useSearchEntities from '../../utils/filters/useSearchEntities';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import useAttributes from '../../utils/hooks/useAttributes';
import BasicFilterInput from './BasicFilterInput';
import QuickRelativeDateFiltersButtons from './QuickRelativeDateFiltersButtons';
import DateRangeFilter from './DateRangeFilter';

import FilterFiltersInput from './FilterFiltersInput';
import stopEvent from '../../utils/domEvent';

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
  fintelTemplatesContext?: boolean;
}

export interface FilterChipsParameter {
  filterId?: string;
  anchorEl?: HTMLElement;
}

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
  fintelTemplatesContext,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const filter = filters.find((f) => f.id === params.filterId);
  const filterKey = filter?.key ?? '';
  const filterOperator = filter?.operator ?? '';
  const filterValues = filter?.values ?? [];
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const filterLabel = t_i18n(filterDefinition?.label ?? filterKey);
  const { typesWithFintelTemplates } = useAttributes();

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
        const cleanedValues = alreadySelectedValues.filter((val) => val !== value);
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

  const noValueOperator = !['not_nil', 'nil'].includes(filterOperator);
  const renderSearchScopeSelection = (key: string) => (
    <SearchScopeElement
      name={key}
      searchScope={searchScope}
      setSearchScope={setSearchScope}
      availableRelationFilterTypes={availableRelationFilterTypes}
    />
  );

  const buildAutocompleteFilter = (fKey: string, fLabel?: string, subKey?: string, disabled = false): ReactNode => {
    const getEntitiesOptions = getOptionsFromEntities(entities, searchScope, fKey);
    const optionsValues = subKey ? (filterValues.find((f) => f.key === subKey)?.values ?? []) : filterValues;

    const completedTypesWithFintelTemplates = typesWithFintelTemplates.concat(['Container', 'Stix-Domain-Object', 'Stix-Core-Object']);
    const shouldAddSelfId = fintelTemplatesContext
      && (filterDefinition?.type === 'id' || (filterDefinition?.filterKey === 'regardingOf' && subKey === 'id'))
      && (filterDefinition?.elementsForFilterValuesSearch ?? []).every((type) => completedTypesWithFintelTemplates.includes(type));

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
    const selectedOptions: FilterOptionValue[] = getSelectedOptions(getOptions, optionsValues, filtersRepresentativesMap, t_i18n);

    const options = [...selectedOptions, ...entitiesOptions];

    const groupByEntities = (option: FilterOptionValue, label?: string) => {
      return t_i18n(option?.group ? option?.group : label);
    };
    return (
      <Autocomplete
        multiple
        key={fKey}
        getOptionLabel={(option) => option.label ?? ''}
        noOptionsText={t_i18n('No available options')}
        options={options}
        groupBy={(option) => groupByEntities(option, fLabel)}
        onInputChange={(event) => searchEntities(fKey, cacheEntities, setCacheEntities, event, !!subKey)}
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
            onFocus={(event) => searchEntities(
              fKey,
              cacheEntities,
              setCacheEntities,
              event,
              !!subKey,
            )
            }
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
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.stopPropagation();
                  }
                }}
                onClick={() => (disabledOptions ? {} : handleChange(!checked, option.value, subKey))}
                style={{
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  padding: 0,
                  margin: 0,
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

  const displayOperatorAndFilter = (fKey: string, subKey?: string, disabled = false) => {
    const availableOperators = getAvailableOperatorForFilter(filterDefinition, subKey);
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
            MenuProps={{
            // Force MUI to use a backdrop
              hideBackdrop: false,
              BackdropProps: {
                style: {
                // Make the backdrop invisible because we already have one
                  backgroundColor: 'rgba(0, 0, 0, 0)',
                },
                // Prevent clicks from going through
                onClick: (e) => {
                  stopEvent(e);
                  handleClose();
                },
                onMouseDown: stopEvent,
              },
            }}
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
          <>{buildAutocompleteFilter(subKey ?? fKey, finalFilterDefinition?.label ?? t_i18n(fKey), subKey, disabled)}</>
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
      anchorEl={params.anchorEl}
      onClose={handleClose}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'left',
      }}
      // Force MUI to use a backdrop
      hideBackdrop={false}
      slotProps={{
        paper: {
          elevation: 1,
          style: { marginTop: 10 },
        },
        backdrop: {
          style: {
            // Make the backdrop invisible because we already have one
            backgroundColor: 'rgba(0, 0, 0, 0)',
          },
          // Prevent clicks from going through
          onClick: (e) => {
            stopEvent(e);
            handleClose();
          },
          onMouseDown: stopEvent,
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
