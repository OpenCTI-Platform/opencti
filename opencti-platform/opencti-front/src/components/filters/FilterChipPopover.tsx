import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import FilterDate from '@components/common/lists/FilterDate';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import { Autocomplete, AutocompleteChangeReason, AutocompleteInputChangeReason } from '@mui/material';
import { Checkbox, Chip, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import Popover from '@mui/material/Popover';
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
  NO_VALUES_FILTER_OPERATORS,
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

import FilterFiltersInput from './FilterFiltersInput';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../utils/fdsLayer';

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
  const isOperatorRequiringValue = !NO_VALUES_FILTER_OPERATORS.includes(filterOperator);
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const filterLabel = filterKey ? t_i18n(filterDefinition?.label ?? filterKey) : '';
  const { typesWithFintelTemplates } = useAttributes();
  const [autocompleteInputValues, setAutocompleteInputValues] = useState<Record<string, string>>({});

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
    const selectedOptions: FilterOptionValue[] = getSelectedOptions(getOptions, optionsValues, filtersRepresentativesMap, t_i18n);

    const options = [...selectedOptions, ...entitiesOptions];

    const groupByEntities = (option: FilterOptionValue, label?: string) => {
      return t_i18n(option?.group ? option?.group : label);
    };

    const handleAutocompleteChange = (_event: SyntheticEvent, newValue: FilterOptionValue[], reason: AutocompleteChangeReason) => {
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

      const added = newValues.filter((v) => !actualFilterValues.includes(v));
      const removed = actualFilterValues.filter((v: FilterValue) => !newValues.includes(v));

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
        // FDS-ORNAMENT: stays on MUI for this round. Its input endAdornment
        // carries the search-scope selector for STIX object types, which is the
        // gap #155 closes with `adornment` on ComboboxField. FIFTH ornament site.
        // See fds-migration/LIBRARY-FEEDBACK.md
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
            role="search"
            {...paramsInput}
            slotProps={{
              input: {
                ...paramsInput.InputProps,
                type: 'search',
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
                  minHeight: 32,
                  padding: '0 8px 0 16px',
                  gap: 8,
                  margin: 0,
                  pointerEvents: disabledOptions ? 'none' : undefined,
                }}
              >
                {/* NOT `presentational`, deliberately. This row IS a role="option" in
                    MUI's Autocomplete listbox, so a real control nested in it is
                    an axe nested-interactive finding -- but that finding predates
                    this conversion (the box here was a real MUI Checkbox), and
                    `presentational` renders an unfocusable <span>, which removes
                    the checkbox role that filters.pageModel checks to pick a
                    filter value. Fixing the nesting means changing this markup
                    and that page model together; see NIGHT-LOG-2. */}
                <Checkbox checked={checked} disabled={disabledOptions} />
                <ItemIcon type={option.type} color={option.color} />
                <span>
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
    const isStixFiltering = entityTypes?.includes('Stix-Filtering');
    const availableOperators = getAvailableOperatorForFilter(filterDefinition, subKey, { isStixFiltering });
    const finalFilterDefinition = useFilterDefinition(fKey, entityTypes, subKey);
    return (
      <>
        {availableOperators.length > 0 && (
          <Select
            value={filterOperator}
            onValueChange={(value) => handleChangeOperator(value, finalFilterDefinition)}
            disabled={disabled}
          >
            {/* The MUI version pointed labelId at a label that does not exist, so
                the trigger had no accessible name at all. Named here. */}
            <SelectTrigger id="change-operator-select" aria-label={t_i18n('Operator')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Operator')}>
              {availableOperators.map((value) => (
                <SelectItem key={value} value={value}>
                  {t_i18n(OperatorKeyValues[value])}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {isOperatorRequiringValue && isSpecificFilter(finalFilterDefinition) && (
          <>{getSpecificFilter(finalFilterDefinition, subKey, disabled)}</>
        )}
        {isOperatorRequiringValue && !isSpecificFilter(finalFilterDefinition) && (
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
          // Filter popovers: surface on `--bg-elevation-highlight` at layer 1,
          // the fields inside at layer 2. See utils/fdsLayer.ts.
          className: fdsLayerClass(FILTER_POPOVER_LAYER),
          sx: { ...filterPopoverPaperSx, marginTop: '10px' },
        },
      }}
    >
      {filterDefinition?.subFilters && filterDefinition.subFilters.length > 1
        ? (
            <div
              style={{
                minWidth: 250,
                padding: 8,
                display: 'flex',
                flexDirection: 'column',
                gap: 16,
              }}
            >
              {displayOperatorAndFilter(filterKey, filterDefinition?.subFilters[0].filterKey, disableSubfilter1)}
              <Chip
                style={{ alignSelf: 'flex-start' }}
                label={t_i18n('WITH')}
              />
              {displayOperatorAndFilter(filterKey, filterDefinition.subFilters[1].filterKey, disableSubfilter2)}
            </div>
          )
        : (
            <div style={{ display: 'inline-flex' }}>
              <div
                style={{
                  minWidth: 250,
                  padding: 8,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 16,
                }}
              >
                {displayOperatorAndFilter(filterKey)}
              </div>
              {filterOperator === 'within'
                && (
                  <div style={{ display: 'inline-flex', flexShrink: 0, width: 'max-content' }}>
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
