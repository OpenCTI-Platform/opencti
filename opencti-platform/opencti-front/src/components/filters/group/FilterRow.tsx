import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import FilterDate from '@components/common/lists/FilterDate';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import { Autocomplete, AutocompleteChangeReason, AutocompleteInputChangeReason } from '@mui/material';
import { Checkbox, IconButton, Menu, MenuContent, MenuItem, MenuTrigger, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import CloseOutlined from '@mui/icons-material/CloseOutlined';
import MoreVert from '@mui/icons-material/MoreVert';
import { addDays, subDays } from 'date-fns';
import { CSSProperties, Dispatch, FunctionComponent, ReactNode, SetStateAction, SyntheticEvent, useState } from 'react';
import { Filter, FilterValue, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import {
  DEFAULT_WITHIN_FILTER_VALUES,
  emptyFilterGroup,
  FilterSearchContext,
  getAvailableOperatorForFilter,
  getDefaultFilterObject,
  getFilterDefinitionFromFilterKeysMap,
  getSelectedOptions,
  isBasicTextFilter,
  isNumericFilter,
  isStixObjectTypes,
  NO_VALUES_FILTER_OPERATORS,
  SELF_ID,
  SELF_ID_VALUE,
  useBuildFilterKeysMapFromEntityType,
  useFilterDefinition,
} from '../../../utils/filters/filtersUtils';
import { getOptionsFromEntities } from '../../../utils/filters/SearchEntitiesUtil';
import useSearchEntities from '../../../utils/filters/useSearchEntities';
import useAttributes from '../../../utils/hooks/useAttributes';
import { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { WidgetHost } from '../../../utils/widget/widget';
import { useFormatter } from '../../i18n';
import ItemIcon from '../../ItemIcon';
import BasicFilterInput from '../BasicFilterInput';
import DateRangeFilter from '../DateRangeFilter';
import FilterFiltersInput from '../FilterFiltersInput';
import { FilterRepresentative } from '../FiltersModel';

export const AUTOCOMPLETE_KEY_ACTIONS: { [k: string]: AutocompleteChangeReason | AutocompleteInputChangeReason } = {
  SELECT_OPTION: 'selectOption',
  REMOVE_OPTION: 'removeOption',
  CLEAR: 'clear',
  INPUT: 'input',
  RESET: 'reset',
};

export const OperatorKeyValues: {
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

export interface FilterEditorInputValue {
  key: string;
  values: string[];
  operator?: string;
}

export interface FilterEditorState {
  inputValues: FilterEditorInputValue[];
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
  autocompleteInputValues: Record<string, string>;
  setAutocompleteInputValues: Dispatch<SetStateAction<Record<string, string>>>;
  cacheEntities: Record<string, FilterOptionValue[]>;
  setCacheEntities: Dispatch<Record<string, FilterOptionValue[]>>;
  searchScope: Record<string, string[]>;
  setSearchScope: Dispatch<SetStateAction<Record<string, string[]>>>;
  entities: Record<string, FilterOptionValue[]>;
  searchEntities: (
    filterKey: string,
    cacheEntities: Record<string, FilterOptionValue[]>,
    setCacheEntities: Dispatch<Record<string, FilterOptionValue[]>>,
    event: SyntheticEvent,
    isSubKey?: boolean,
  ) => Record<string, FilterOptionValue[]>;
}

interface UseFilterEditorStateArgs {
  filter?: Filter;
  entityTypes?: string[];
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
}

/**
 * Holds all the local (non-filter) state needed to edit one filter: the entity search cache,
 * the search scopes and the transient input values.
 * Extracted from FilterChipPopover so that both the popover and FilterRow share the exact same behaviour.
 */
export const useFilterEditorState = ({
  filter,
  entityTypes,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
}: UseFilterEditorStateArgs): FilterEditorState => {
  const [autocompleteInputValues, setAutocompleteInputValues] = useState<Record<string, string>>({});
  const [inputValues, setInputValues] = useState<FilterEditorInputValue[]>(filter ? [filter as FilterEditorInputValue] : []);
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
  }) as [Record<string, FilterOptionValue[]>, FilterEditorState['searchEntities']];

  return {
    inputValues,
    setInputValues,
    autocompleteInputValues,
    setAutocompleteInputValues,
    cacheEntities,
    setCacheEntities,
    searchScope,
    setSearchScope,
    entities,
    searchEntities,
  };
};

export interface FilterOperatorAndValueProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  state: FilterEditorState;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  entityTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  host?: WidgetHost;
  subKey?: string;
  disabled?: boolean;
  /** Accessible name of the operator select. */
  operatorLabel?: string;
  /** DOM id of the operator trigger. */
  operatorTriggerId?: string;
  operatorStyle?: CSSProperties;
  dataTestIds?: { operator?: string; value?: string };
}

/**
 * Operator select + value editor of a single filter (or of one sub-key of a combined filter).
 * This is the whole editing logic previously inlined in FilterChipPopover, shared by the popover and by FilterRow.
 */
export const FilterOperatorAndValue: FunctionComponent<FilterOperatorAndValueProps> = ({
  filter,
  filterKey,
  helpers,
  state,
  filtersRepresentativesMap,
  entityTypes,
  availableRelationFilterTypes,
  host,
  subKey,
  disabled = false,
  operatorLabel,
  operatorTriggerId = 'change-operator-select',
  operatorStyle,
  dataTestIds,
}) => {
  const { t_i18n } = useFormatter();
  const { typesWithFintelTemplates } = useAttributes();
  const {
    inputValues,
    setInputValues,
    autocompleteInputValues,
    setAutocompleteInputValues,
    cacheEntities,
    setCacheEntities,
    searchScope,
    setSearchScope,
    entities,
    searchEntities,
  } = state;

  const filterOperator = filter?.operator ?? '';
  const filterValues = filter?.values ?? [];
  const isOperatorRequiringValue = !NO_VALUES_FILTER_OPERATORS.includes(filterOperator);
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const filterLabel = filterKey ? t_i18n(filterDefinition?.label ?? filterKey) : '';
  const finalFilterDefinition = useFilterDefinition(filterKey, entityTypes, subKey);

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

  const buildAutocompleteFilter = (fKey: string, fLabel?: string, fSubKey?: string, isDisabled = false): ReactNode => {
    const getEntitiesOptions = getOptionsFromEntities(entities, searchScope, fKey);
    const optionsValues = fSubKey ? (filterValues.find((f) => f.key === fSubKey)?.values ?? []) : filterValues;

    const isIdFilterDefinition = (
      fDefinition?: FilterDefinition,
      currentSubKey?: string,
    ) => {
      if (!fDefinition) return false;
      return fDefinition.type === 'id'
        || (fDefinition.filterKey === 'regardingOf' && currentSubKey === 'id');
    };

    const completedTypesWithFintelTemplates = typesWithFintelTemplates.concat(['Container', 'Stix-Domain-Object', 'Stix-Core-Object']);
    const shouldAddSelfIdInFintelTemplates = host?.kind === 'fintelTemplate'
      && (filterDefinition?.elementsForFilterValuesSearch ?? []).every((type) => completedTypesWithFintelTemplates.includes(type));
    const shouldAddSelfIdInCustomViews = host?.kind === 'custom-view';
    const shouldAddSelfId = isIdFilterDefinition(filterDefinition, fSubKey)
      && (shouldAddSelfIdInFintelTemplates || shouldAddSelfIdInCustomViews);

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
        if (fSubKey) {
          const childFilters = (filter?.values ?? []).filter((val) => val.key === fSubKey) as Filter[];
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

      const actualFilterValues: FilterValue[] = fSubKey
        ? filterValues.filter((filterValue) => filterValue && filterValue.key === fSubKey).at(0)?.values ?? []
        : filterValues;

      const added = newValues.filter((v) => !actualFilterValues.includes(v));
      const removed = actualFilterValues.filter((v: FilterValue) => !newValues.includes(v));

      if (added.length === 1) {
        const value = added[0];
        const disabledOption = isDisabled && actualFilterValues.length === 1 && actualFilterValues.includes(value);
        if (!disabledOption) {
          handleChange(true, value, fSubKey);
        }
      } else if (removed.length === 1) {
        const value = removed[0];
        const disabledOption = isDisabled && actualFilterValues.length === 1;
        if (!disabledOption) {
          handleChange(false, value, fSubKey);
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
            searchEntities(fKey, cacheEntities, setCacheEntities, syntheticEvent, !!fSubKey);
          }
        }}
        onChange={handleAutocompleteChange}
        disableCloseOnSelect
        isOptionEqualToValue={(option, val) => option.value === val.value}
        sx={{
          '& .MuiAutocomplete-tag': {
            maxWidth: 200,
          },
          '& .MuiAutocomplete-tag .MuiChip-label': {
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          },
        }}
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
                !!fSubKey,
              );
            }}
          />
        )}
        renderOption={(props, option) => {
          const actualFilterValues = fSubKey ? filterValues.filter((fVal) => fVal && fVal.key === fSubKey).at(0)?.values ?? [] : filterValues;
          const checked = actualFilterValues.includes(option.value);
          const disabledOptions = isDisabled && checked && actualFilterValues.length === 1;

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
                {/* NOT `presentational`, deliberately — see fds-migration/MIGRATION-DECISIONS.md#filter-value-checkbox-role */}
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

  const getSpecificFilter = (fDefinition?: FilterDefinition, fSubKey?: string, isDisabled = false): ReactNode => {
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

  const isStixFiltering = entityTypes?.includes('Stix-Filtering');
  const availableOperators = getAvailableOperatorForFilter(filterDefinition, subKey, { isStixFiltering });
  const accessibleOperatorLabel = operatorLabel ?? t_i18n('Operator');

  const valueElement = (
    <>
      {isOperatorRequiringValue && isSpecificFilter(finalFilterDefinition) && (
        <>{getSpecificFilter(finalFilterDefinition, subKey, disabled)}</>
      )}
      {isOperatorRequiringValue && !isSpecificFilter(finalFilterDefinition) && (
        <>{buildAutocompleteFilter(subKey ?? filterKey, finalFilterDefinition?.label ?? t_i18n(filterKey), subKey, disabled)}</>
      )}
    </>
  );

  const operatorElement = availableOperators.length > 0 && (
    <Select
      value={filterOperator}
      onValueChange={(value) => handleChangeOperator(value, finalFilterDefinition)}
      disabled={disabled}
    >
      {/* The MUI version pointed labelId at a label that does not exist, so
          the trigger had no accessible name at all. Named here. */}
      <SelectTrigger id={operatorTriggerId} aria-label={accessibleOperatorLabel} style={operatorStyle}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={accessibleOperatorLabel}>
        {availableOperators.map((value) => (
          <SelectItem key={value} value={value}>
            {t_i18n(OperatorKeyValues[value])}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );

  return (
    <>
      {dataTestIds?.operator
        ? <div data-testid={dataTestIds.operator}>{operatorElement}</div>
        : operatorElement}
      {dataTestIds?.value
        ? <div data-testid={dataTestIds.value}>{valueElement}</div>
        : valueElement}
    </>
  );
};

export interface FilterRowProps {
  filter: Filter;
  helpers: handleFilterHelpers;
  availableFilterKeys: string[];
  entityTypes?: string[];
  filtersRepresentativesMap?: Map<string, FilterRepresentative>;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
  host?: WidgetHost;
}

/**
 * One condition of a (nested) filter group, displayed as a single row:
 * [filter name] [condition] [value] [⋮] [✕]
 */
const FilterRow: FunctionComponent<FilterRowProps> = ({
  filter,
  helpers,
  availableFilterKeys,
  entityTypes = ['Stix-Core-Object'],
  filtersRepresentativesMap = new Map(),
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const [menuOpen, setMenuOpen] = useState(false);
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);

  const state = useFilterEditorState({
    filter,
    entityTypes,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    searchContext,
  });

  const keyOptions = availableFilterKeys
    .map((key) => ({ value: key, label: t_i18n(getFilterDefinitionFromFilterKeysMap(key, filterKeysMap)?.label ?? key) }))
    .sort((a, b) => a.label.localeCompare(b.label));

  const handleChangeKey = (newKey: string) => {
    if (newKey === filter.key) return;
    const newDefinition = getFilterDefinitionFromFilterKeysMap(newKey, filterKeysMap);
    helpers.handleRemoveFilterById(filter.id ?? '');
    helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(newKey, newDefinition, undefined, filter.mode));
  };

  const handleSwitchLocalMode = () => {
    helpers.handleSwitchLocalMode(filter);
    setMenuOpen(false);
  };

  const localMode = (filter.mode ?? 'or').toUpperCase();
  const otherLocalMode = localMode === 'OR' ? 'AND' : 'OR';

  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, width: '100%' }}>
      <div data-testid="filter-row-key-select">
        <Select value={filter.key} onValueChange={handleChangeKey}>
          <SelectTrigger id={`filter-row-key-${filter.id}`} aria-label={t_i18n('Filter name')} style={{ minWidth: 180 }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Filter name')}>
            {keyOptions.map((option) => (
              <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <FilterOperatorAndValue
        filter={filter}
        filterKey={filter.key}
        helpers={helpers}
        state={state}
        filtersRepresentativesMap={filtersRepresentativesMap}
        entityTypes={entityTypes}
        availableRelationFilterTypes={availableRelationFilterTypes}
        host={host}
        operatorLabel={t_i18n('Condition')}
        operatorTriggerId={`filter-row-operator-${filter.id}`}
        operatorStyle={{ minWidth: 160 }}
        dataTestIds={{ operator: 'filter-row-operator-select', value: 'filter-row-value' }}
      />
      <Menu open={menuOpen} onOpenChange={setMenuOpen}>
        <MenuTrigger asChild>
          <IconButton
            priority="tertiary"
            data-testid="filter-row-menu-button"
            aria-label={t_i18n('Options')}
            icon={<MoreVert fontSize="small" />}
          />
        </MenuTrigger>
        {/* portalled={false}: the group panel wraps its rows in a ClickAwayListener, and a portalled
            menu would be seen as a click away, closing the panel on every interaction. */}
        <MenuContent portalled={false}>
          <MenuItem onSelect={handleSwitchLocalMode} data-testid="filter-row-switch-local-mode">
            {t_i18n('Switch to')} {t_i18n(otherLocalMode)}
          </MenuItem>
        </MenuContent>
      </Menu>
      <IconButton
        priority="tertiary"
        onClick={() => helpers.handleRemoveFilterById(filter.id ?? '')}
        data-testid="filter-row-remove-button"
        aria-label={t_i18n('Delete')}
        icon={<CloseOutlined fontSize="small" />}
      />
    </div>
  );
};

export default FilterRow;
