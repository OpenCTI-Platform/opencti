import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
// fds:keep-mui Combobox has no endAdornment slot for the search-scope selector (gap #155) — see fds-migration/LIBRARY-FEEDBACK.md
import { Autocomplete, AutocompleteChangeReason, AutocompleteInputChangeReason } from '@mui/material';
import { Checkbox, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
// fds:keep-mui paired with the Autocomplete above (renderInput), converts with it once gap #155 lands
import TextField from '@mui/material/TextField';
import { FunctionComponent, SyntheticEvent } from 'react';
import { Filter, FilterValue, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { getSelectedOptions, isStixObjectTypes, SELF_ID, SELF_ID_VALUE, useFilterDefinition } from '../../../utils/filters/filtersUtils';
import { getOptionsFromEntities } from '../../../utils/filters/SearchEntitiesUtil';
import useAttributes from '../../../utils/hooks/useAttributes';
import { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { WidgetHost } from '../../../utils/widget/widget';
import { useFormatter } from '../../i18n';
import ItemIcon from '../../ItemIcon';
import { FilterRepresentative } from '../FiltersModel';
import { FilterEditorState } from './useFilterEditorState';

const AUTOCOMPLETE_KEY_ACTIONS: { [k: string]: AutocompleteChangeReason | AutocompleteInputChangeReason } = {
  SELECT_OPTION: 'selectOption',
  REMOVE_OPTION: 'removeOption',
  CLEAR: 'clear',
  INPUT: 'input',
  RESET: 'reset',
};

export interface FilterEntityAutocompleteProps {
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
  /** Fallback group/input label, used when an option carries no group of its own. */
  label?: string;
}

/**
 * Default value editor of a filter: a multi-select over the entities matching the filter
 * definition, searched server-side through the shared editor state.
 *
 * Split out of FilterValueInput because it is the one value widget that is not a plain
 * controlled input: it owns the entity search, the search-scope adornment and the whole
 * `fds:keep-mui` debt of the filters area (gap #155). FilterValueInput falls back to it for
 * every filter type that has no dedicated widget.
 */
const FilterEntityAutocomplete: FunctionComponent<FilterEntityAutocompleteProps> = ({
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
  label,
}) => {
  const { t_i18n } = useFormatter();
  const { typesWithFintelTemplates } = useAttributes();
  const {
    autocompleteInputValues,
    setAutocompleteInputValues,
    cacheEntities,
    setCacheEntities,
    searchScope,
    setSearchScope,
    entities,
    searchEntities,
  } = state;

  const filterValues = filter?.values ?? [];
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  // A subfilter searches under its own key (e.g. 'relationship_type'), the filter under its own.
  const searchKey = subKey ?? filterKey;

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

  const renderSearchScopeSelection = (key: string) => (
    <SearchScopeElement
      name={key}
      searchScope={searchScope}
      setSearchScope={setSearchScope}
      availableRelationFilterTypes={availableRelationFilterTypes}
    />
  );

  const getEntitiesOptions = getOptionsFromEntities(entities, searchScope, searchKey);
  const optionsValues = subKey ? (filterValues.find((f) => f.key === subKey)?.values ?? []) : filterValues;

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
  const shouldAddSelfId = isIdFilterDefinition(filterDefinition, subKey)
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

  const groupByEntities = (option: FilterOptionValue, fLabel?: string) => {
    return t_i18n(option?.group ? option?.group : fLabel);
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
      setAutocompleteInputValues((prev) => ({ ...prev, [searchKey]: '' }));
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
      key={searchKey}
      size="small"
      value={selectedOptions}
      inputValue={autocompleteInputValues[searchKey] || ''}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t_i18n('No available options')}
      options={options}
      groupBy={(option) => groupByEntities(option, label)}
      onInputChange={(event, newInputValue, reason: AutocompleteInputChangeReason) => {
        if (reason === AUTOCOMPLETE_KEY_ACTIONS.INPUT || reason === AUTOCOMPLETE_KEY_ACTIONS.CLEAR) {
          setAutocompleteInputValues((prev) => ({ ...prev, [searchKey]: newInputValue }));
        }
        if (event && reason === AUTOCOMPLETE_KEY_ACTIONS.INPUT) {
          const syntheticEvent = { target: { value: newInputValue } } as unknown as SyntheticEvent;
          searchEntities(searchKey, cacheEntities, setCacheEntities, syntheticEvent, !!subKey);
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
              endAdornment: isStixObjectTypes.includes(searchKey)
                ? renderSearchScopeSelection(searchKey)
                : paramsInput.InputProps.endAdornment,
            },
          }}
          label={t_i18n(label)}
          variant="outlined"
          size="small"
          fullWidth={true}
          autoFocus={true}
          onFocus={(event) => {
            searchEntities(
              searchKey,
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
          <Tooltip key={key || option.value}>
            <TooltipTrigger asChild>
              <li
                {...otherProps}
                aria-disabled={disabledOptions}
                aria-label={option.label}
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
                {/* NOT `presentational`, deliberately — see fds-migration/MIGRATION-DECISIONS.md#filter-value-checkbox-role. */}
                <Checkbox checked={checked} disabled={disabledOptions} aria-label={option.label} />
                <ItemIcon type={option.type} color={option.color} />
                <span>
                  {option.label}
                </span>
              </li>
            </TooltipTrigger>
            <TooltipContent>{option.label}</TooltipContent>
          </Tooltip>
        );
      }}
    />
  );
};

export default FilterEntityAutocomplete;
