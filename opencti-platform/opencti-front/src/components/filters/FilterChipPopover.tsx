import React, { Dispatch, FunctionComponent, ReactNode, SyntheticEvent, useState } from 'react';
import Popover from '@mui/material/Popover';
import TextField from '@mui/material/TextField';
import Checkbox from '@mui/material/Checkbox';
import Tooltip from '@mui/material/Tooltip';
import FilterDate from '@components/common/lists/FilterDate';
import { Autocomplete, MenuItem, Radio, Select } from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import Chip from '@mui/material/Chip';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import {
  FilterSearchContext,
  getAvailableOperatorForFilter,
  getSelectedOptions,
  isBasicTextFilter,
  isNumericFilter,
  isStixObjectTypes,
  useFilterDefinition,
} from '../../utils/filters/filtersUtils';
import { useFormatter } from '../i18n';
import ItemIcon from '../ItemIcon';
import { getOptionsFromEntities } from '../../utils/filters/SearchEntitiesUtil';
import { FilterDefinition } from '../../utils/hooks/useAuth';
import { FilterRepresentative } from './FiltersModel';
import useSearchEntities from '../../utils/filters/useSearchEntities';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

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
  noMultiSelect?: boolean;
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
};

interface BasicNumberInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  filterValues: string[];
  label: string;
}

const BasicNumberInput: FunctionComponent<BasicNumberInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
  label,
}) => {
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={label}
      type="number"
      defaultValue={filterValues[0]}
      autoFocus={true}
      onKeyDown={(event) => {
        if (event.key === 'Enter') {
          helpers?.handleAddSingleValueFilter(
            filter?.id ?? '',
            (event.target as HTMLInputElement).value,
          );
        }
      }}
      onBlur={(event) => {
        helpers?.handleAddSingleValueFilter(
          filter?.id ?? '',
          event.target.value,
        );
      }}
    />
  );
};
const BasicTextInput: FunctionComponent<BasicNumberInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
  label,
}) => {
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={label}
      defaultValue={filterValues[0]}
      autoFocus={true}
      onKeyDown={(event) => {
        if (event.key === 'Enter') {
          helpers?.handleAddSingleValueFilter(
            filter?.id ?? '',
            (event.target as HTMLInputElement).value,
          );
        }
      }}
      onBlur={(event) => {
        helpers?.handleAddSingleValueFilter(
          filter?.id ?? '',
          event.target.value,
        );
      }}
    />
  );
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
  noMultiSelect,
}) => {
  const { t_i18n } = useFormatter();
  const filter = filters.find((f) => f.id === params.filterId);
  const filterKey = filter?.key ?? '';
  const filterOperator = filter?.operator ?? '';
  const filterValues = filter?.values ?? [];
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const filterLabel = t_i18n(filterDefinition?.label ?? filterKey);
  const [inputValues, setInputValues] = useState<{
    key: string;
    values: string[];
    operator?: string;
  }[]>(filter ? [filter] : []);
  const [cacheEntities, setCacheEntities] = useState<Record<string, OptionValue[]>>({});
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
  }) as [Record<string, OptionValue[]>, (
    filterKey: string,
    cacheEntities: Record<string, OptionValue[]>,
    setCacheEntities: Dispatch<Record<string, OptionValue[]>>,
    event: SyntheticEvent,
    isSubKey?: boolean,
  ) => Record<string, OptionValue[]>,
  ];
  const handleChange = (checked: boolean, value: string, childKey?: string) => {
    if (childKey) { // case 'regardingOf' filter, noMultiSelect not implemented for this filter type
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
      if (noMultiSelect) {
        filter?.values.map((selected) => { return helpers?.handleRemoveRepresentationFilter(filter?.id ?? '', selected); });
      }
      helpers?.handleAddRepresentationFilter(filter?.id ?? '', value);
    } else {
      helpers?.handleRemoveRepresentationFilter(filter?.id ?? '', value);
    }
  };

  const handleChangeOperator = (event: SelectChangeEvent) => {
    helpers?.handleChangeOperatorFilters(filter?.id ?? '', event.target.value);
  };
  const handleDateChange = (_: string, value: string) => {
    helpers?.handleAddSingleValueFilter(filter?.id ?? '', value);
  };

  const isSpecificFilter = (fDef?: FilterDefinition) => {
    const filterType = fDef?.type;
    return (
      filterType === 'date'
      || isNumericFilter(filterType)
      || isBasicTextFilter(fDef)
    );
  };

  const BasicFilterDate = () => (
    <FilterDate
      defaultHandleAddFilter={handleDateChange}
      filterKey={filterKey}
      operator={filterOperator}
      inputValues={inputValues}
      setInputValues={setInputValues}
      filterLabel={filterLabel}
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

  const buildAutocompleteFilter = (fKey: string, fLabel?: string, subKey?: string): ReactNode => {
    const getOptions = getOptionsFromEntities(entities, searchScope, fKey);
    const optionsValues = subKey ? (filterValues.find((f) => f.key === subKey)?.values ?? []) : filterValues;
    const entitiesOptions = getOptions.filter((option) => !optionsValues.includes(option.value));
    const selectedOptions: OptionValue[] = getSelectedOptions(getOptions, optionsValues, filtersRepresentativesMap, t_i18n);

    const groupByEntities = (option: OptionValue, label?: string) => {
      return t_i18n(option?.group ? option?.group : label);
    };
    return (
      <Autocomplete
        multiple
        key={fKey}
        getOptionLabel={(option) => option.label ?? ''}
        noOptionsText={t_i18n('No available options')}
        options={[...selectedOptions, ...entitiesOptions]}
        groupBy={(option) => groupByEntities(option, fLabel)}
        onInputChange={(event) => searchEntities(fKey, cacheEntities, setCacheEntities, event, !!subKey)}
        renderInput={(paramsInput) => (
          <TextField
            {...paramsInput}
            InputProps={{
              ...paramsInput.InputProps,
              endAdornment: isStixObjectTypes.includes(fKey)
                ? renderSearchScopeSelection(fKey)
                : paramsInput.InputProps.endAdornment,
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
          const checked = subKey
            ? filterValues.filter((fVal) => fVal && fVal.key === subKey && fVal.values.includes(option.value)).length > 0
            : filterValues.includes(option.value);
          return (
            <Tooltip title={option.label} key={option.label} followCursor>
              <li
                {...props}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.stopPropagation();
                  }
                }}
                onClick={() => handleChange(!checked, option.value, subKey)}
                style={{
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  padding: 0,
                  margin: 0,
                }}
              >
                {noMultiSelect
                  ? (
                    <Radio checked={checked} />
                  ) : (
                    <Checkbox checked={checked} />
                  )
                }
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
  const getSpecificFilter = (fDefinition?: FilterDefinition): ReactNode => {
    if (fDefinition?.type === 'date') {
      return <BasicFilterDate />;
    }
    if (isNumericFilter(fDefinition?.type)) {
      return (
        <BasicNumberInput
          filter={filter}
          filterKey={filterKey}
          filterValues={filterValues}
          helpers={helpers}
          label={filterLabel}
        />
      );
    }
    if (isBasicTextFilter(filterDefinition)) {
      return (
        <BasicTextInput
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

  const displayOperatorAndFilter = (fKey: string, subKey?: string) => {
    const availableOperators = getAvailableOperatorForFilter(filterDefinition, subKey);
    const finalFilterDefinition = useFilterDefinition(fKey, entityTypes, subKey);
    return (
      <>
        <Select
          labelId="change-operator-select-label"
          id="change-operator-select"
          value={filterOperator}
          label="Operator"
          fullWidth={true}
          onChange={handleChangeOperator}
          style={{ marginBottom: 15 }}
        >
          {availableOperators.map((value) => (
            <MenuItem key={value} value={value}>
              {t_i18n(OperatorKeyValues[value])}
            </MenuItem>
          ))}
        </Select>
        {noValueOperator && isSpecificFilter(finalFilterDefinition) && (
          <>{getSpecificFilter(finalFilterDefinition)}</>
        )}
        {noValueOperator && !isSpecificFilter(finalFilterDefinition) && (
          <>{buildAutocompleteFilter(subKey ?? fKey, finalFilterDefinition?.label ?? t_i18n(fKey), subKey)}</>
        )}
      </>
    );
  };

  return (
    <Popover
      open={open}
      anchorEl={params.anchorEl}
      onClose={handleClose}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'left',
      }}
      PaperProps={{ elevation: 1, style: { marginTop: 10 } }}
    >
      {filterDefinition?.subFilters && filterDefinition.subFilters.length > 1
        ? <div
            style={{
              width: 250,
              padding: 8,
            }}
          >
          {displayOperatorAndFilter(filterKey, filterDefinition?.subFilters[0].filterKey)}
          <Chip
            style={{
              fontFamily: 'Consolas, monaco, monospace',
              margin: '10px 10px 15px 0',
            }}
            label={t_i18n('WITH')}
          />
          {displayOperatorAndFilter(filterKey, filterDefinition.subFilters[1].filterKey)}
        </div>
        : <div
            style={{
              width: 250,
              padding: 8,
            }}
          >
          {displayOperatorAndFilter(filterKey)}
        </div>
      }
    </Popover>
  );
};
