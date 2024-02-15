import React, { FunctionComponent, ReactNode, useState } from 'react';
import Popover from '@mui/material/Popover';
import TextField from '@mui/material/TextField';
import Checkbox from '@mui/material/Checkbox';
import Tooltip from '@mui/material/Tooltip';
import FilterDate from '@components/common/lists/FilterDate';
import { Autocomplete, MenuItem, Select } from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import Chip from '@mui/material/Chip';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import { dateFilters, Filter, getAvailableOperatorForFilter, getSelectedOptions, integerFilters, isStixObjectTypes, textFilters } from '../../utils/filters/filtersUtils';
import { useFormatter } from '../i18n';
import ItemIcon from '../ItemIcon';
import { getOptionsFromEntities, getUseSearch } from '../../utils/filters/SearchEntitiesUtil';
import { handleFilterHelpers } from '../../utils/hooks/useLocalStorage';
import { FilterRepresentative } from './FiltersModel';

interface FilterChipMenuProps {
  handleClose: () => void;
  open: boolean;
  params: FilterChipsParameter;
  filters: Filter[];
  helpers?: handleFilterHelpers;
  availableRelationFilterTypes?: Record<string, string[]>;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
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
};

interface BasicNumberInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  filterValues: string[];
}
const BasicNumberInput: FunctionComponent<BasicNumberInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={t_i18n(filterKey)}
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
}) => {
  const { t_i18n } = useFormatter();
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={t_i18n(filterKey)}
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
  filtersRepresentativesMap,
}) => {
  const filter = filters.find((f) => f.id === params.filterId);
  const filterKey = filter?.key ?? '';
  const filterOperator = filter?.operator ?? '';
  const filterValues = filter?.values ?? [];
  const [inputValues, setInputValues] = useState<
  {
    key: string;
    values: string[];
    operator?: string;
  }[]
  >(filter ? [filter] : []);
  const [cacheEntities, setCacheEntities] = useState<
  Record<
  string,
  {
    label: string;
    value: string;
    type: string;
  }[]
  >
  >({});
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
  const [entities, searchEntities] = getUseSearch(searchScope);
  const { t_i18n } = useFormatter();
  const handleChange = (checked: boolean, value: string, childKey?: string) => {
    if (childKey) { // case 'regardingOf' filter
      const childFilters = filter?.values.filter((val) => val.key === childKey) as Filter[];
      const childFilter = childFilters && childFilters.length > 0 ? childFilters[0] : undefined;
      const alreadySelectedValues = childFilter?.values ?? [];
      let representationToAdd;
      if (checked) {
        representationToAdd = { key: childKey, values: [...alreadySelectedValues, value] }; // the representation to add = the former values + the added value
      } else {
        const cleanedValues = alreadySelectedValues.filter((val) => val !== value);
        representationToAdd = cleanedValues.length > 0 ? { key: childKey, values: cleanedValues } : undefined; // the representation to add = the former values - the removed value
      }
      helpers?.handleChangeRepresentationFilter(filter?.id ?? '', childFilter, representationToAdd);
    } else if (checked) {
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

  const isSpecificFilter = (fKey: string) => {
    return (
      dateFilters.includes(fKey)
      || integerFilters.includes(fKey)
      || textFilters.includes(fKey)
    );
  };

  const BasicFilterDate = () => (
    <FilterDate
      defaultHandleAddFilter={handleDateChange}
      filterKey={filterKey}
      operator={filterOperator}
      inputValues={inputValues}
      setInputValues={setInputValues}
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

  const buildAutocompleteFilter = (fKey: string, subKey?: string): ReactNode => {
    const getOptions = getOptionsFromEntities(entities, searchScope, fKey);
    const optionsValues = subKey ? (filterValues.find((f) => f.key === subKey)?.values ?? []) : filterValues;
    const entitiesOptions = getOptions.filter((option) => !optionsValues.includes(option.value));
    const selectedOptions: OptionValue[] = getSelectedOptions(getOptions, optionsValues, filtersRepresentativesMap, t_i18n);

    const groupByEntities = (option: OptionValue) => {
      return t_i18n(option?.group ? option?.group : fKey);
    };
    return (
      <Autocomplete
        multiple
        key={fKey}
        getOptionLabel={(option) => option.label ?? ''}
        noOptionsText={t_i18n('No available options')}
        options={[...selectedOptions, ...entitiesOptions]}
        groupBy={(option) => groupByEntities(option)}
        onInputChange={(event) => searchEntities(fKey, cacheEntities, setCacheEntities, event)}
        renderInput={(paramsInput) => (
          <TextField
            {...paramsInput}
            InputProps={{
              ...paramsInput.InputProps,
              endAdornment: isStixObjectTypes.includes(fKey)
                ? renderSearchScopeSelection(fKey)
                : paramsInput.InputProps.endAdornment,
            }}
            label={t_i18n(subKey ?? fKey)}
            variant="outlined"
            size="small"
            fullWidth={true}
            autoFocus={true}
            onFocus={(event) => searchEntities(
              fKey,
              cacheEntities,
              setCacheEntities,
              event,
            )
            }
          />
        )}
        renderOption={(props, option) => {
          const checked = subKey
            ? filterValues.filter((fVal) => fVal && fVal.key === subKey && fVal.values.includes(option.value)).length > 0
            : filterValues.includes(option.value);
          return (
            <Tooltip title={option.label} key={option.label}>
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
                <Checkbox checked={checked} />
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
  const getSpecificFilter = (fKey: string): ReactNode => {
    if (dateFilters.includes(fKey)) {
      return <BasicFilterDate />;
    }
    if (integerFilters.includes(fKey)) {
      return (
        <BasicNumberInput
          filter={filter}
          filterKey={filterKey}
          filterValues={filterValues}
          helpers={helpers}
        />
      );
    }
    if (textFilters.includes(fKey)) {
      return (
        <BasicTextInput
          filter={filter}
          filterKey={filterKey}
          filterValues={filterValues}
          helpers={helpers}
        />
      );
    }
    return null;
  };

  const displayOperatorAndFilter = (fKey: string, subKey?: string, aliasSubKey?: string) => {
    const availableOperators = getAvailableOperatorForFilter(fKey, subKey);
    // for subkeys, we turn to the behavior of existing filter keys
    // we might use an alias if the subkey does not match the name of the existing key
    const finalFilterKey = subKey ? (aliasSubKey ?? subKey) : fKey;
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
        {noValueOperator && isSpecificFilter(finalFilterKey) && (
          <>{getSpecificFilter(finalFilterKey)}</>
        )}
        {noValueOperator && !isSpecificFilter(finalFilterKey) && (
          <>{buildAutocompleteFilter(finalFilterKey, subKey)}</>
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
      {filterKey === 'regardingOf'
        ? <div
            style={{
              width: 250,
              padding: 8,
            }}
          >
          {displayOperatorAndFilter('regardingOf', 'type', 'relationship_type')}
          <Chip
            style={{
              fontFamily: 'Consolas, monaco, monospace',
              margin: '10px 10px 15px 0',
            }}
            label={t_i18n('WITH')}
          />
          {displayOperatorAndFilter('regardingOf', 'id')}
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
