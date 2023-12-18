import React, { FunctionComponent, ReactNode, useState } from 'react';
import Popover from '@mui/material/Popover';
import MUIAutocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import Checkbox from '@mui/material/Checkbox';
import Tooltip from '@mui/material/Tooltip';
import FilterDate from '@components/common/lists/FilterDate';
import { MenuItem, Select } from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import { dateFilters, Filter, getAvailableOperatorForFilter, integerFilters, isStixObjectTypes, textFilters } from '../../utils/filters/filtersUtils';
import { useFormatter } from '../i18n';
import ItemIcon from '../ItemIcon';
import { getOptionsFromEntities, getUseSearch } from '../../utils/filters/SearchEntitiesUtil';
import { handleFilterHelpers } from '../../utils/hooks/useLocalStorage';

interface FilterChipMenuProps {
  handleClose: () => void;
  open: boolean;
  params: FilterChipsParameter;
  filters: Filter[];
  helpers?: handleFilterHelpers;
  availableRelationFilterTypes?: Record<string, string[]>;
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
  const { t } = useFormatter();
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={t(filterKey)}
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
  const { t } = useFormatter();
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={t(filterKey)}
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
  >([]);
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
  const { t } = useFormatter();
  const optionValues: OptionValue[] = getOptionsFromEntities(entities, searchScope, filterKey);
  const handleChange = (checked: boolean, value: string) => {
    if (checked) {
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

  const noValueOperator = !['not_nil', 'nil'].includes(filterOperator);
  const renderSearchScopeSelection = (key: string) => (
    <SearchScopeElement
      name={key}
      searchScope={searchScope}
      setSearchScope={setSearchScope}
      availableRelationFilterTypes={availableRelationFilterTypes}
    />
  );
  return (
    <Popover
      open={open}
      anchorEl={params.anchorEl}
      onClose={handleClose}
      anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'left',
      }}
      PaperProps={{ style: { marginTop: 10 } }}
    >
      <div
        style={{
          width: 250,
          padding: 8,
        }}
      >
        <Select
          labelId="change-operator-select-label"
          id="change-operator-select"
          value={filterOperator}
          label="Operator"
          fullWidth={true}
          onChange={handleChangeOperator}
          style={{ marginBottom: 15 }}
        >
          {getAvailableOperatorForFilter(filterKey).map((value) => (
            <MenuItem key={value} value={value}>
              {t(OperatorKeyValues[value])}
            </MenuItem>
          ))}
        </Select>
        {noValueOperator && isSpecificFilter(filterKey) && (
          <>{getSpecificFilter(filterKey)}</>
        )}
        {noValueOperator && !isSpecificFilter(filterKey) && (
          <MUIAutocomplete
            disableCloseOnSelect
            key={filterKey}
            selectOnFocus={true}
            autoSelect={false}
            autoHighlight={true}
            getOptionLabel={(option) => option.label ?? ''}
            noOptionsText={t('No available options')}
            options={optionValues}
            groupBy={
              isStixObjectTypes.includes(filterKey)
                ? (option) => option.type
                : (option) => t(option.group ? option.group : filterKey)
            }
            onInputChange={(event) => searchEntities(filterKey, cacheEntities, setCacheEntities, event)
            }
            renderInput={(paramsInput) => (
              <TextField
                {...paramsInput}
                InputProps={{
                  ...paramsInput.InputProps,
                  endAdornment: isStixObjectTypes.includes(filterKey)
                    ? renderSearchScopeSelection(filterKey)
                    : paramsInput.InputProps.endAdornment,
                }}
                label={t(filterKey)}
                variant="outlined"
                size="small"
                fullWidth={true}
                autoFocus={true}
                onFocus={(event) => searchEntities(
                  filterKey,
                  cacheEntities,
                  setCacheEntities,
                  event,
                )
                }
              />
            )}
            renderOption={(props, option) => {
              const checked = filterValues.includes(option.value);
              return (
                <Tooltip title={option.label} key={option.label}>
                  <li
                    {...props}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.stopPropagation();
                      }
                    }}
                    onClick={() => handleChange(!checked, option.value)}
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
        )}
      </div>
    </Popover>
  );
};
