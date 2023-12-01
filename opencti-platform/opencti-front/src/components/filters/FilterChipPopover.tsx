import React, { FunctionComponent, ReactNode, useState } from 'react';
import Popover from '@mui/material/Popover';
import MUIAutocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import Checkbox from '@mui/material/Checkbox';
import FilterDate from '@components/common/lists/FilterDate';
import { MenuItem, Select } from '@mui/material';
import { SelectChangeEvent } from '@mui/material/Select';
import { dateFilters, Filter, getAvailableOperatorForFilter, integerFilters } from '../../utils/filters/filtersUtils';
import { useFormatter } from '../i18n';
import ItemIcon from '../ItemIcon';
import { getOptions, getUseSearch } from '../../utils/filters/SearchEntitiesUtil';
import { UseLocalStorageHelpers } from '../../utils/hooks/useLocalStorage';

interface FilterChipMenuProps {
  handleClose: () => void;
  open: boolean;
  params: FilterChipsParameter;
  filters: Filter[];
  helpers?: UseLocalStorageHelpers
}

export interface FilterChipsParameter {
  filterId?: string;
  anchorEl?: HTMLElement;
}

const OperatorKeyValues: {
  [key: string]: string
} = {
  eq: 'Equals',
  not_eq: 'Not equals',
  nil: 'Empty',
  not_nil: 'Not empty',
  gt: 'Greater than',
  gte: 'Greater than/ Equals',
  lt: 'Lower than',
  lte: 'Lower than/ Equals',
};

interface BasicNumberInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: UseLocalStorageHelpers;
  filterValues: string[];
}
const BasicNumberInput: FunctionComponent<BasicNumberInputProps> = ({ filter, filterKey, helpers, filterValues }) => {
  const { t } = useFormatter();
  return <TextField
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
        helpers?.handleAddSingleValueFilter(filter?.id ?? '', (event.target as HTMLInputElement).value);
      }
    }}
    onBlur={(event) => {
      helpers?.handleAddSingleValueFilter(filter?.id ?? '', event.target.value);
    }
    }
  />;
};
export const FilterChipPopover: FunctionComponent<FilterChipMenuProps> = ({
  params,
  handleClose, open,
  filters,
  helpers,
}) => {
  const filter = filters.find((f) => f.id === params.filterId);
  const filterKey = filter?.key ?? '';
  const filterOperator = filter?.operator ?? '';
  const filterValues = filter?.values ?? [];
  const [inputValues, setInputValues] = useState<{
    key: string,
    values: string[],
    operator?: string
  }[]>([]);
  const [cacheEntities, setCacheEntities] = useState<
  Record<string, {
    label: string;
    value: string;
    type: string
  }[]>
  >({});
  const [entities, searchEntities] = getUseSearch();
  const { t } = useFormatter();
  const optionValues: OptionValue[] = getOptions(filterKey, entities);
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
  const handleDateChange = (
    _: string,
    value: string,
  ) => {
    helpers?.handleAddSingleValueFilter(filter?.id ?? '', value);
  };

  const isSpecificFilter = (fKey: string) => {
    return dateFilters.includes(fKey) || integerFilters.includes(fKey);
  };

  const BasicFilterDate = () => <FilterDate
    defaultHandleAddFilter={handleDateChange}
    filterKey={filterKey}
    operator={filterOperator}
    inputValues={inputValues}
    setInputValues={setInputValues}
  />;
  const getSpecificFilter = (fKey: string): ReactNode => {
    if (dateFilters.includes(fKey)) {
      return <BasicFilterDate/>;
    }
    if (integerFilters.includes(fKey)) {
      return <BasicNumberInput filter={filter} filterKey={filterKey} filterValues={filterValues} helpers={helpers}/>;
    }
    return null;
  };

  return <Popover
    open={open}
    anchorEl={params.anchorEl}
    onClose={handleClose}
    anchorOrigin={{
      vertical: 'bottom',
      horizontal: 'left',
    }}
  >
    <div
      style={{
        width: '250px',
        padding: '8px',
      }}
    >
      <Select
        labelId="change-operator-select-label"
        id="change-operator-select"
        value={filterOperator}
        label="Operator"
        sx={{ marginBottom: '12px' }}
        onChange={handleChangeOperator}
      >
        {
          getAvailableOperatorForFilter(filterKey).map((value) => <MenuItem key={value}
                                                                            value={value}>{t(OperatorKeyValues[value])}</MenuItem>)
        }
      </Select>
      {
        isSpecificFilter(filterKey)
          ? <>{getSpecificFilter(filterKey)}</>
          : <>
            {(!['not_nil', 'nil'].includes(filterOperator))
              && <MUIAutocomplete
                disableCloseOnSelect
                key={filterKey}
                selectOnFocus={true}
                autoSelect={false}
                autoHighlight={true}
                getOptionLabel={(option) => option.label ?? ''}
                noOptionsText={t('No available options')}
                options={optionValues}
                onInputChange={(event) => searchEntities(
                  filterKey,
                  cacheEntities,
                  setCacheEntities,
                  event,
                )}
                renderInput={(paramsInput) => (
                  <TextField
                    {...paramsInput}
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
                    )}
                  />
                )}
                renderOption={(props, option) => {
                  const checked = filterValues.includes(option.value);
                  return <li {...props}
                              onKeyDown={ (e) => {
                                if (e.key === 'Enter') {
                                  e.stopPropagation();
                                }
                              }}
                             onClick={() => handleChange(!checked, option.value)}>
                    <Checkbox
                      checked={checked}
                    />
                    <ItemIcon type={option.type} color={option.color}/>
                    <span style={{ padding: '0 4px' }}>{option.label}</span>
                  </li>;
                }}
              />
            }
          </>
      }
    </div>
  </Popover>;
};
