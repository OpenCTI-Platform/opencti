import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import type { Theme } from '../../../../components/Theme';
import SearchScopeElement from './SearchScopeElement';
import { EqFilters } from '../../../../utils/filters/filtersUtils';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { Option } from '../form/ReferenceField';

const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

export interface OptionValue extends Option {
  type: string;
  parentTypes: string[];
  group?: string;
}

export interface FilterAutocompleteInputValue {
  key: string;
  values: string[];
  operator?: string;
}

interface FilterAutocompleteProps {
  filterKey: string;
  searchContext: { entityTypes: string[]; elementId?: string[] };
  defaultHandleAddFilter: HandleAddFilter;
  inputValues: { key: string; values: string[]; operator?: string }[];
  setInputValues: (value: FilterAutocompleteInputValue[]) => void;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  openOnFocus?: boolean;
}

const FilterAutocomplete: FunctionComponent<FilterAutocompleteProps> = (props) => {
  const {
    filterKey,
    searchContext,
    defaultHandleAddFilter,
    inputValues,
    setInputValues,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    openOnFocus,
  } = props;
  const { t_i18n } = useFormatter();
  const classes = useStyles();
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
  const [cacheEntities, setCacheEntities] = useState<
  Record<string, { label: string; value: string; type: string }[]>
  >({});
  const [entities, searchEntities] = useSearchEntities({
    searchContext,
    searchScope,
    setInputValues,
    availableEntityTypes,
    availableRelationshipTypes,
  }) as [
    Record<string, OptionValue[]>,
    (
      filterKey: string,
      cacheEntities: Record<
      string,
      { label: string; value: string; type: string }[]
      >,
      setCacheEntities: Dispatch<
      Record<string, { label: string; value: string; type: string }[]>
      >,
      event: SyntheticEvent,
    ) => Record<string, OptionValue[]>,
  ]; // change when useSearchEntities will be in TS
  const isStixObjectTypes = [
    'fromId',
    'toId',
    'objects',
    'targets',
    'indicates',
    'contextEntityId',
  ].includes(filterKey);
  const handleChange = (event: SyntheticEvent, value: OptionValue | null) => {
    if (value) {
      if (
        EqFilters.includes(filterKey)
        && (event as unknown as MouseEvent).altKey
        && event.type === 'click'
      ) {
        defaultHandleAddFilter(
          filterKey,
          value.value,
          value.value === null ? 'not_nil' : 'not_eq',
          event,
        );
      } else {
        defaultHandleAddFilter(
          filterKey,
          value.value,
          value.value === null ? 'nil' : undefined,
          event,
        );
      }
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
  let options: OptionValue[] = [];
  if (isStixObjectTypes) {
    if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
      options = (entities[filterKey] || [])
        .filter((n) => searchScope[filterKey].some((s) => (n.parentTypes ?? []).concat(n.type).includes(s)))
        .sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
    } else {
      options = (entities[filterKey] || []).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
    }
  } else if (entities[filterKey]) {
    options = entities[filterKey];
  }
  const input = inputValues.filter((f) => f.key === filterKey)?.[0]?.values?.[0] ?? '';
  return (
    <MUIAutocomplete
      key={filterKey}
      selectOnFocus={true}
      openOnFocus={openOnFocus}
      autoSelect={false}
      autoHighlight={true}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t_i18n('No available options')}
      options={options}
      onInputChange={(event) => searchEntities(filterKey, cacheEntities, setCacheEntities, event)}
      inputValue={input}
      onChange={handleChange}
      groupBy={
        isStixObjectTypes
          ? (option) => option.type
          : (option) => t_i18n(option.group ? option.group : filterKey)
      }
      isOptionEqualToValue={(option, value) => option.value === value.value}
      renderInput={(params) => (
        <TextField
          {...params}
          label={t_i18n(filterKey)}
          variant="outlined"
          size="small"
          fullWidth={true}
          onFocus={(event) => searchEntities(filterKey, cacheEntities, setCacheEntities, event)
          }
          InputProps={{
            ...params.InputProps,
            endAdornment: isStixObjectTypes
              ? renderSearchScopeSelection(filterKey)
              : params.InputProps.endAdornment,
          }}
        />
      )}
      renderOption={(propsOption, option) => (
        <li {...propsOption}>
          <div className={classes.icon}>
            <ItemIcon type={option.type} color={option.color}/>
          </div>
          <div className={classes.text}>{option.label}</div>
        </li>
      )}
    />
  );
};

export default FilterAutocomplete;
