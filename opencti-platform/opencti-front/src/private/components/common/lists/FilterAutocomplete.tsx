import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import TextField from '@mui/material/TextField';
import Autocomplete from '@mui/material/Autocomplete';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import { Theme } from '../../../../components/Theme';
import SearchScopeElement from './SearchScopeElement';
import { onlyGroupOrganization } from '../../../../utils/filters/filtersUtils';
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

interface OptionValue extends Option {
  type: string
  group?: string
}

interface FilterAutocompleteProps {
  filterKey: string
  defaultHandleAddFilter: HandleAddFilter
  inputValues: Record<string, string | Date>
  setInputValues: Dispatch<Record<string, string | Date>>
  availableEntityTypes?: string[]
  availableRelationshipTypes?: string[]
  allEntityTypes?: boolean
  openOnFocus?: boolean
}

const FilterAutocomplete: FunctionComponent<FilterAutocompleteProps> = ({
  filterKey,
  defaultHandleAddFilter,
  inputValues,
  setInputValues,
  availableEntityTypes,
  availableRelationshipTypes,
  allEntityTypes,
  openOnFocus,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [searchScope, setSearchScope] = useState<Record<string, string[]>>({});

  const [entities, searchEntities] = useSearchEntities({
    searchScope,
    setInputValues,
    availableEntityTypes,
    availableRelationshipTypes,
    allEntityTypes,
  }) as [Record<string, OptionValue[]>, (filterKey: string, event: SyntheticEvent) => Record<string, OptionValue[]>]; // change when useSearchEntities will be in TS

  const isStixObjectTypes = ['elementId', 'fromId', 'toId', 'objectContains'].includes(filterKey);

  const handleChange = (event: SyntheticEvent, value: OptionValue | null) => {
    if (value) {
      const group = !onlyGroupOrganization.includes(filterKey)
        ? value.group
        : undefined;
      const filterAdd = `${filterKey}${group ? `_${group}` : ''}`;
      defaultHandleAddFilter(filterAdd, value.value, value.label, event);
    }
  };

  const renderSearchScopeSelection = (key: string) => (
    <SearchScopeElement
      name={key}
      searchScope={searchScope}
      setSearchScope={setSearchScope}
    />
  );

  let options: OptionValue[] = [];
  if (isStixObjectTypes) {
    if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
      options = (entities[filterKey] || [])
        .filter((n) => searchScope[filterKey].includes(n.type))
        .sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
    } else {
      options = (entities[filterKey] || []).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
    }
  } else if (entities[filterKey]) {
    options = entities[filterKey];
  }

  return (
    <Autocomplete
      key={filterKey}
      selectOnFocus={true}
      openOnFocus={openOnFocus}
      autoSelect={false}
      autoHighlight={true}
      getOptionLabel={(option) => (option.label ?? '')}
      noOptionsText={t('No available options')}
      options={options}
      onInputChange={(event) => searchEntities(filterKey, event)}
      inputValue={inputValues[filterKey] as string || ''}
      onChange={(event: SyntheticEvent, value: OptionValue | null) => handleChange(event, value)}
      groupBy={
        isStixObjectTypes
          ? (option) => option.type
          : (option) => t(option.group ? option.group : `filter_${filterKey}`)
      }
      isOptionEqualToValue={(option, value) => option.value === value.value}
      renderInput={(params) => (
        <TextField
          {...params}
          label={t(`filter_${filterKey}`)}
          variant="outlined"
          size="small"
          fullWidth={true}
          onFocus={(event) => searchEntities(filterKey, event)}
          InputProps={{
            ...params.InputProps,
            endAdornment: isStixObjectTypes
              ? renderSearchScopeSelection(filterKey)
              : params.InputProps.endAdornment,
          }}
        />
      )}
      renderOption={(props, option) => (
        <li {...props}>
          <div
            className={classes.icon}
            style={{ color: option.color }}
          >
            <ItemIcon type={option.type} />
          </div>
          <div className={classes.text}>{option.label}</div>
        </li>
      )}
    />
  );
};

export default FilterAutocomplete;
