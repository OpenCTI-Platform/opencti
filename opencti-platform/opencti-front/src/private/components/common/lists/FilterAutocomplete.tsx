import React, {
  Dispatch,
  FunctionComponent,
  SyntheticEvent,
  useState,
} from 'react';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import { Theme } from '../../../../components/Theme';
import SearchScopeElement from './SearchScopeElement';
import {
  EqFilters,
  onlyGroupOrganization,
} from '../../../../utils/filters/filtersUtils';
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
  type: string;
  parentTypes: string[];
  group?: string;
}

interface FilterAutocompleteProps {
  filterKey: string;
  searchContext: { entityTypes: string[] };
  defaultHandleAddFilter: HandleAddFilter;
  inputValues: Record<string, string | Date>;
  setInputValues: Dispatch<Record<string, string | Date>>;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  allEntityTypes?: boolean;
  openOnFocus?: boolean;
}

const FilterAutocomplete: FunctionComponent<FilterAutocompleteProps> = ({
  filterKey,
  searchContext,
  defaultHandleAddFilter,
  inputValues,
  setInputValues,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  allEntityTypes,
  openOnFocus,
}) => {
  const { t } = useFormatter();
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
    allEntityTypes,
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
      event: SyntheticEvent
    ) => Record<string, OptionValue[]>,
  ]; // change when useSearchEntities will be in TS
  const isStixObjectTypes = [
    'elementId',
    'fromId',
    'toId',
    'objectContains',
    'targets',
    'elementId',
    'indicates',
  ].includes(filterKey);
  const handleChange = (event: SyntheticEvent, value: OptionValue | null) => {
    if (value) {
      if (
        EqFilters.includes(filterKey)
        && (event as unknown as MouseEvent).altKey
        && event.type === 'click'
      ) {
        const filterAdd = `${filterKey}_not_eq`;
        defaultHandleAddFilter(filterAdd, value.value, value.label, event);
      } else {
        const group = !onlyGroupOrganization.includes(filterKey)
          ? value.group
          : undefined;
        const filterAdd = `${filterKey}${group ? `_${group}` : ''}`;
        defaultHandleAddFilter(filterAdd, value.value, value.label, event);
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
  return (
    <MUIAutocomplete
      key={filterKey}
      selectOnFocus={true}
      openOnFocus={openOnFocus}
      autoSelect={false}
      autoHighlight={true}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t('No available options')}
      options={options}
      onInputChange={(event) => searchEntities(
        filterKey,
        cacheEntities,
        setCacheEntities,
        event,
      )
      }
      inputValue={(inputValues[filterKey] as string) || ''}
      onChange={handleChange}
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
          onFocus={(event) => searchEntities(
            filterKey,
            cacheEntities,
            setCacheEntities,
            event,
          )
          }
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
          <div className={classes.icon}>
            <ItemIcon type={option.type} color={option.color} />
          </div>
          <div className={classes.text}>{option.label}</div>
        </li>
      )}
    />
  );
};

export default FilterAutocomplete;
