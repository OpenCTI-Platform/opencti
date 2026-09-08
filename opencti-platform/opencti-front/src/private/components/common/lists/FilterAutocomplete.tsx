import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import { Combobox, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxLabel, ComboboxTrigger } from '@filigran/design-system';
import { useTheme } from '@mui/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import type { Theme } from '../../../../components/Theme';
import SearchScopeElement from './SearchScopeElement';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

export interface FilterOption {
  id?: string;
  value: string | null;
  label: string;
  color?: string;
  type?: string;
  standard_id?: string;
}

export interface FilterOptionValue extends FilterOption {
  type: string;
  parentTypes?: string[];
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
  filterLabel: string;
  disabled?: boolean;
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
    filterLabel,
    disabled,
  } = props;
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
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
    Record<string, FilterOptionValue[]>,
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
    ) => Record<string, FilterOptionValue[]>,
  ]; // change when useSearchEntities will be in TS
  const isStixObjectTypes = [
    'fromId',
    'toId',
    'objects',
    'targets',
    'indicates',
    'contextEntityId',
  ].includes(filterKey);
  const handleChange = (event: SyntheticEvent | null, value: FilterOptionValue | null) => {
    if (value && event) {
      if (
        (event as unknown as MouseEvent).altKey
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
  let options: FilterOptionValue[] = [];
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
    <Combobox<FilterOptionValue>
      key={filterKey}
      disabled={disabled}
      selectOnFocus
      openOnFocus={openOnFocus}
      getOptionLabel={(option) => option.label ?? ''}
      options={options}
      inputValue={input}
      onInputChange={(_, meta) => searchEntities(filterKey, cacheEntities, setCacheEntities, meta.event as SyntheticEvent)}
      value={null}
      onValueChange={(val, meta) => handleChange(meta.event, val as FilterOptionValue | null)}
      groupBy={
        isStixObjectTypes
          ? (option) => option.type
          : (option) => (option.group ? t_i18n(option.group) : filterLabel)
      }
      isOptionEqualToValue={(a, b) => a.value === b.value}
      renderOption={(option) => (
        <>
          <div style={{
            paddingTop: 4,
            display: 'inline-block',
            color: theme.palette.primary.main,
          }}
          >
            <ItemIcon type={option.type} color={option.color} />
          </div>
          <div style={{
            display: 'inline-block',
            flexGrow: 1,
            marginLeft: 10,
          }}
          >{option.label}
          </div>
        </>
      )}
    >
      <ComboboxLabel>{filterLabel}</ComboboxLabel>
      <ComboboxField>
        <ComboboxInput
          onFocus={(event) => searchEntities(filterKey, cacheEntities, setCacheEntities, event)}
        />
        <ComboboxControls>
          {isStixObjectTypes && renderSearchScopeSelection(filterKey)}
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent
        emptyMessage={t_i18n('No available options')}
        listAriaLabel={filterLabel}
      />
    </Combobox>
  );
};

export default FilterAutocomplete;
