import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { useTheme } from '@mui/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import type { Theme } from '../../../../components/Theme';
import SearchScopeElement from './SearchScopeElement';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { useDashboardVariables } from '../../workspaces/dashboards/variables/DashboardVariablesContext';
import { useFilterVariableSelection } from '../../widgets/FilterVariableSelectionContext';
import { getFilterDefinitionFromFilterKeysMap, useBuildFilterKeysMapFromEntityType } from '../../../../utils/filters/filtersUtils';

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
  const handleChange = (event: SyntheticEvent, value: FilterOptionValue | null) => {
    if (value) {
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

  // ── Dashboard variable injection ──────────────────────────────────────────
  // Variables are injected as options only inside the widget config dialog
  // (when FilterVariableSelectionProvider is active).
  const { variables: dashboardVariables } = useDashboardVariables();
  const { onVariableSelected } = useFilterVariableSelection();
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(searchContext.entityTypes);
  const filterDef = getFilterDefinitionFromFilterKeysMap(filterKey, filterKeysMap);
  // Map from FilterDefinition.type to DashboardFilterKeyType enum
  const resolveVariableType = (defType: string | undefined, elementsForFilterValuesSearch?: readonly string[]): string | null => {
    if (defType === 'id') {
      // 'id' filters can target very different kinds of objects; use the declared
      // target entity types to route to the matching variable type instead of
      // always falling back to a generic entity selector.
      const elements = elementsForFilterValuesSearch ?? [];
      if (elements.includes('Label')) return 'label';
      if (elements.includes('Marking-Definition')) return 'marking';
      if (elements.includes('User')) return 'user';
      if (elements.includes('Group')) return 'group';
      if (elements.includes('StatusTemplate')) return 'status';
      return 'entity_ref';
    }
    switch (defType) {
      case 'vocabulary':
      case 'enum': return 'vocabulary';
      case 'boolean': return 'boolean';
      case 'integer':
      case 'float': return 'numeric';
      case 'string':
      case 'text': return 'text';
      case 'date': return 'date';
      default: return null;
    }
  };
  const matchedVarType = resolveVariableType(filterDef?.type, filterDef?.elementsForFilterValuesSearch);
  const variableOptions: FilterOptionValue[] = (onVariableSelected && matchedVarType)
    ? dashboardVariables
      .filter((v) => v.filterKeyType === matchedVarType)
      .map((v) => ({
        value: `__var__:${v.id}:${encodeURIComponent(v.name)}:${v.filterKeyType}`,
        label: v.name,
        type: 'Variable',
        group: t_i18n('Variables'),
      }))
    : [];
  const allOptions = variableOptions.length > 0 ? [...variableOptions, ...options] : options;
  // ─────────────────────────────────────────────────────────────────────────

  const input = inputValues.filter((f) => f.key === filterKey)?.[0]?.values?.[0] ?? '';

  const handleChangeWithVariable = (event: SyntheticEvent, value: FilterOptionValue | null) => {
    if (value?.value?.startsWith('__var__:') && onVariableSelected) {
      const parts = value.value.split(':');
      const variableId = parts[1];
      const variableName = decodeURIComponent(parts[2]);
      const fkt = parts[3];
      onVariableSelected(variableId, variableName, fkt);
      return;
    }
    handleChange(event, value);
  };

  return (
    <MUIAutocomplete
      key={filterKey}
      disabled={disabled}
      selectOnFocus={true}
      openOnFocus={openOnFocus}
      autoSelect={false}
      autoHighlight={true}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t_i18n('No available options')}
      options={allOptions}
      onInputChange={(event) => searchEntities(filterKey, cacheEntities, setCacheEntities, event)}
      inputValue={input}
      onChange={handleChangeWithVariable}
      groupBy={
        isStixObjectTypes
          ? (option) => (option.group ? t_i18n(option.group) : option.type)
          : (option) => (option.group ? t_i18n(option.group) : filterLabel)
      }
      isOptionEqualToValue={(option, value) => option.value === value.value}
      renderInput={(params) => (
        <TextField
          {...params}
          label={filterLabel}
          variant="outlined"
          size="small"
          fullWidth={true}
          onFocus={(event) => searchEntities(filterKey, cacheEntities, setCacheEntities, event)
          }
          slotProps={{
            input: {
              ...params.InputProps,
              endAdornment: isStixObjectTypes
                ? renderSearchScopeSelection(filterKey)
                : params.InputProps.endAdornment,
            },
          }}
        />
      )}
      renderOption={(propsOption, option) => (
        <li {...propsOption}>
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
        </li>
      )}
    />
  );
};

export default FilterAutocomplete;
