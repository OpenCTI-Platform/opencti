import { IconButton, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import CloseOutlined from '@mui/icons-material/CloseOutlined';
import Box from '@mui/material/Box';
import { FunctionComponent } from 'react';
import { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { FilterSearchContext, getDefaultFilterObject, getFilterDefinitionFromFilterKeysMap, useBuildFilterKeysMapFromEntityType } from '../../../utils/filters/filtersUtils';
import type { WidgetHost } from '../../../utils/widget/widget';
import { useFormatter } from '../../i18n';
import { FilterRepresentative } from '../FiltersModel';
import FilterOperatorSelect from './FilterOperatorSelect';
import FilterRowCompositeValue from './FilterRowCompositeValue';
import FilterValueInput from './FilterValueInput';
import useFilterEditorState from './useFilterEditorState';

export interface FilterRowProps {
  filter: Filter;
  helpers: handleFilterHelpers;
  availableFilterKeys: string[];
  entityTypes?: string[];
  filtersRepresentativesMap?: Map<string, FilterRepresentative>;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
  host?: WidgetHost;
}

/**
 * One condition of a (nested) filter group, displayed as a single row:
 * [filter name] [condition] [value] [✕]
 */
const FilterRow: FunctionComponent<FilterRowProps> = ({
  filter,
  helpers,
  availableFilterKeys,
  entityTypes = ['Stix-Core-Object'],
  filtersRepresentativesMap = new Map(),
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);

  const state = useFilterEditorState({
    filter,
    entityTypes,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    searchContext,
  });

  const keyOptions = availableFilterKeys
    .map((key) => ({ value: key, label: t_i18n(getFilterDefinitionFromFilterKeysMap(key, filterKeysMap)?.label ?? key) }))
    .sort((a, b) => a.label.localeCompare(b.label));

  const handleChangeKey = (newKey: string) => {
    if (newKey === filter.key) return;
    const newDefinition = getFilterDefinitionFromFilterKeysMap(newKey, filterKeysMap);
    helpers.handleChangeFilterKey(filter.id ?? '', getDefaultFilterObject(newKey, newDefinition, undefined, filter.mode));
  };

  // Only this nested-group row lays 'From'/'To' side by side; the filter chip popover keeps them
  // stacked. Computed here, not inside the value editor, so the two callers can't affect each other.
  const isDateRangeValue = getFilterDefinitionFromFilterKeysMap(filter.key, filterKeysMap)?.type === 'date' && filter.operator === 'within';
  // 'regardingOf' / 'dynamicRegardingOf' are composite filters (relationship_type + id/dynamic
  // subfilters): this row lays their subfilters out as extra columns instead of a single value.
  const isCompositeRegardingOf = filter.key === 'regardingOf' || filter.key === 'dynamicRegardingOf';

  const sharedValueProps = {
    filter,
    helpers,
    state,
    filtersRepresentativesMap,
    entityTypes,
    availableRelationFilterTypes,
    host,
  };

  return (
    <Box sx={{ display: 'flex', alignItems: 'stretch', gap: 1, width: '100%' }}>
      <Box data-testid="filter-row-key-select" sx={{ flex: '0 0 22%' }}>
        <Select value={filter.key} onValueChange={handleChangeKey}>
          <SelectTrigger id={`filter-row-key-${filter.id}`} aria-label={t_i18n('Filter name')} style={{ width: '100%' }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Filter name')}>
            {keyOptions.map((option) => (
              <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Box>
      <Box data-testid="filter-row-operator-select" sx={{ flex: '0 0 18%' }}>
        <FilterOperatorSelect
          filter={filter}
          filterKey={filter.key}
          helpers={helpers}
          setInputValues={state.setInputValues}
          entityTypes={entityTypes}
          label={t_i18n('Condition')}
          triggerId={`filter-row-operator-${filter.id}`}
          style={{ width: '100%' }}
        />
      </Box>
      {!isCompositeRegardingOf && (
        <Box
          data-testid="filter-row-value"
          sx={isDateRangeValue ? { flex: '1 1 auto', minWidth: 0, display: 'flex', gap: 1 } : { flex: '1 1 auto', minWidth: 0 }}
        >
          <FilterValueInput
            {...sharedValueProps}
            filterKey={filter.key}
            showRelativeDateShortcuts={isDateRangeValue}
          />
        </Box>
      )}
      {isCompositeRegardingOf && (
        <>
          <Box data-testid="filter-row-relationship-type" sx={{ flex: '1 1 0', minWidth: 0 }}>
            <FilterValueInput {...sharedValueProps} filterKey={filter.key} subKey="relationship_type" />
          </Box>
          <Box data-testid="filter-row-value" sx={{ flex: '1 1 0', minWidth: 0 }}>
            {filter.key === 'regardingOf'
              ? <FilterValueInput {...sharedValueProps} filterKey={filter.key} subKey="id" />
              : <FilterRowCompositeValue {...sharedValueProps} />}
          </Box>
        </>
      )}
      <IconButton
        priority="tertiary"
        variant="destructive"
        onClick={() => helpers.handleRemoveFilterById(filter.id ?? '')}
        data-testid="filter-row-remove-button"
        aria-label={t_i18n('Delete')}
        icon={<CloseOutlined fontSize="small" />}
      />
    </Box>
  );
};

export default FilterRow;
