import Box from '@mui/material/Box';
import { IconButton, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import CloseOutlined from '@mui/icons-material/CloseOutlined';
import { FunctionComponent } from 'react';
import { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import {
  FilterSearchContext,
  getDefaultFilterObject,
  getFilterDefinitionFromFilterKeysMap,
  useBuildFilterKeysMapFromEntityType,
} from '../../../utils/filters/filtersUtils';
import type { WidgetHost } from '../../../utils/widget/widget';
import { useFormatter } from '../../i18n';
import { FilterRepresentative } from '../FiltersModel';
import {
  FilterOperatorAndValue,
  useFilterEditorState,
} from './FilterOperatorAndValue';
import FilterRowCompositeValue from './FilterRowCompositeValue';

// Re-exported for backward compatibility with existing call sites (e.g. FilterChipPopover),
// the actual implementation now lives in FilterOperatorAndValue.tsx (moved there to break the
// circular import FilterRow -> FilterRowCompositeValue -> CompositeRegardingOfEditor -> FilterRow).
export {
  AUTOCOMPLETE_KEY_ACTIONS,
  OperatorKeyValues,
  useFilterEditorState,
  FilterOperatorAndValue,
} from './FilterOperatorAndValue';
export type {
  FilterEditorInputValue,
  FilterEditorState,
  FilterOperatorAndValueProps,
} from './FilterOperatorAndValue';

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

  // Only this nested-group row lays 'From'/'To' side by side; the filter chip popover (its own,
  // untouched call site of `FilterOperatorAndValue`) keeps them stacked. Computed here, not inside
  // `FilterOperatorAndValue`, so the two callers can't affect each other.
  const isDateRangeValue = getFilterDefinitionFromFilterKeysMap(filter.key, filterKeysMap)?.type === 'date' && filter.operator === 'within';
  // Too complex for the 3-column layout (2 subfilters, one of which is itself a nested filter
  // group editor): displayed as a compact clickable summary opening a popover instead. See
  // FilterRowCompositeValue.
  const isCompositeRegardingOf = filter.key === 'regardingOf' || filter.key === 'dynamicRegardingOf';

  return (
    <div style={{ display: 'flex', alignItems: 'stretch', gap: 8, width: '100%' }}>
      <div data-testid="filter-row-key-select" style={{ flex: '0 0 22%' }}>
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
      </div>
      <FilterOperatorAndValue
        filter={filter}
        filterKey={filter.key}
        helpers={helpers}
        state={state}
        filtersRepresentativesMap={filtersRepresentativesMap}
        entityTypes={entityTypes}
        availableRelationFilterTypes={availableRelationFilterTypes}
        host={host}
        operatorLabel={t_i18n('Condition')}
        operatorTriggerId={`filter-row-operator-${filter.id}`}
        operatorStyle={{ width: '100%' }}
        operatorWrapperStyle={{ flex: '0 0 18%' }}
        valueWrapperStyle={isDateRangeValue ? { flex: '1 1 auto', minWidth: 0, display: 'flex', gap: 1 } : { flex: '1 1 auto', minWidth: 0 }}
        dataTestIds={{ operator: 'filter-row-operator-select', value: 'filter-row-value' }}
        hideValue={isCompositeRegardingOf}
      />
      {isCompositeRegardingOf && (
        <Box data-testid="filter-row-value" sx={{ flex: '1 1 auto', minWidth: 0 }}>
          <FilterRowCompositeValue
            filter={filter}
            helpers={helpers}
            state={state}
            filtersRepresentativesMap={filtersRepresentativesMap}
            entityTypes={entityTypes}
            availableRelationFilterTypes={availableRelationFilterTypes}
            host={host}
          />
        </Box>
      )}
      <IconButton
        priority="tertiary"
        variant="destructive"
        onClick={() => helpers.handleRemoveFilterById(filter.id ?? '')}
        data-testid="filter-row-remove-button"
        aria-label={t_i18n('Delete')}
        icon={<CloseOutlined fontSize="small" />}
      />
    </div>
  );
};

export default FilterRow;
