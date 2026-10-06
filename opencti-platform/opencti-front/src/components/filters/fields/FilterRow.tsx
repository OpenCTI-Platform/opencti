import { Combobox, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxTrigger, IconButton } from '@filigran/design-system';
import CloseOutlined from '@mui/icons-material/CloseOutlined';
import Box from '@mui/material/Box';
import { FunctionComponent, useState } from 'react';
import { Filter, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import { getDefaultFilterObject, getFilterDefinitionFromFilterKeysMap, useBuildFilterKeysMapFromEntityType } from '../../../utils/filters/filtersUtils';
import { buildGroupedFilterKeyOptions, GroupedFilterKeyOption, isGroupedFilterKeySelection } from '../../../utils/filters/filterKeyGrouping';
import { useFormatter } from '../../i18n';
import FilterChip from '../FilterChip';
import FilterKeyLabel from '../FilterKeyLabel';
import FilterValues from '../FilterValues';
import { useFilterEditorContext } from './FilterEditorContext';
import FilterOperatorSelect from './FilterOperatorSelect';
import FilterRowCompositeValue from './FilterRowCompositeValue';
import { FILTER_ROW_COLUMN_FLEX } from './filterFieldLayout';
import FilterValueInput from './FilterValueInput';

export interface FilterRowProps {
  filter: Filter;
}

/**
 * The editing part of a filter row: the operator select and the value editor(s). Rendered keyed
 * by `filter.key` (not `filter.id`) by `FilterRow` below, so that changing the filter's key —
 * which mutates the filter object in place rather than remounting the row — forces a full
 * unmount/remount of this subtree. That resets every bit of local state seeded from the previous
 * filter (this component's own `useState` call, and further down `FilterEntityAutocomplete`'s
 * and `FilterDate`'s local state), avoiding stale values from the filter's former key/type.
 */
const FilterRowEditor: FunctionComponent<FilterRowProps> = ({ filter }) => {
  const { t_i18n } = useFormatter();
  const { entityTypes } = useFilterEditorContext();
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);

  const [inputValues, setInputValues] = useState<FilterEditorInputValue[]>(filter ? [filter as FilterEditorInputValue] : []);

  const isDateRangeValue = getFilterDefinitionFromFilterKeysMap(filter.key, filterKeysMap)?.type === 'date' && filter.operator === 'within';
  const isCompositeRegardingOf = filter.key === 'regardingOf' || filter.key === 'dynamicRegardingOf';
  const isStandaloneDynamicFilter = filter.key === 'dynamicFrom' || filter.key === 'dynamicTo';

  // Same rule as CompositeRegardingOfFilterEditor (root chip popover): once a dynamic filter is
  // defined, the relationship type it depends on cannot be emptied or changed anymore.
  const isRelationshipTypeLocked = filter.key === 'dynamicRegardingOf' && filter.values.some((value) => value.key === 'dynamic');

  const sharedValueProps = { filter, inputValues, setInputValues };

  return (
    <>
      <Box data-testid="filter-row-operator-select" sx={{ flex: FILTER_ROW_COLUMN_FLEX.operator }}>
        <FilterOperatorSelect
          filter={filter}
          filterKey={filter.key}
          setInputValues={setInputValues}
          subKey={isCompositeRegardingOf ? 'relationship_type' : undefined}
          disabled={isRelationshipTypeLocked}
          label={t_i18n('Condition')}
          triggerId={`filter-row-operator-${filter.id}`}
          style={{ width: '100%' }}
        />
      </Box>
      {!isCompositeRegardingOf && !isStandaloneDynamicFilter && (
        <Box
          data-testid="filter-row-value"
          sx={isDateRangeValue ? { flex: FILTER_ROW_COLUMN_FLEX.value, minWidth: 0, display: 'flex', gap: 1 } : { flex: FILTER_ROW_COLUMN_FLEX.value, minWidth: 0 }}
        >
          <FilterValueInput
            {...sharedValueProps}
            filterKey={filter.key}
            showRelativeDateShortcuts={isDateRangeValue}
          />
        </Box>
      )}
      {isStandaloneDynamicFilter && (
        <Box data-testid="filter-row-value" sx={{ flex: FILTER_ROW_COLUMN_FLEX.value, minWidth: 0 }}>
          <FilterRowCompositeValue {...sharedValueProps} />
        </Box>
      )}
      {isCompositeRegardingOf && (
        <>
          <Box data-testid="filter-row-relationship-type" sx={{ flex: FILTER_ROW_COLUMN_FLEX.compositeValue, minWidth: 0 }}>
            <FilterValueInput {...sharedValueProps} filterKey={filter.key} subKey="relationship_type" disabled={isRelationshipTypeLocked} />
          </Box>
          <Box data-testid="filter-row-value" sx={{ flex: FILTER_ROW_COLUMN_FLEX.compositeValue, minWidth: 0 }}>
            {filter.key === 'regardingOf'
              ? <FilterValueInput {...sharedValueProps} filterKey={filter.key} subKey="id" />
              : <FilterRowCompositeValue {...sharedValueProps} subKey="dynamic" />}
          </Box>
        </>
      )}
    </>
  );
};

/**
 * A condition when there is nothing to edit (no helpers): the same chip as in the root filter line.
 */
const FilterRowReadOnly: FunctionComponent<FilterRowProps> = ({ filter }) => {
  const { filtersRepresentativesMap, entityTypes, host } = useFilterEditorContext();
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  return (
    <Box sx={{ display: 'flex', width: '100%' }}>
      <FilterChip variant="filled">
        <FilterValues
          label={<FilterKeyLabel filter={filter} filterKeysMap={filterKeysMap} />}
          tooltip={false}
          currentFilter={filter}
          filtersRepresentativesMap={filtersRepresentativesMap}
          entityTypes={entityTypes}
          host={host}
        />
      </FilterChip>
    </Box>
  );
};

/**
 * An editable condition of a (nested) filter group, displayed as a single row:
 * [filter name] [condition] [value] [✕]
 */
const FilterRowEditable: FunctionComponent<FilterRowProps> = ({ filter }) => {
  const { t_i18n } = useFormatter();
  const { helpers, availableFilterKeys, entityTypes } = useFilterEditorContext();
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);

  const keyOptions = buildGroupedFilterKeyOptions(availableFilterKeys, entityTypes ?? [], filterKeysMap, t_i18n);
  const isGrouped = isGroupedFilterKeySelection(entityTypes ?? []);

  const selectedKeyOption = keyOptions.find((option) => option.value === filter.key) ?? null;

  const handleChangeKey = (newKey: string) => {
    if (newKey === filter.key) return;
    const newDefinition = getFilterDefinitionFromFilterKeysMap(newKey, filterKeysMap);
    helpers?.handleChangeFilterKey(filter.id ?? '', getDefaultFilterObject(newKey, newDefinition, undefined, filter.mode));
  };

  return (
    <Box sx={{ display: 'flex', alignItems: 'stretch', gap: 1, width: '100%' }}>
      <Box data-testid="filter-row-key-select" sx={{ flex: FILTER_ROW_COLUMN_FLEX.key }}>
        <Combobox<GroupedFilterKeyOption>
          value={selectedKeyOption}
          options={keyOptions}
          getOptionLabel={(option) => option.label}
          isOptionEqualToValue={(option, val) => option.value === val.value}
          groupBy={isGrouped ? (option) => option.groupLabel ?? '' : undefined}
          labelPosition="none"
          onValueChange={(next) => {
            const picked = Array.isArray(next) ? next[0] : next;
            if (picked?.value) handleChangeKey(picked.value);
          }}
        >
          <ComboboxField style={{ width: '100%' }}>
            <ComboboxInput
              id={`filter-row-key-${filter.id}`}
              aria-label={t_i18n('Filter name')}
              placeholder={t_i18n('Filter name')}
            />
            <ComboboxControls>
              <ComboboxTrigger />
            </ComboboxControls>
          </ComboboxField>
          <ComboboxContent listAriaLabel={t_i18n('Filter name')} />
        </Combobox>
      </Box>
      <FilterRowEditor key={filter.key} filter={filter} />
      <IconButton
        priority="tertiary"
        variant="destructive"
        onClick={() => helpers?.handleRemoveFilterById(filter.id ?? '')}
        data-testid="filter-row-remove-button"
        aria-label={t_i18n('Delete')}
        icon={<CloseOutlined fontSize="small" />}
      />
    </Box>
  );
};

/** Without helpers there is nothing to edit: the row is displayed as a chip, like in the root line. */
const FilterRow: FunctionComponent<FilterRowProps> = ({ filter }) => {
  const { helpers } = useFilterEditorContext();
  return helpers ? <FilterRowEditable filter={filter} /> : <FilterRowReadOnly filter={filter} />;
};

export default FilterRow;
