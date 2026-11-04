import { Chip } from '@filigran/design-system';
import { Dispatch, FunctionComponent, SetStateAction } from 'react';
import { Filter, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import { useFilterDefinition } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../i18n';
import { useFilterEditorContext } from './FilterEditorContext';
import FilterOperatorSelect from './FilterOperatorSelect';
import FilterValueInput from './FilterValueInput';
import { FILTER_VALUE_POPOVER_WIDTH } from './filterFieldLayout';

export interface CompositeNestedFilterEditorProps {
  filter?: Filter;
  filterKey: string;
  inputValues: FilterEditorInputValue[];
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
  /**
   * Whether the operator select of the first sub-filter is displayed. It also carries the empty / not empty
   * operators of the nested filter itself (see FilterOperatorSelect). The root filter chip popover has no
   * other place to show it, so it does; the nested filter-group row already displays that same operator
   * in its own 'Condition' column.
   */
  showFirstOperator?: boolean;
}

/**
 * Body of the generic nested filters (e.g. coverage_information): one operator and value editor per
 * sub-filter, separated by a 'WITH' chip. Each sub-filter carries its own operator; the first one also
 * holds the empty / not empty operators of the nested filter.
 * Used by both the root FilterChipPopover and the nested-group FilterRow.
 */
const CompositeNestedFilterEditor: FunctionComponent<CompositeNestedFilterEditorProps> = ({
  filter,
  filterKey,
  inputValues,
  setInputValues,
  showFirstOperator = false,
}) => {
  const { t_i18n } = useFormatter();
  const { entityTypes } = useFilterEditorContext();
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);

  const subFilters = filterDefinition?.subFilters ?? [];
  // with 'nil' / 'not_nil' the nested values are not edited
  const hasSubFilterBlocks = (filter?.operator ?? 'eq') === 'eq';

  return (
    <div
      style={{
        // floating popover body, or inline value column of a filter-group row
        width: showFirstOperator ? FILTER_VALUE_POPOVER_WIDTH : '100%',
        maxWidth: '100%',
        boxSizing: 'border-box',
        padding: showFirstOperator ? 8 : 0,
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      {subFilters.map((subFilter, index) => {
        const showOperator = index > 0 || showFirstOperator;
        // with 'nil' / 'not_nil', only the first operator stays, to switch back to a value
        if (!hasSubFilterBlocks && !(index === 0 && showOperator)) return null;
        return (
          <div key={subFilter.filterKey} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {index > 0 && (
              <Chip
                style={{ alignSelf: 'flex-start' }}
                label={t_i18n('WITH')}
              />
            )}
            {showOperator && (
              <FilterOperatorSelect
                filter={filter}
                filterKey={filterKey}
                setInputValues={setInputValues}
                subKey={subFilter.filterKey}
              />
            )}
            {hasSubFilterBlocks && (
              <FilterValueInput
                filter={filter}
                filterKey={filterKey}
                inputValues={inputValues}
                setInputValues={setInputValues}
                subKey={subFilter.filterKey}
              />
            )}
          </div>
        );
      })}
    </div>
  );
};

export default CompositeNestedFilterEditor;
