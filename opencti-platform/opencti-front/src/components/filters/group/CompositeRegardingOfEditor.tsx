import { Chip } from '@filigran/design-system';
import { FunctionComponent } from 'react';
import { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { useFilterDefinition } from '../../../utils/filters/filtersUtils';
import type { WidgetHost } from '../../../utils/widget/widget';
import { useFormatter } from '../../i18n';
import { FilterRepresentative } from '../FiltersModel';
import { FilterEditorState, FilterOperatorAndValue } from './FilterOperatorAndValue';

export interface CompositeRegardingOfEditorProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  state: FilterEditorState;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  entityTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  host?: WidgetHost;
  /**
   * Whether the operator select of the first subfilter (relationship_type) is displayed.
   * The root filter chip popover has no other place to show it, so it does; the nested
   * filter-group row already displays that same operator in its own 'Condition' column.
   */
  showFirstOperator?: boolean;
}

/**
 * Shared body of the 'regardingOf' / 'dynamicRegardingOf' composite filters: two stacked
 * subfilter editors (relationship_type/id or relationship_type/dynamic) separated by a 'WITH' chip.
 * Used by both the root FilterChipPopover and the nested-group FilterRowCompositeValue popover,
 * so the two can never drift apart.
 */
const CompositeRegardingOfEditor: FunctionComponent<CompositeRegardingOfEditorProps> = ({
  filter,
  filterKey,
  helpers,
  state,
  filtersRepresentativesMap,
  entityTypes,
  availableRelationFilterTypes,
  host,
  showFirstOperator = false,
}) => {
  const { t_i18n } = useFormatter();
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);

  if (!filterDefinition?.subFilters || filterDefinition.subFilters.length <= 1) {
    return null;
  }

  let disableSubfilter1 = false;
  let disableSubfilter2 = false;
  if (
    filterDefinition.subFilters[1].filterKey === 'dynamic'
    && (filter?.values.filter((f) => f.key === 'relationship_type').length ?? 0) === 0
  ) {
    disableSubfilter2 = true;
  } else if (
    filterDefinition.subFilters[1].filterKey === 'dynamic'
    && (filter?.values.filter((f) => f.key === 'dynamic')?.length ?? 0) > 0
  ) {
    disableSubfilter1 = true;
  }

  const displayOperatorAndFilter = (subKey: string, disabled: boolean, hideOperator = false) => (
    <FilterOperatorAndValue
      filter={filter}
      filterKey={filterKey}
      helpers={helpers}
      state={state}
      filtersRepresentativesMap={filtersRepresentativesMap}
      entityTypes={entityTypes}
      availableRelationFilterTypes={availableRelationFilterTypes}
      host={host}
      subKey={subKey}
      disabled={disabled}
      hideOperator={hideOperator}
    />
  );

  return (
    <div
      style={{
        minWidth: 250,
        padding: 8,
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
      }}
    >
      {displayOperatorAndFilter(filterDefinition.subFilters[0].filterKey, disableSubfilter1, !showFirstOperator)}
      <Chip
        style={{ alignSelf: 'flex-start' }}
        label={t_i18n('WITH')}
      />
      {displayOperatorAndFilter(filterDefinition.subFilters[1].filterKey, disableSubfilter2)}
    </div>
  );
};

export default CompositeRegardingOfEditor;
